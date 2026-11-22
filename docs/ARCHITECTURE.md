# Architecture

```
  GDM / sudo / su / polkit / login                       utilisateur ou admin
            │ pam_authenticate()                                  │
            ▼                                                     ▼
   ┌──────────────────┐   socket Unix (root)    ┌──────────────────────────────┐
   │ pam_facial_auth  │ ───────────────────────▶│  facial-authd  (user système │
   │  (C, dans le     │  VERIFY / ACCEPT / OK   │  facial-auth, bac à sable    │
   │  processus hôte) │◀─────────────────────── │  systemd)                    │
   └──────────────────┘                         │                              │
            │ PAM_IGNORE ⇒ pam_unix (mot de    │  server.py   socket PAM       │
            │ passe, via PAM_AUTHTOK)           │  core.py     politique+scan   │
                                                │  dbus_service.py  API D-Bus ◀─┼── facial-auth (CLI)
                                                │  engine.py   YuNet + SFace    │◀─ facial-auth-settings (GTK4)
                                                │  camera.py / v4l2.py          │        │ polkit
                                                │  store.py    gabarits 0600    │◀───────┘ (admin)
                                                └──────────────────────────────┘
```

## Le module PAM (`pam/pam_facial_auth.c`)

Petit, sans dépendance au-delà de libpam, chargé dans des processus sensibles
(`sudo`, `gdm-session-worker`, `polkit-agent-helper-1`). Il **ne décide rien** :
il interroge le démon et ne renvoie `PAM_SUCCESS` que sur un `OK` reçu d'une
socket dont le pair est `root` (ou `facial-auth`). Tout le reste vaut
`PAM_IGNORE`, jamais `PAM_AUTH_ERR`.

Contrôle PAM installé : `[success=end conv_err=die default=ignore]`, en tête de
pile (priorité 270, avant `pam_unix`).

### Parallélisme visage / mot de passe

PAM n'a pas de conversation asynchrone. Le module lance donc l'invite du mot de
passe (`pam_prompt`) dans un **thread dédié**, pendant que le thread principal
surveille le démon :

* **jamais deux appels `conv()` simultanés** (le harnais de test le détecte) ;
* si le visage gagne : en mode `parallel-tty`, l'invite en attente est annulée
  (`pthread_cancel`) et le terminal restauré (`tcsetattr(TCSAFLUSH)`, ce qui
  jette aussi les caractères déjà tapés) ; en mode `parallel`, elle est
  **abandonnée** (annuler un thread dans du code GLib/D-Bus est dangereux) et le
  module est épinglé en mémoire (`-z nodelete`) pour que ce thread puisse
  revenir après `pam_end` ;
* pendant le défi de tête, l'invite reste ouverte (`parallel-tty`) : les consignes sont écrites
  directement sur `/dev/tty`, sous l'invite (`tty_say()`), puisque la conversation n'est pas réentrante ;
  aucun réglage du terminal n'est modifié, donc rien ne s'affiche de ce qui est tapé et `Ctrl-C` agit
  comme d'habitude ;
* si l'utilisateur saisit un mot de passe : le scan est annulé, le mot de passe
  est posé dans `PAM_AUTHTOK` et le module renvoie `PAM_IGNORE` ; `pam_unix`
  (profil `Auth:` avec `try_first_pass`) l'utilise sans le redemander, de même
  que `pam_gnome_keyring` ;
* les signaux (`Ctrl-C`) sont bloqués dans le thread principal pour atteindre le
  thread d'invite, comme dans un programme mono-thread ; une erreur de `conv()`
  *tardive* (> 0,3 s) est un abandon utilisateur ⇒ `PAM_CONV_ERR`
  (`conv_err=die` arrête la pile) ; une erreur *immédiate* signifie « ce
  frontal ne peut pas poser la question » ⇒ on continue à chercher le visage.

Pourquoi `gdm-password` reste séquentiel par défaut : GNOME sépare normalement
ses méthodes dans des services PAM distincts (`gdm-fingerprint`…) précisément
parce que PAM ne sait pas faire de concurrence. Le code de GDM 46 montre une
conversation à appels D-Bus synchrones (donc utilisable depuis un thread), mais
sans test sur un vrai écran de connexion, la valeur sûre est le mode séquentiel.

## Le démon (`src/facial_auth/`)

* `server.py` — une connexion = une tentative ; fermer la connexion annule le scan.
* `core.py` — **toutes les vérifications bon marché avant d'allumer la caméra** :
  activé ? utilisateur connu ? appelant autorisé (`SO_PEERCRED` : `root` pour
  tous, un utilisateur pour lui seul) ? `root` interdit ? service autorisé ?
  session distante (hôte PAM ou logind) ? capot fermé ? visage enrôlé ?
  verrouillage ? caméra de la bonne classe (IR/RGB) ? modèles présents ?
* `scan.py` — N images consécutives qui dépassent le seuil **et** battent tous les
  autres comptes enrôlés d'une marge (deux sosies ne se déverrouillent pas
  mutuellement) ; image ambiguë (deux visages comparables) ignorée ; visage trop
  petit/trop sombre ignoré ; flux d'images strictement identiques rejeté.
* `engine.py` — YuNet (détection + 5 points) et SFace (embedding 128-d) via
  OpenCV. **Ubuntu 24.04 embarque OpenCV 4.6**, dont `FaceDetectorYN` ne décode
  que l'ancien format YuNet (`loc/conf/iou`) : le modèle « 2022mar » y est
  imposé, « 2023mar » à partir d'OpenCV 4.8 (`models.required`). Les modèles sont
  vérifiés par SHA-256 avant chargement.
* `store.py` — embeddings seuls, `faces.json` en 0600 dans un dossier 0700,
  écritures atomiques ; un fichier illisible équivaut à « aucun visage »
  (jamais « n'importe quel visage »). Les visages sont rangés par numéro
  d'utilisateur **mais retiennent le nom du compte** : si le numéro désigne
  aujourd'hui un autre nom (compte supprimé puis numéro réattribué, compte
  renommé, annuaire injoignable), ils ne servent pas — et rien n'est effacé
  tant que `facial-auth purge-orphans` n'a pas été lancé par root. Des
  marqueurs vides `enrolled/<login>` permettent au module PAM de ne même pas
  contacter le démon pour les comptes sans visage.
* `ratelimit.py` — verrouillage progressif du chemin facial par compte ;
  l'état (verrouillages en cours et « coups » récents) est écrit dans
  `/var/lib/facial-auth/lockout.json`, car le démon s'arrête après 15 minutes
  d'inactivité et peut être redémarré à tout moment.
* `scan.decode_image` — seul endroit où le démon lit des octets choisis par
  quelqu'un d'autre : JPEG et PNG uniquement, taille lue dans l'en-tête avant
  d'allouer quoi que ce soit, deux décodages à la fois (voir `docs/SECURITY.md`).
* `challenge.py` — défi de tête : suivi de points de texture (flux optique), plan de l'intérieur du
  visage, parallaxe signée du nez ; machine à états (ordre aléatoire, continuité d'identité). Voir
  `docs/SECURITY.md` pour le principe, les mesures et les limites.
* `irtest.py` + `trust.py` — vérification d'une caméra « infrarouge » (elle ne doit pas voir un écran de
  téléphone) et registre des caméras vérifiées (`/var/lib/facial-auth/cameras.json`) ; les services qui
  exigent l'infrarouge n'acceptent qu'une caméra vérifiée.
* `v4l2.py` — découverte par ioctl V4L2 : ignore les nœuds de métadonnées,
  refuse `v4l2loopback`/`vivid`, classe IR/RGB (formats `GREY`/`Y8I`… ou nom).
* `dbus_service.py` — API de gestion, autorisée par polkit (`manage-faces`,
  `configure`, `use-camera`). L'aperçu caméra est renvoyé à l'appelant seul
  (jamais diffusé en signal) et libéré si son propriétaire disparaît.
  Le démon (utilisateur `facial-auth`, sans privilège) interroge polkit **au sujet
  d'un autre utilisateur** (l'application qui l'appelle) : `polkitd` ne l'autorise
  qu'à root ou au « propriétaire » de l'action. Chaque action de la politique
  déclare donc `org.freedesktop.policykit.owner = unix-user:facial-auth` ; sans cela
  toute demande échoue en « Non autorisé », quel que soit le mot de passe saisi
  (`tests/system/test_polkit_real.py` le vérifie avec un vrai `polkitd`).
* `server.py` — boucle d'acceptation de la socket PAM. Elle ne s'arrête **jamais** tant que
  le démon vit (plus de thread, plus de descripteur : le client est refusé par
  `SKIP busy` et la boucle continue) : une socket ouverte mais plus servie ferait attendre
  chaque connexion jusqu'au délai du module.
* Le démon **s'arrête seul** après 15 min d'inactivité ; l'activation par socket
  ou D-Bus le relance (Python + OpenCV ne restent pas en mémoire).

## Durcissement systemd

Utilisateur non privilégié `facial-auth` (+ groupe `video`), `NoNewPrivileges`,
`CapabilityBoundingSet=` vide, `ProtectSystem=strict`, `ProtectHome`,
`PrivateTmp`, `RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter=@system-service`,
`DevicePolicy=closed` + `char-video4linux`, `MemoryMax=1G`. Le démon décode des
images non fiables : `OPENCV_IO_MAX_IMAGE_PIXELS` est plafonné et les images
sont limitées à 8 Mio.

## Fichiers installés

| Fichier | Rôle |
|---|---|
| `/usr/lib/*/security/pam_facial_auth.so` | module PAM |
| `/usr/share/pam-configs/facial-auth` | profil `pam-auth-update` |
| `/usr/libexec/facial-auth/facial-authd` | démon |
| `/usr/lib/systemd/system/facial-authd.{socket,service}` | activation et bac à sable |
| `/usr/share/dbus-1/system.d/…FacialAuth1.conf` | politique D-Bus |
| `/usr/share/polkit-1/actions/…FacialAuth1.policy` | actions polkit (FR inclus) |
| `/etc/facial-auth/facial-auth.conf` | réglages locaux |
| `/var/lib/facial-auth/` | gabarits, marqueurs, réglages de l'application |
| `/usr/share/facial-auth/models/` | modèles ONNX téléchargés |
