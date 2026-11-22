# Sécurité et vie privée

> **Une authentification faciale sur webcam n'est pas aussi sûre qu'un mot de
> passe.** Ce projet réduit les risques ; il ne les supprime pas.

## Ce que l'on protège, contre qui

| Menace | Réponse |
|---|---|
| Quelqu'un tente de se connecter avec **son propre visage** | seuil de similarité + N images consécutives + marge face aux autres comptes enrôlés |
| Un **sosie** / un proche enrôlé sur la même machine | le visage doit battre tous les autres gabarits d'au moins `impostor_margin` |
| Un **processus local malveillant** fait croire à un succès | le module n'accepte `OK` que d'une socket dont le pair est `root` (ou `facial-auth`) ; la socket est dans un dossier de `root` |
| Un utilisateur interroge le démon **pour un autre compte** | `SO_PEERCRED` : un non-root ne peut vérifier que lui-même |
| **Force brute** | après `max_failures` échecs en `failure_window` s (visage inconnu, photo, défi raté), le chemin facial est verrouillé `lockout` s, **puis deux fois plus longtemps à chaque verrouillage** (jusqu'à `lockout_max`, 1 h) : insister ne paie pas (le mot de passe n'est jamais verrouillé par ce mécanisme). Le verrouillage est écrit dans `/var/lib/facial-auth/lockout.json` : le démon s'arrête après 15 minutes d'inactivité et peut être redémarré, attendre ou le redémarrer ne l'efface pas |
| Fichier de configuration mal édité | valeurs bornées (seuil ≥ 0,30), fichier invalide ignoré **en entier** et signalé |
| Fichier de gabarits corrompu | traité comme « aucun visage », jamais comme « tous les visages » |
| Image piégée envoyée à l'API | **JPEG et PNG seulement** (reconnus à leurs octets de tête : les autres formats que décode l'OpenCV d'Ubuntu, GDAL, GDCM, OpenEXR, JPEG 2000…, ne sont jamais ouverts), taille lue dans l'en-tête avant tout décodage (8 Mio, 24 Mpx), deux décodages à la fois, démon sans privilèges, sans réseau, sous `MemoryMax` |
| Un compte supprimé, puis un autre créé avec le même numéro d'utilisateur | les visages sont rangés par numéro mais **retiennent le nom du compte** : sous un autre nom, ils ne servent à personne (`sudo facial-auth purge-orphans` les efface) |
| Un utilisateur local écrit dans le journal du démon par la socket | `service`, `tty`, `rhost` et `ruser` sont une ligne imprimable de longueur bornée, sinon la requête est refusée (`SKIP bad-request`) |
| Un réglage sensible changé par un détour (`SetConfig`) | le fichier de réglages de l'application est écrit par le démon, qui n'est pas root, et lu en dernier : il ne peut contenir que les réglages modifiables depuis l'application (jamais `security.*`, les commandes d'émetteur infrarouge, `allow_virtual`) ; les noms de service sont validés |
| Modèle ONNX altéré | SHA-256 épinglé, vérifié au téléchargement **et** avant chargement |
| Session **SSH** / distante | pas de visage (hôte PAM, `SSH_*`, session logind distante) |
| Compte verrouillé (`passwd -l`), `root` | pas de visage |
| Un admin qui s'éloigne, session déverrouillée | l'élévation (`sudo`/polkit) exige une caméra IR **vérifiée** par défaut, comme tous les autres services |
| Une **photo** (papier, écran de téléphone) devant la caméra | caméra infrarouge **vérifiée** (un écran lui est invisible) + **défi de tête** (voir plus bas) : une surface plane ne passe pas |
| La **rediffusion** d'un enregistrement de votre tête qui tourne | l'ordre du défi (gauche puis droite, ou l'inverse) est tiré au hasard à chaque tentative ; un écran est invisible d'une caméra IR |

## Ce qui n'est PAS couvert

Aucune authentification faciale par webcam n'est aussi sûre qu'un mot de passe ; voici ce qui reste
possible, du plus au moins accessible.

* **Une surface qui a du relief** : une photo collée sur une boule ou un bol (courbure dans les deux
  sens), un masque. Le défi de tête distingue une surface *plane ou simplement pliée* d'une tête, pas
  un objet 3D. En simulation, une feuille bombée de 2 cm dans les deux sens passe environ 3 fois sur 100,
  de 4 cm environ une fois sur cinq ; une feuille pliée dans un seul sens (la seule chose que fait un
  papier sans plis) passe 0 à 3 fois sur 100 à 2 cm de bombement, environ une fois sur huit à 4 cm.
* **Une vidéo montée** de votre tête qui tourne dans le bon ordre, devant une caméra **couleur** (une
  caméra infrarouge ne voit pas un écran), ou un **deepfake injecté** avant le démon. L'ordre aléatoire
  oblige l'attaquant à posséder les deux enregistrements et à choisir en temps réel.
* **Une photo imprimée vue par une caméra infrarouge** : le papier réfléchit l'infrarouge proche. Le
  défi de tête la rejette (elle est plane), mais c'est la seule défense.
* **Le trousseau GNOME** (`gnome-keyring`) n'est déverrouillé que par le mot de
  passe ; après une connexion par le visage il reste verrouillé et les
  applications le demanderont. Ce paquet ne stocke volontairement **aucun mot
  de passe** pour contourner cela.
* **Chiffrement de disque (LUKS)** au démarrage, `systemd-homed`, démarrage
  anticipé : mot de passe uniquement.
* Un utilisateur **root** local contrôle de toute façon la machine : il peut
  remplacer le module, le démon ou les modèles.
* Qualité de reconnaissance (taux de faux rejets/acceptations) : **non mesurée**
  sur de vrais visages dans cet environnement. Réglez `recognition.threshold`
  avec `facial-auth test` (valeurs plus élevées = plus strict).

## Le démon fait partie de la base de confiance

Le module PAM s'exécute dans `sudo`, `su`, `gdm`, `polkit-agent-helper`… Il n'accepte `OK` que d'une socket
créée par `root` dans un dossier de `root`. Avec l'activation par socket de systemd, le module voit les
identifiants de *celui qui a créé la socket* (root), **quel que soit le processus qui répond ensuite** : il
ne peut pas savoir qui répond. Tout code qui s'exécute sous le compte `facial-auth` et détient la socket
d'écoute — c'est-à-dire le démon lui-même, s'il était piégé — peut répondre « OK » à n'importe quel compte
non verrouillé, donc devenir administrateur puis root. Sur Ubuntu `root` est protégé parce que son mot de
passe est verrouillé et que le module ignore les comptes verrouillés, mais un compte administrateur ordinaire
suffit.

C'est pourquoi **tout ce que le démon lit venant de quelqu'un d'autre est une surface d'attaque de
première importance** : les images envoyées à l'API (JPEG et PNG seulement, voir plus haut), le fichier de
réglages qu'il écrit lui-même (limité aux réglages modifiables), les champs de la requête PAM (bornés), ses
propres gabarits (un fichier illisible = « aucun visage »).

**Ce qui n'est pas fait** : le démon décode toujours les images dans le même processus que celui qui répond à
PAM. Les séparer (deux processus, deux comptes : l'un qui répond à PAM et ne décode jamais de fichier, l'autre
qui décode et n'a ni la socket ni les gabarits) est la seule mesure qui supprimerait ce risque au lieu de le
réduire à ce que font libjpeg et libpng ; c'est un chantier de conception. D'ici là, **gardez le système à
jour** (`sudo apt upgrade`) : une faille de ces deux bibliothèques serait le chemin d'attaque.

## Détecter qu'un visage est vivant

Une webcam ne mesure pas la profondeur ; ce projet empile donc trois défenses, qui coûtent chacune
une chose différente à un attaquant.

### 1. Une caméra infrarouge, vérifiée

Par défaut **chaque** service (écran de connexion, verrouillage, console, `sudo`, `su`, polkit) exige
une caméra infrarouge : une webcam couleur est trompée par une photo affichée sur un téléphone, et
c'est ce qui a été constaté. « Infrarouge » est cependant déduit des formats de pixels
(monochrome), ce qui est faux pour un capteur monochrome **sans filtre infrarouge** : il voit un
écran de téléphone. `facial-auth check-camera` montre donc à la caméra un écran blanc lumineux :
une vraie caméra infrarouge ne le voit pas (rectangle sombre), la caméra est alors enregistrée comme
**vérifiée** (`/var/lib/facial-auth/cameras.json`) ; sinon elle reste refusée pour les services qui
exigent l'infrarouge. L'assistant d'enrôlement propose cette vérification.
`camera.require_ir_check = false` la supprime pour un administrateur qui assume le risque.

### 2. Le défi de tête (`liveness.mode = challenge`, par défaut)

Une fois le visage reconnu (c'est ce qui fait apparaître la consigne), la personne doit **tourner
nettement la tête vers sa gauche puis vers sa droite (ou l'inverse, tiré au hasard), puis regarder
l'écran**. Chaque mouvement vu est confirmé (« Bien. Maintenant, tournez nettement la tête vers votre
droite. ») : on sait où l'on en est, et si la confirmation ne vient pas, c'est que le mouvement n'a pas
été vu. Dans un terminal (`sudo`, `su`, console) l'invite du mot de passe **reste ouverte** : la consigne
s'écrit sous elle et le mot de passe peut être tapé à tout moment, ce qui met fin au défi ; sur un écran de
connexion ou un dialogue graphique, les messages passent par la conversation PAM et, en cas d'échec, le
mot de passe est demandé comme d'habitude. L'échec est dit tel qu'il est : « Le test de rotation de la tête
n'a pas abouti » veut dire que le visage **a** été reconnu et que le geste n'a pas été validé.

Le principe n'est pas « le visage a-t-il bougé ? » (une feuille tenue à la main bouge, s'incline, pivote
et se plie) mais « **le visage est-il plat ?** » : tout mouvement rigide d'une surface plane est une
homographie. Dans `src/facial_auth/challenge.py` :

1. des dizaines de points de texture du visage sont suivis d'une image à l'autre (flux optique de
   Lucas-Kanade) ;
2. un plan est ajusté sur les points de l'**intérieur** du visage (sourcils, yeux, bouche), hors nez : ce
   qu'un papier, même plié, imite bien ;
3. le **nez** est comparé à ce plan. Sur une vraie tête il dépasse d'environ 3 cm et, quand la tête tourne,
   glisse latéralement contre le plan dans le sens du mouvement (parallaxe) ; sur une surface plane il
   y reste collé, quelle que soit l'inclinaison.

La parallaxe signée du nez (en fraction de la distance entre les yeux) mesure **à la fois** la
profondeur et le sens du mouvement : il faut qu'elle franchisse `+challenge_turn` puis `-challenge_turn`
(ou l'inverse), plusieurs images de suite, avant la fin du délai ; la même personne doit être
présente pendant tout le mouvement (un changement de visage échoue) et à la fin.

**Ce qui a été mesuré** (sept portraits réels, déformés comme une feuille tenue à la main, vus par le
vrai détecteur de visages ; tête 3D synthétique texturée pour la classe « utilisateur » — **pas de
vidéos de vraies personnes**, donc les taux de réussite de l'utilisateur sont à vérifier sur votre
caméra) :

| Cas simulé | Parallaxe maximale du nez | Passe le défi |
|---|---|---|
| Photo plane tenue à la main, inclinée jusqu'à 40° (60 mouvements × 2 ordres) | médiane 0,004 ; max 0,026 | **0 fois** |
| Photo plane avec reflet qui glisse (60 × 2) | médiane 0,015 | **0 fois** |
| Feuille pliée, bombement de 2 cm (un seul sens) | max 0,07 | 0 à 3 % |
| Feuille pliée, bombement de 4 cm | max 0,05 | 0 à 18 % (selon l'axe) |
| Surface bombée dans les deux sens, 2 cm / 4 cm | max 0,04 / 0,13 | ≈ 6 % / ≈ 28 % |
| Vraie rotation, **mauvais ordre** (rediffusion d'un autre enregistrement) | — | 0 % |
| Tête 3D qui tourne comme demandé (14 à 28°, nez de 1,6 à 2,2 cm) | 0,03 à 0,09 | ≈ 96 % |

**Combien tourner, et à quelle vitesse ?** Même simulation, 7 à 8 essais par ligne (ordres de grandeur, pas
des statistiques) :

| Amplitude de chaque côté | Passe le défi (seuil 0,02) |
|---|---|
| 5° | 0 % |
| 7° | 0 à 14 % |
| 9° | 0 à 75 % |
| 11° | 43 à 71 % |
| 13° | 71 à 86 % |
| 16° | 88 à 100 % |
| 20° | 86 à 100 % |

Un mouvement **léger** (moins de 10°) ne franchit pas le seuil : c'est la cause la plus probable d'un refus.
La **vitesse** compte beaucoup moins : un aller-retour complet de 1,2 à 6 s passe 75 à 100 % des fois, mais
en 0,8 s seulement 6 fois sur 10 (il faut rester au-delà du seuil trois images de suite : marquez une
courte pause à chaque côté). La limite est le **délai global de 12 s** (`challenge_timeout`), qui court
dès l'envoi de la consigne et comprend sa lecture (2 à 3 s) ainsi que le retour face à l'écran, où le même
visage doit être reconnu à nouveau.

Seuil par défaut `challenge_turn = 0.02` : une surface plane tenue à la main donne typiquement 0,005 (le
plus grand pic isolé observé : 0,026, qui ne suffit pas puisqu'il faut franchir `+seuil` puis `-seuil`
dans l'ordre demandé, plusieurs images de suite) ; une vraie tête l'atteint vers 10° de rotation (un peu
plus pour un nez peu saillant). Un seuil de 0,025 (essayé d'abord) refusait trop souvent des gestes
pourtant corrects (14 % d'échecs à 20°) ; descendre à 0,015 laisserait passer 5 % des photos avec reflet.

Un échec du défi (visage plat, autre personne, délai dépassé) compte comme un échec pour le verrouillage
du chemin facial, avec des verrouillages de plus en plus longs.

#### Si le défi vous refuse

1. **Lisez le message.** « Face not recognized » : le visage n'a pas été reconnu. « Le test de rotation
   de la tête n'a pas abouti » : le visage l'a été (sans cela la consigne n'apparaît pas), c'est le geste
   qui n'a pas été validé.
2. **`facial-auth test`** rejoue le test et **dit quoi changer** : tourner plus loin, moins vite, de l'autre
   côté, regarder l'écran en face à la fin… Avec `--liveness` il affiche aussi les mesures : `peak` (pic
   de parallaxe, à comparer à `challenge_turn`), `steps` (mouvements validés sur 2), `points` (points du
   visage suivis), `hint`.
3. **Le journal** garde la même chose pour chaque tentative :
   `journalctl -u facial-authd | grep head-turn`, par exemple
   `head-turn lr: failed challenge-timeout (peak 0.012 of 0.020 needed, 0/2 steps, 87 points) hint=too-little`.
   `too-little` : mouvement trop petit ; `too-fast` : seuil atteint sans tenir trois images ;
   `wrong-way` : l'autre côté d'abord (ou image en miroir : `liveness.mirror = true`) ; `second-turn` : un
   seul côté vu ; `final-match` : les deux côtés vus mais visage pas reconnu de nouveau, de face ;
   `lost-face`, `no-texture` (trop sombre ou trop loin).
4. **Réglages** (`/etc/facial-auth/facial-auth.conf`, section `[liveness]`) : `challenge_turn` plus bas si
   votre `peak` s'arrête juste sous le seuil malgré un vrai geste ; `challenge_timeout` plus haut si le
   temps manque.
5. **Niveau « Strict »** : il relève aussi le seuil de la dernière étape (le visage de face, reconnu de
   nouveau après les deux rotations). Si le journal dit `final-match`, regardez l'écran bien en face, dans
   une lumière franche, ou repassez au niveau « Standard ».

### 3. Rien ne dépend d'une seule défense

Le chemin facial reste une **alternative** au mot de passe, pas un second facteur : si la caméra échoue, le
mot de passe fonctionne toujours. Pour des données qui valent plus qu'une webcam, gardez le mot de passe
(`[core] enabled = false`) ou une clé FIDO2.

## Vie privée

* **Aucune photographie n'est conservée** : seuls des vecteurs de 128 nombres
  par échantillon sont stockés (`/var/lib/facial-auth/templates/<uid>/faces.json`,
  0600, propriété de `facial-auth`). Ces gabarits sont des données biométriques :
  traitez les sauvegardes en conséquence.
* L'aperçu de l'application transite par D-Bus **vers l'appelant uniquement** et
  n'est jamais écrit sur disque. La caméra n'est allumée que pendant un scan, un
  aperçu ou un test, et son voyant l'indique.
* Les journaux (`journalctl -u facial-authd`) contiennent compte, service,
  caméra, résultat, score et durée — aucune donnée biométrique.
* `apt purge facial-auth` supprime gabarits et modèles. Un utilisateur peut à
  tout moment supprimer ses visages (`facial-auth clear`) ou désactiver le
  visage pour son compte.
* Quand un compte est supprimé ou renommé, ses visages ne servent plus à personne mais restent sur le
  disque : `sudo facial-auth purge-orphans` (`--dry-run` pour voir avant) les efface. Rien n'est effacé
  automatiquement, parce qu'un annuaire d'utilisateurs momentanément injoignable ressemble à un compte
  supprimé et ne doit coûter son visage à personne.
* `/var/lib/facial-auth/lockout.json` ne contient que des numéros d'utilisateur et des dates.

## Disponibilité : ne pas être enfermé dehors

Une panne de ce composant ne doit jamais empêcher de se connecter par mot de passe. Le module PAM ne
répond jamais « non » (`PAM_IGNORE`), borne chacune de ses attentes avec sa propre horloge, n'est
activé qu'après s'être chargé une fois dans un processus jetable, et un compte sans visage ne le
sollicite pas. Chaque panne imaginable (démon figé, socket piégée, module absent ou corrompu…) est
rejouée contre le paquet installé : voir [`RECOVERY.md`](RECOVERY.md), qui donne aussi les consignes
d'installation prudente et les procédures de secours.

Une socket accessible à tous (`0666`) permet à un utilisateur local de saturer le démon : le module
reçoit alors `SKIP busy` ou attend au plus quelques secondes, puis le mot de passe est demandé. Il peut
ainsi priver les autres du visage, jamais du mot de passe.

## Durcissement recommandé

* Utiliser une caméra infrarouge et la faire vérifier (`facial-auth check-camera`) ; laisser tous les
  services sur `ir`.
* Garder `liveness.mode = challenge`, `security.allow_root = false`, `abort_if_remote = true`,
  `camera.require_ir_check = true`.
* Pour un portable souvent branché sur écran externe capot fermé, la caméra
  intégrée ne voit rien : le visage est ignoré (c'est voulu).
* Garder le système à jour : le démon lit des images avec les bibliothèques d'Ubuntu (libjpeg, libpng).
* Signaler une faille : voir le dépôt du projet.

## Audit de sécurité de novembre 2026

Un audit de la version 1.2.0 (relecture complète, analyse statique, essais sur le code réel) a relevé 16
points. **Aucun ne permettait, tel quel, d'ouvrir une session ou de devenir root sans accès préalable** : le
plus sérieux (le décodeur d'images) n'aurait servi qu'avec une faille dans une bibliothèque tierce, que
l'audit n'a pas trouvée. Ce que chaque point permettait, à qui, et ce qui a été fait :

| Point | Qui pouvait en profiter | Root requis ? | Ce que cela permettait | Correction |
|---|---|---|---|---|
| Décodeur d'images accessible sans mot de passe | tout utilisateur d'une session locale active | non | élargir la surface d'attaque à une douzaine de décodeurs (GDAL, GDCM, OpenEXR…) dans le processus qui répond à PAM ; lecture d'un fichier local comme « image » par GDAL | JPEG et PNG seulement, taille lue dans l'en-tête |
| Images mal formées | idem | non | rendre le démon sourd (fuite de descripteurs par le décodeur HDR d'OpenCV), remplir le disque (fichiers temporaires Sun Raster/PFM), dépasser la limite de mémoire : 4 s d'attente avant le mot de passe à chaque authentification, jamais d'enfermement | formats refusés avant OpenCV, erreurs d'OpenCV captées |
| Injection dans le fichier de réglages | détenteur de l'action polkit `configure` (administrateur par défaut) | oui en pratique : sans gain pour un administrateur ordinaire, ne compte que si `configure` est délégué à quelqu'un d'autre | contourner la liste des réglages interdits (`security.*`, commandes d'émetteur infrarouge) jusqu'à exécuter une commande sous `facial-auth` | noms validés ; fichier limité aux réglages modifiables |
| Visage d'un ancien titulaire sur un numéro d'utilisateur réattribué | l'ancien titulaire d'un compte | non pour lui (un administrateur doit avoir supprimé puis recréé le compte) ; il lui faut aussi la caméra IR vérifiée et le défi de tête | ouvrir la session du nouvel arrivant avec son visage | visages liés au nom du compte ; `facial-auth purge-orphans` |
| Lignes forgées dans le journal | tout utilisateur local | non | faire passer de fausses lignes pour celles du démon | champs de la requête validés |
| `facial-auth doctor` lancé dans un dossier inscriptible par un tiers | quiconque écrit dans ce dossier | un administrateur doit lancer la commande | exécuter du code en root | sonde en mode isolé (`-I`, répertoire `/`) |
| Verrouillage progressif perdu à l'arrêt du démon | un passant physique | non | plafond réel de 15 minutes au lieu d'une heure | état écrit dans `lockout.json` |
| Fenêtres polkit non sollicitées, API de gestion bloquable | tout processus local | non | harceler avec des demandes de mot de passe ; geler l'API de gestion (pas la connexion) | drapeau d'interaction du demandeur respecté, deux demandes d'autorisation en attente par appelant, travailleurs séparés pour les appels de lecture |
| Test de reconnaissance sans `use-camera`, messages d'erreur détaillés | une session SSH du même compte | non | allumer la caméra à distance ; lire des chemins dans les erreurs | `use-camera` exigé, messages génériques |
| Variables d'environnement de développement, `--no-polkit` | root seulement | sans objet | — | ignorées hors `--dev` ; `--no-polkit` refusé pour le service |
| `install_from` vérifie puis recopie | quelqu'un qui écrit dans le dossier source | un administrateur doit lancer la commande | installer un autre fichier (le démon le refuserait au chargement) | un seul passage : ce qui est vérifié est ce qui est écrit |
| Unité systemd | — | — | marges de durcissement | `ProtectProc=invisible`, `RemoveIPC=yes` (1,6 → 1,4 à `systemd-analyze security`) |
| Publications non signées | quiconque contrôle le compte GitHub du mainteneur | non | root chez les utilisateurs | **en partie** : le jeton n'est plus conservé dans les copies du dépôt ; voir ci-dessous |

**Pas corrigé, et pourquoi :**

* **Séparer le décodage des images de l'autorité qui répond à PAM** (voir plus haut) : chantier de conception.
* **Signer les publications et épingler les actions GitHub par empreinte** : il faut une clé de signature
  que seul le mainteneur peut créer, et les empreintes exactes de `actions/checkout`, `upload-artifact` et
  `download-artifact` (à relever sur ces dépôts : `gh api repos/actions/checkout/commits/v4 --jq .sha`).
  En attendant, vérifier un paquet téléchargé contre `SHA256SUMS` ne protège que d'une corruption de
  transfert, pas d'une release modifiée.
* **Mesures sur du vrai matériel** : taux de fausses acceptations et de faux rejets, attaques de
  présentation (photo infrarouge imprimée, nez découpé, masque), identité de la caméra IR (nom, bus, formats :
  fournis par le périphérique).
* `ListUsers`, les signaux diffusés et les marqueurs `enrolled/` sont lisibles par tout utilisateur local :
  ce sont des informations que la machine publie déjà (liste des comptes, marqueurs en 0644 voulus pour le
  module PAM).
