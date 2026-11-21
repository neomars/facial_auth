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
| **Force brute** | après `max_failures` échecs en `failure_window` s (visage inconnu, photo, défi raté), le chemin facial est verrouillé `lockout` s, **puis deux fois plus longtemps à chaque verrouillage** (jusqu'à `lockout_max`, 1 h) : insister ne paie pas (le mot de passe n'est jamais verrouillé par ce mécanisme) |
| Fichier de configuration mal édité | valeurs bornées (seuil ≥ 0,30), fichier invalide ignoré **en entier** et signalé |
| Fichier de gabarits corrompu | traité comme « aucun visage », jamais comme « tous les visages » |
| Image piégée envoyée à l'API | taille limitée (8 Mio, 32 Mpx), démon sans privilèges, sans réseau, sous `MemoryMax` |
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

Une fois le visage reconnu, la personne doit **tourner lentement la tête vers sa gauche puis vers sa
droite (ou l'inverse, tiré au hasard), puis regarder l'écran**. L'instruction s'affiche dans la
conversation PAM ; en cas d'échec, le mot de passe est demandé comme d'habitude.

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
| Feuille pliée, bombement de 4 cm | max 0,05 | 0 à 12 % (selon l'axe) |
| Surface bombée dans les deux sens, 2 cm / 4 cm | max 0,04 / 0,13 | ≈ 3 % / ≈ 20 % |
| Vraie rotation, **mauvais ordre** (rediffusion d'un autre enregistrement) | — | 0 % |
| Tête 3D qui tourne comme demandé (nez de 1,6 à 3 cm), un geste de 2 s sur les 8 s permis | 0,04 à 0,09 | 82 à 96 % |

Seuil par défaut `challenge_turn = 0.025` : une surface plane tenue à la main donne typiquement 0,005
(le plus grand pic isolé observé : 0,026, qui ne suffit pas puisqu'il faut franchir `+seuil` puis `-seuil`
dans l'ordre demandé, plusieurs images de suite) ; une vraie tête l'atteint vers 10° de rotation. `facial-auth test --liveness` affiche les valeurs mesurées sur
votre caméra (pic de parallaxe, étapes franchies, nombre de points suivis) pour régler ce seuil avec votre
photo et votre visage.

Un échec du défi (visage plat, autre personne, délai dépassé) compte comme un échec pour le verrouillage
du chemin facial, avec des verrouillages de plus en plus longs.

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
* Signaler une faille : voir le dépôt du projet.
