# facial_auth — authentification faciale intégrée à Ubuntu

Se connecter, déverrouiller l'écran, lancer `sudo` ou valider une demande
d'administrateur **avec son visage**, via le système d'authentification natif
d'Ubuntu (PAM). Inspiré de [howdy](https://github.com/boltgolt/howdy), mais avec
une intégration complète : démon durci, API D-Bus, autorisations polkit,
application graphique, paquet Debian.

**Le mot de passe reste toujours disponible**, à chaque étape :

* pendant que la caméra cherche votre visage, vous pouvez saisir votre mot de
  passe à tout moment (terminal) ;
* si le visage n'est pas reconnu, la saisie du mot de passe suit, comme d'habitude ;
* un échec facial **ne compte jamais** comme une tentative de connexion ratée et
  ne peut pas verrouiller le compte ;
* si le démon, la caméra ou les modèles sont absents, le système se comporte
  exactement comme sans ce paquet.

## Parcours de configuration

1. L'utilisateur ouvre **« Connexion par le visage »** (ou `facial-auth add`).
2. **Capture** — aperçu de la caméra (comme l'application *Caméra*) avec cadre
   sur le visage et consignes de pose, **ou** import des photos prises avec
   l'application *Caméra* d'Ubuntu (≥ 3 photos).
3. **Liaison au compte** — l'**administrateur** choisit le compte et valide avec
   son mot de passe (polkit) : c'est lui qui lie le visage au compte. Un simple
   utilisateur peut tester, désactiver ou supprimer *ses propres* visages, mais
   pas en ajouter.

Seuls des **embeddings** (128 nombres par échantillon) sont stockés, jamais de
photographies, dans un dossier privé de l'utilisateur système `facial-auth`.

## Installation

Cible : Ubuntu 24.04 LTS (OpenCV 4.6, GNOME/GDM). Python ≥ 3.10. Sur 22.04, le module, le démon et la
ligne de commande devraient fonctionner (OpenCV 4.5.4, non testé) ; l'application graphique exige
libadwaita ≥ 1.5.

> **Avant d'installer** : gardez un terminal root ouvert (`sudo -s`) pendant l'installation et les
> premiers essais. Les pannes simulées de ce paquet ne peuvent pas vous empêcher de vous connecter par
> mot de passe (voir [`docs/RECOVERY.md`](docs/RECOVERY.md)), mais ce guide dit quoi tester et comment
> tout défaire en une commande.

### Depuis une release (recommandé)

Chaque [release](../../releases) fournit les paquets `.deb` déjà compilés, **modèles de
reconnaissance inclus** : l'installation fonctionne hors ligne.

```bash
# remplacez X.Y.Z par la version de la release
BASE=https://github.com/neomars/facial_auth/releases/download/vX.Y.Z
curl -LO "$BASE/facial-auth_X.Y.Z_amd64.deb"
curl -LO "$BASE/facial-auth-gtk_X.Y.Z_all.deb"
curl -LO "$BASE/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
sudo apt install ./facial-auth_X.Y.Z_amd64.deb ./facial-auth-gtk_X.Y.Z_all.deb
```

Les releases se publient depuis GitHub (voir [`docs/RELEASE.md`](docs/RELEASE.md)) : un workflow
compile, teste sur une machine propre, puis attache les paquets à la release.

### Depuis les sources

```bash
sudo apt install build-essential devscripts debhelper dh-python meson gettext \
                 libpam0g-dev python3-all
dpkg-buildpackage -us -uc -b
sudo apt install ../facial-auth_*_amd64.deb ../facial-auth-gtk_*_all.deb
```

Un paquet compilé ainsi n'embarque pas les modèles : il les télécharge à l'installation
(`scripts/build-deb.sh --require-models` les embarque, voir `docs/RELEASE.md`).

### Après l'installation

L'installation crée l'utilisateur `facial-auth`, active la socket systemd et
ajoute le module à `/etc/pam.d/common-auth` (via `pam-auth-update`). Si les
modèles manquent (paquet compilé sans eux, hors ligne) :

```bash
sudo facial-auth fetch-models              # télécharge et vérifie (SHA-256)
sudo facial-auth fetch-models --from DIR   # ou installe depuis un dossier
facial-auth doctor                         # diagnostic complet
```

Puis lier votre visage :

```bash
facial-auth-settings                       # application graphique
sudo facial-auth add --user "$USER"        # ou en ligne de commande
facial-auth import --user "$USER" ~/Images/Camera/*.jpg   # photos de l'appli Caméra
facial-auth check-camera                   # la caméra « infrarouge » ne doit pas voir un écran de téléphone
facial-auth test                           # « est-ce qu'elle me reconnaît ? » (avec le défi de tête)
facial-auth test --liveness                # idem, et affiche les mesures du défi (pour régler challenge_turn)
```

Désinstallation : `sudo apt remove facial-auth` rétablit `common-auth` à
l'identique ; `sudo apt purge facial-auth` supprime en plus les gabarits
biométriques et les modèles.

## Où le visage peut-il servir ?

| Contexte | Service PAM | Mode par défaut | Caméra exigée par défaut |
|---|---|---|---|
| Écrans de connexion et de verrouillage (GNOME, LightDM, Cinnamon, MATE, SDDM) | `gdm-password`, `lightdm`, `cinnamon-screensaver`… | séquentiel | **infrarouge vérifiée** |
| Console texte (Ctrl+Alt+F3) | `login` | parallèle | **infrarouge vérifiée** |
| `sudo` | `sudo`, `sudo-i` | parallèle | **infrarouge vérifiée** |
| `su` | `su`, `su-l` | parallèle | **infrarouge vérifiée** |
| Demandes d'administrateur graphiques | `polkit-1` | séquentiel avec le défi | **infrarouge vérifiée** |

* **Séquentiel** : le scan passe en premier (4 s max, 2 s si personne devant la
  caméra), puis le mot de passe est demandé.
* **Parallèle** : l'invite « Mot de passe » reste affichée pendant le scan ; le
  premier des deux qui aboutit gagne. Valider un mot de passe **vide** relance
  un scan (« réessayer avec mon visage »). `Ctrl-C` abandonne immédiatement.
* **Défi de tête** (par défaut) : une fois le visage reconnu, l'instruction « Tournez nettement la tête
  vers votre gauche, puis vers votre droite, puis regardez l'écran » s'affiche (l'ordre est tiré au hasard)
  et chaque mouvement vu est confirmé ; une photo, plane, ne peut pas la suivre. **Tournez franchement**
  (15 à 20° de chaque côté, comme pour regarder le bord de l'écran) : un mouvement léger ne passe pas.
  En terminal, l'invite du mot de passe reste ouverte pendant tout le défi (on peut taper le mot de passe
  à tout moment) ; ailleurs, un échec redonne la main au mot de passe. Si le défi vous refuse,
  `facial-auth test` dit quoi changer : voir [`docs/SECURITY.md`](docs/SECURITY.md).
* Une **webcam couleur est trompée par une photo affichée sur un téléphone** : par défaut aucun service
  ne l'accepte. Autoriser « toute caméra » pour un service est un choix assumé (application, ou
  `sudo facial-auth service NOM any`).
* Une caméra « infrarouge » n'est une caméra infrarouge que si elle **ne voit pas un écran de
  téléphone** : `facial-auth check-camera` le vérifie (l'assistant d'enrôlement le propose) ; tant que
  ce n'est pas fait, les services qui exigent l'infrarouge n'utilisent pas le visage.
* Jamais de visage : sessions SSH/distantes, capot fermé, compte verrouillé
  (`passwd -l`), `root`, services non listés.

Réglages : `/etc/facial-auth/facial-auth.conf` (toutes les options et leurs
valeurs par défaut : `/usr/share/facial-auth/defaults.conf`).

## Ce qui a été vérifié — et ce qui ne l'a pas été

Vérifié dans un conteneur Ubuntu 24.04 (419 tests automatisés, plus le parcours graphique sous Xvfb) :

* module PAM en C contre le **vrai `pam_unix`**, le **vrai `sudo`** et le **vrai `su`**
  sur un pseudo-terminal : le visage gagne pendant l'invite, mot de passe saisi en
  parallèle réutilisé par `pam_unix` (`PAM_AUTHTOK`), état du terminal restauré,
  frappes non volées, `Ctrl-C`, `sudo -S`, `sudo -n` ;
* **impossibilité de se retrouver bloqué** : une centaine de pannes provoquées sur le paquet
  installé (démon figé, absent, bavard, socket piégée ou saturée, module absent ou corrompu,
  options absurdes…) avec, à chaque fois, le bon mot de passe accepté en un temps borné **et** un
  mauvais mot de passe refusé — voir [`docs/RECOVERY.md`](docs/RECOVERY.md) ;
* module PAM reconstruit avec AddressSanitizer, UndefinedBehaviorSanitizer et ThreadSanitizer,
  puis attaqué (entrées hostiles, démon aléatoire) : aucune anomalie ;
* chaîne complète module C → socket → démon Python → décision → scan (caméra
  et moteur factices) : verrouillage, services IR, modèles absents, caméra HS… et défi de tête
  (une tête 3D synthétique qui tourne ouvre la session ; une photo tenue à la main, ou une rotation
  dans le mauvais ordre, la refuse et le mot de passe est demandé) ;
* API D-Bus sur un vrai bus ; le démon interrogé contre un **vrai `polkitd`** (politique
  installée, autorisation d'un autre utilisateur) ; les décisions polkit des tests
  fonctionnels restent simulées ;
* **défi de tête** : suivi optique et parallaxe du nez, sur sept portraits réels déformés comme une feuille
  tenue à la main et vus par le vrai détecteur de visages (0 passage sur 240 mouvements, y compris avec
  un reflet qui glisse), sur une tête 3D synthétique (82 à 96 % de réussite d'un geste de 2 s) et en
  rediffusion dans le mauvais ordre (0 %) — voir [`docs/SECURITY.md`](docs/SECURITY.md) pour les limites ;
* application graphique sous Xvfb (parcours complet, captures d'écran) ;
* paquet : `lintian` propre, installation, mise à jour, `common-auth` généré puis rétabli,
  purge, démon lancé par activation de socket sous l'utilisateur `facial-auth`.

**Non vérifié ici (à essayer sur votre machine, en commençant par
`facial-auth doctor`)** :

* la reconnaissance sur de **vrais visages** : les modèles YuNet/SFace n'ont pas
  pu être téléchargés dans ce bac à sable (Git LFS bloqué). L'API OpenCV 4.6 a
  été exercée avec un modèle de substitution ; le seuil `recognition.threshold`
  (0,45) est à ajuster avec `facial-auth test` ;
* une **vraie caméra**, en particulier infrarouge (l'émetteur IR peut nécessiter
  un utilitaire externe : option `camera.emitter_command`) ;
* **GDM** : le mode séquentiel est le défaut. Le mode parallèle y est
  expérimental (`[interaction] gdm-password = parallel`) ; la lecture du code de
  GDM 46 montre que sa conversation PAM est thread-safe, mais cela n'a pas été
  essayé sur un vrai écran de connexion ;
* les vraies boîtes de dialogue polkit (la question posée à `polkitd` est vérifiée, pas l'agent graphique
  qui demande le mot de passe administrateur) ;
* le **défi de tête sur de vraies personnes** : les taux de réussite de l'utilisateur viennent d'un modèle
  de tête 3D, pas de vidéos de vrais visages ; `facial-auth test --liveness` donne les mesures de votre
  caméra pour régler `liveness.challenge_turn` ;
* **LightDM / l'écran de verrouillage de Cinnamon** réels : seul le comportement du module avec les
  messages d'information a été éprouvé (terminaux, `su`, `sudo`, harnais PAM).

Limites connues : à l'ouverture de session par le visage, le **trousseau GNOME**
reste verrouillé (il a besoin du mot de passe) ; le chiffrement de disque (LUKS)
au démarrage reste au mot de passe ; voir [`docs/SECURITY.md`](docs/SECURITY.md).

## Développement

```bash
meson setup build --prefix=/usr --libdir=lib/x86_64-linux-gnu && ninja -C build
sudo /usr/bin/python3.12 -m pytest tests/pam tests/python   # PAM + démon + D-Bus + CLI
xvfb-run -a /usr/bin/python3.12 tests/gui/shoot.py /tmp/shots   # interface + captures
sudo /usr/bin/python3.12 -m pytest tests/system             # après installation du .deb : injection de pannes (≈ 8 min),
                                                            # vrai polkitd, retrait/purge (FA_DEB_DIR=dist)
FA_FUZZ_ITERATIONS=5000000 FA_FUZZ_CONVERSATIONS=3000 \
  sudo /usr/bin/python3.12 -m pytest tests/pam/test_robustness.py   # fuzzing sous ASan/UBSan, campagne longue
```

* [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — composants et décisions de conception
* [`docs/PROTOCOL.md`](docs/PROTOCOL.md) — protocole module PAM ↔ démon
* [`docs/SECURITY.md`](docs/SECURITY.md) — modèle de menace, limites, vie privée
* [`docs/RECOVERY.md`](docs/RECOVERY.md) — installation prudente et procédures de secours
* [`docs/RELEASE.md`](docs/RELEASE.md) — publier une version, paquets `.deb` des releases

Licence : MIT (voir `LICENSE`). Les modèles téléchargés conservent leur propre
licence : YuNet (MIT), SFace (Apache-2.0), de
[opencv_zoo](https://github.com/opencv/opencv_zoo).
