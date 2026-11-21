# Ne jamais se retrouver bloqué dehors

Un module d'authentification est le dernier endroit où l'on veut un défaut. Cette page
dit ce qui est garanti (et comment c'est **vérifié**), ce qu'il faut faire avant
d'installer, et comment revenir en arrière si malgré tout quelque chose tournait mal.

## Ce qui est garanti

**Le module PAM ne peut que dire « oui » ou « je ne sais pas » — jamais « non ».**

* Il répond « oui » uniquement quand le démon lui a envoyé `OK` en toutes lettres, sur une
  socket dont l'autre bout appartient à `root` ou à l'utilisateur `facial-auth`.
* Dans **tous** les autres cas (démon absent, figé, qui répond n'importe quoi, visage non
  reconnu, caméra HS, modèles manquants…) il répond « je ne sais pas » (`PAM_IGNORE`) : la pile
  continue et `pam_unix` demande le mot de passe comme d'habitude. Un échec facial n'est
  **jamais** compté comme une tentative de connexion ratée.
* Chaque attente du module est bornée par **sa propre horloge**, jamais par celle du démon : un
  démon qui ne répond plus coûte quelques secondes, pas la connexion.
* Un compte **sans visage lié** n'est même pas concerné : le module le constate en lisant un
  fichier et rend la main tout de suite, sans contacter le démon ni la caméra.
* Le module n'est ajouté à la pile qu'**après avoir été chargé avec succès** dans un processus
  jetable (voir plus bas pourquoi).

### Mesuré, pas supposé

La batterie `tests/system/test_lockout.py` provoque chaque panne sur le **paquet installé**, avec le
vrai `sudo`, le vrai `su`, le vrai `pam_unix` et le vrai `/etc/pam.d/common-auth`. Pour chaque
cas, elle vérifie deux choses : le **bon** mot de passe est accepté en un temps borné, et un
**mauvais** mot de passe est toujours refusé (une panne ne doit jamais ouvrir de porte).

| Panne simulée | Délai avant l'invite du mot de passe |
|---|---|
| Socket du démon absente, périmée, ou qui n'est pas une socket (fichier, dossier, tube, lien) | immédiat |
| Fichier du module absent, vide, texte, aléatoire, ni bibliothèque ni module PAM | immédiat (PAM l'ignore) |
| Options absurdes dans `/etc/pam.d/common-auth` (noms inconnus, nombres extrêmes, chemins invalides) | au plus ≈ 4 s |
| Démon qui accepte la connexion et ne dit jamais rien | ≈ 4 s (`connect_timeout`) |
| File d'attente de la socket pleine, démon qui n'accepte plus | ≈ 1 s |
| Démon qui ferme, réinitialise la connexion, envoie du bruit, une ligne énorme ou sans fin de ligne | immédiat |
| Démon qui répond `OK` sans fin de ligne, ou avant la poignée de main | **jamais accepté** (mot de passe demandé) |
| Socket créée par un autre utilisateur annonçant `OK` | **jamais crue** (mot de passe demandé) |
| Démon qui annonce le scan puis se tait (écran de connexion, mode séquentiel) | ≈ 5 s (2 s annoncées + 3 s de marge) |
| Démon qui demande le défi de tête puis se tait (`sudo`, `su`, écran de connexion) | la durée du défi annoncée + 3 s de marge (≈ 15 s au plus par défaut) ; dans un terminal l'invite du mot de passe est restée ouverte et accepte le mot de passe pendant tout ce temps |
| Valeur absurde annoncée (NaN, négative, démesurée) en mode séquentiel | ≈ 11 s au plus |
| Mode parallèle (`sudo`, `su`, console ; polkit si le défi de tête est désactivé) : n'importe quelle panne du démon | l'invite est déjà affichée : on peut taper le mot de passe pendant le scan |
| Vrai `facial-authd` figé (`SIGSTOP`) ; vrai démon sans visage enregistré ; 60 connexions inactives | ≈ 4 s ; immédiat ; immédiat |

Et, pour le seul risque qu'aucune configuration PAM ne peut absorber — **un plantage du module
dans l'application qui l'appelle** — le module est reconstruit avec AddressSanitizer,
UndefinedBehaviorSanitizer et ThreadSanitizer, puis attaqué : deux millions d'entrées hostiles sur
chaque analyseur, et des milliers de conversations avec un démon aléatoire (`tests/pam/fuzz_input.c`,
`tests/pam/test_robustness.py`). Aucune anomalie ne subsiste.

### Ce qui n'est pas rattrapable (et ce qu'on en fait)

Un fichier de module **tronqué ou corrompu** fait mourir le chargeur dynamique (`SIGBUS`) dans
`sudo`, `su` ou l'écran de connexion : PAM ne peut pas ignorer un plantage, et c'est vrai de
n'importe quelle bibliothèque. Deux parades :

* `dpkg` remplace les fichiers de façon atomique : le module installé n'est jamais « à moitié écrit » ;
* le script d'installation **charge le module dans un processus jetable** avant de l'ajouter à la pile
  d'authentification, et le retire de la pile s'il ne se charge pas. `facial-auth doctor` fait le même
  contrôle (ligne « PAM module loads »).

Il reste le cas d'un disque qui se corrompt après coup : c'est pour cela que les consignes
ci-dessous commencent par **garder un shell root ouvert**.

## Avant d'installer (deux minutes)

1. **Ouvrez un terminal root et ne le fermez pas** : `sudo -s`. Tant qu'il est ouvert, vous pouvez
   tout défaire, quoi qu'il arrive aux autres sessions.
2. Sauvegardez la configuration PAM : `sudo cp -a /etc/pam.d /root/pam.d.sauvegarde`
3. Gardez à portée une **seconde session** (changement de terminal virtuel : `Ctrl+Alt+F3`,
   retour : `Ctrl+Alt+F1` ou `F2`).
4. Installez : `sudo apt install ./facial-auth_*.deb ./facial-auth-gtk_*.deb`

## Après l'installation : testez *avant* de fermer quoi que ce soit

Dans un **nouveau** terminal (pas celui qui est root) :

```bash
facial-auth doctor          # tout doit être ✔ (hors « Comptes liés : aucune » tant qu'aucun visage n'est lié)
sudo -k && sudo true        # doit demander votre mot de passe et l'accepter
su - un_autre_compte        # idem, si vous avez un second compte
```

Puis verrouillez l'écran et déverrouillez-le avec votre mot de passe, et connectez-vous sur un
terminal virtuel (`Ctrl+Alt+F3`) **pendant que le terminal root est encore ouvert**. Seulement
ensuite, liez votre visage et recommencez les mêmes essais.

### Les premiers jours : le visage seulement pour `sudo`, `su` et polkit

Par défaut, le visage est aussi proposé sur l'écran de connexion et l'écran de verrouillage
(`gdm-password`, `lightdm`, `sddm`, `cinnamon-screensaver`, `mate-screensaver`, `xscreensaver`) et sur
la console (`login`). Ce sont les écrans qu'on ne peut pas dépanner depuis la session elle-même, et
les vrais écrans de connexion n'ont été essayés ici qu'avec des substituts (voir le README). Tant que
vous ne les avez pas éprouvés sur votre machine, laissez-les au mot de passe en ajoutant à
`/etc/facial-auth/facial-auth.conf` :

```ini
[services]
gdm-password = off
lightdm = off
sddm = off
cinnamon-screensaver = off
mate-screensaver = off
xscreensaver = off
login = off
```

puis `sudo systemctl restart facial-authd`. Le visage reste actif pour `sudo`, `su` et les demandes
d'administrateur, où un échec se dépanne depuis un terminal. Supprimez les lignes (ou mettez `any`, toute caméra, ou `ir`, infrarouge seulement) quand vous êtes prêt à essayer l'écran de connexion — toujours avec un terminal root
ouvert, et en vous connectant d'abord depuis un autre terminal virtuel.

## Si quelque chose ne va pas

| Situation | Que faire |
|---|---|
| Quelques secondes d'attente avant le mot de passe | Normal si la caméra ou le démon est lent. Réglez `[recognition]` (voir `defaults.conf`) ou neutralisez le visage (ci-dessous). |
| Vous avez un shell root ouvert | `pam-auth-update --package --remove facial-auth` (rétablit `common-auth` à l'identique), ou `apt remove facial-auth`. |
| Le visage ne vous reconnaît plus ou le défi de tête vous gêne | `[liveness] mode = basic` dans `/etc/facial-auth/facial-auth.conf` retire le défi (une photo suffit alors devant une caméra couleur) ; `facial-auth test` dit quoi changer (tourner plus loin, moins vite…) et `--liveness` donne les mesures pour régler `challenge_turn` ; `facial-auth check-camera` si le journal dit `camera-unverified`. |
| Vous voulez garder le paquet mais couper le visage | `[core] enabled = false` dans `/etc/facial-auth/facial-auth.conf` puis `sudo systemctl restart facial-authd` (le démon relit sa configuration au démarrage), ou `sudo systemctl mask --now facial-authd.socket` (le module trouve alors la socket absente : immédiat), ou `sudo facial-auth disable --user NOM` pour un seul compte, ou décochez *Facial authentication* dans `sudo pam-auth-update`. |
| Plus de shell root, mais un terminal virtuel utilisable | Connectez-vous avec votre mot de passe sur `Ctrl+Alt+F3` puis `sudo pam-auth-update --package --remove facial-auth`. |
| Plus aucun accès | Démarrez en **mode de secours** : au démarrage, maintenez `Maj` (BIOS) ou appuyez sur `Échap` (UEFI) pour afficher GRUB → *Options avancées* → *(recovery mode)* → *root*. Puis : `mount -o remount,rw /` et `pam-auth-update --package --remove facial-auth`. |
| `pam-auth-update` lui-même est cassé | Dans le même shell root : `mv /usr/lib/x86_64-linux-gnu/security/pam_facial_auth.so /root/`. Un module absent est **ignoré** par PAM (c'est un des cas testés ci-dessus) : la connexion par mot de passe fonctionne aussitôt. |
| Session live (clé USB) | Montez le disque, supprimez le fichier `…/security/pam_facial_auth.so` ou la ligne `pam_facial_auth.so` de `/etc/pam.d/common-auth`. |

Pour désinstaller complètement, y compris les gabarits biométriques et les modèles :
`sudo apt purge facial-auth facial-auth-gtk`.
