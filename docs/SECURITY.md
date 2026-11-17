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
| **Force brute** | après `max_failures` visages inconnus en `failure_window` s, le chemin facial est verrouillé `lockout` s (le mot de passe n'est jamais verrouillé par ce mécanisme) |
| Fichier de configuration mal édité | valeurs bornées (seuil ≥ 0,30), fichier invalide ignoré **en entier** et signalé |
| Fichier de gabarits corrompu | traité comme « aucun visage », jamais comme « tous les visages » |
| Image piégée envoyée à l'API | taille limitée (8 Mio, 32 Mpx), démon sans privilèges, sans réseau, sous `MemoryMax` |
| Modèle ONNX altéré | SHA-256 épinglé, vérifié au téléchargement **et** avant chargement |
| Session **SSH** / distante | pas de visage (hôte PAM, `SSH_*`, session logind distante) |
| Compte verrouillé (`passwd -l`), `root` | pas de visage |
| Un admin qui s'éloigne, session déverrouillée | l'élévation (`sudo`/polkit) exige une caméra IR par défaut |

## Ce qui n'est PAS couvert

* **Une photo, une vidéo sur un téléphone, un masque** devant une **webcam
  couleur** peuvent tromper la reconnaissance. Les contrôles de vivacité
  fournis ne détectent que le **rejeu d'images strictement identiques** (flux
  figé, caméra virtuelle) ; une heuristique de micro-mouvement avait été essayée
  puis abandonnée (elle rejette les personnes très immobiles et gêne peu un
  attaquant). La parade réelle est la **caméra infrarouge** : c'est pourquoi
  `sudo`, `su` et polkit l'exigent par défaut. Ouvrir ces services à une webcam
  couleur (`facial-auth service sudo any`) est un choix explicite.
* **Un attaquant physique avec votre photo** peut ouvrir l'écran de connexion
  *si* vous avez autorisé les webcams couleur pour `gdm-password` (le défaut).
  Si votre modèle de menace l'inclut : `facial-auth service gdm-password ir`
  ou `off`.
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

## Durcissement recommandé

* Préférer une caméra infrarouge ; laisser `sudo`/`su`/`polkit` sur `ir`.
* Garder `liveness.mode = basic`, `security.allow_root = false`,
  `abort_if_remote = true`.
* Pour un portable souvent branché sur écran externe capot fermé, la caméra
  intégrée ne voit rien : le visage est ignoré (c'est voulu).
* Signaler une faille : voir le dépôt du projet.
