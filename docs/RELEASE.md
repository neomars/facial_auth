# Publier une version

Créer une release sur GitHub **compile les paquets `.deb` et les attache à la
release** : on les télécharge ensuite depuis la page de la release.

## En bref

1. Les changements sont fusionnés dans `main` (le workflow doit exister sur le
   commit qui reçoit le tag).
2. **GitHub → Releases → Draft a new release**
   * *Choose a tag* : saisir `v0.2.0` puis *Create new tag on publish* ;
   * *Target* : `main` ;
   * titre et notes, puis **Publish release**.

   En ligne de commande : `gh release create v0.2.0 --target main --generate-notes`.
3. L'onglet **Actions → « Paquet Debian »** montre la progression (≈ 10 min).
   À la fin, la release contient :

   | Fichier | Contenu |
   |---|---|
   | `facial-auth_0.2.0_amd64.deb` | module PAM, démon, ligne de commande, **modèles de reconnaissance** |
   | `facial-auth-gtk_0.2.0_all.deb` | application « Connexion par le visage » |
   | `SHA256SUMS` | empreintes des deux paquets |

Pour une version de test, cocher **Set as a pre-release**.

## Numéro de version

Le **tag donne la version** ; les fichiers du dépôt n'ont pas à être modifiés.

| Tag | Version du paquet |
|---|---|
| `v1.2.3` | `1.2.3` |
| `v1.2.3-rc1` | `1.2.3~rc1` (une pré-version Debian se classe *avant* la version finale) |

`scripts/set-version.sh` l'écrit dans `meson.build`, `src/facial_auth/const.py`,
les pages de manuel et une nouvelle entrée de `debian/changelog`, dans la copie
de compilation. `facial-auth --version` affiche donc bien le numéro de la release.
Un tag qui n'est pas de la forme `vX.Y.Z[-suffixe]` fait échouer le workflow
immédiatement, avant toute compilation.

Dans les noms de fichiers, `~` devient `-` (et `+` devient `.`) : les sites de
téléchargement réécrivent certains caractères, et `SHA256SUMS` doit rester
cohérent. `apt` et `dpkg` lisent la version dans le paquet, pas dans son nom.

## Ce que fait le workflow (`.github/workflows/deb.yml`)

Trois jobs, dans cet ordre ; **rien n'est publié si un seul échoue** :

1. **Compiler** — version tirée du tag ; installation des dépendances de
   compilation (lues dans `debian/control`) ; téléchargement des modèles
   YuNet et SFace avec **vérification SHA-256** ; compilation ; `lintian
   --fail-on error` ; tests (module PAM, démon, D-Bus, CLI).
2. **Vérifier** — sur une machine *neuve* : installation des `.deb` avec leurs
   dépendances (c'est ce qui révèle une dépendance oubliée), vérification de la
   version, de l'utilisateur système, des modèles et de l'intégration PAM, puis
   les tests système avec le vrai `sudo` et le vrai `su`.
3. **Publier** — uniquement pour une release : envoi des fichiers sur la
   release (`gh release upload`). C'est le seul job qui a le droit d'écrire dans
   le dépôt.

Le même workflow tourne sur chaque **pull request** (sans publier) et peut être
lancé à la main (**Actions → Paquet Debian → Run workflow**, version
facultative) : les paquets sont alors téléchargeables depuis la page du run,
dans l'artefact `paquets-debian`.

Un test qui échoue au premier essai est relancé une fois (avertissement dans le
journal) ; un vrai défaut échoue deux fois.

## Les modèles sont dans le paquet

Les paquets des releases **embarquent** les modèles (≈ 39 Mo) : l'installation
fonctionne **hors ligne** et ne dépend pas de la disponibilité de GitHub LFS.
Leurs licences (YuNet : MIT, SFace : Apache-2.0) figurent dans
`debian/copyright`. Un paquet compilé sans eux (`dpkg-buildpackage` seul) les
télécharge à l'installation.

## Compiler en local

```bash
sudo apt install build-essential devscripts equivs lintian
sudo mk-build-deps --install --remove debian/control
python3 scripts/fetch-models.py data/models            # télécharge et vérifie
scripts/build-deb.sh --require-models 0.2.0            # -> dist/*.deb + SHA256SUMS
```

La compilation se fait dans une copie temporaire : l'arbre de travail n'est jamais
modifié. Sans `--require-models`, un paquet sans modèles est produit.

## Vérifier un téléchargement

```bash
sha256sum -c --ignore-missing SHA256SUMS
sudo apt install ./facial-auth_0.2.0_amd64.deb ./facial-auth-gtk_0.2.0_all.deb
```

`SHA256SUMS` est déposé par le même travail, sur la même release, que les paquets : il détecte un
téléchargement corrompu, pas une release modifiée par quelqu'un qui contrôlerait le compte du
mainteneur. **À faire** (l'audit de novembre 2026 l'a relevé, voir `docs/SECURITY.md`) :

* signer `SHA256SUMS` (GPG, minisign ou Sigstore) et publier l'empreinte de la clé dans le README ;
* produire une attestation de provenance (`actions/attest-build-provenance`), vérifiable avec
  `gh attestation verify` ;
* épingler `actions/checkout`, `upload-artifact` et `download-artifact` par empreinte de commit
  (`gh api repos/actions/checkout/commits/v4 --jq .sha`, puis laisser Dependabot les tenir à jour).

## Essayer sans publier de vraie version

* ouvrir une pull request : les jobs *Compiler* et *Vérifier* tournent ;
* ou **Actions → Paquet Debian → Run workflow** ;
* ou publier une pré-release `v0.0.1-test`, vérifier, puis supprimer la release
  *et* le tag (`gh release delete v0.0.1-test --cleanup-tag`).

## Dépannage

| Symptôme | Cause probable |
|---|---|
| Rien ne se passe à la publication | le tag pointe sur un commit **antérieur** au workflow (créer le tag sur `main` à jour) ; une release en *brouillon* ne déclenche rien tant qu'elle n'est pas publiée ; vérifier que les Actions sont activées |
| `invalid version '…'` | le tag n'est pas de la forme `vX.Y.Z` ou `vX.Y.Z-rc1` |
| Échec de « Télécharger les modèles » | réseau ou quota Git LFS d'`opencv_zoo` : relancer (*Re-run failed jobs*). Une erreur *checksum mismatch* signifie que le dépôt amont a changé : mettre à jour les empreintes dans `src/facial_auth/models.py` |
| « Resource not accessible by integration » à la publication | *Settings → Actions → General → Workflow permissions* interdit l'écriture ; le job `publish` demande `contents: write`, ce qui est normalement permis |
| Impossible d'ajouter les fichiers à la release | l'option *Immutable releases* du dépôt est activée : elle interdit tout ajout après publication ; la désactiver |
| Avertissement « Node.js … deprecated » | monter les versions de `actions/checkout`, `upload-artifact` et `download-artifact` dans le workflow |

## Architectures

Seul `amd64` est compilé. `arm64` demanderait un runner `ubuntu-24.04-arm`
(gratuit pour les dépôts publics uniquement) et une matrice dans le workflow.
