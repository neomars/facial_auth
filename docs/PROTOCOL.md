# Protocole module PAM ↔ démon

Le module PAM (`pam_facial_auth.so`, en C) discute avec le démon (`facial-authd`,
en Python) sur une socket Unix `SOCK_STREAM` : `/run/facial-auth/pam.sock`.

* Une **connexion = une tentative** d'authentification. Fermer la connexion
  annule la tentative (le démon arrête aussitôt la caméra).
* Le protocole est **textuel**, une ligne par message, terminée par `\n`,
  1023 octets maximum. Pas de JSON : un module chargé dans `sudo`, `su`, `gdm`
  ou `polkit` ne doit embarquer aucun analyseur complexe.
* Une ligne = un verbe en majuscules suivi de paires `clé=valeur` séparées par
  un espace. Les valeurs sont encodées en *pourcentage* (RFC 3986 : seuls
  `A-Za-z0-9-._~` restent tels quels).

## Module → démon

```
VERIFY v=1 user=alice service=sudo tty=%2Fdev%2Fpts%2F3 rhost= ruser=alice
```

| clé       | sens                                                      |
|-----------|-----------------------------------------------------------|
| `v`       | version du protocole (`1`)                                |
| `user`    | utilisateur à authentifier (`PAM_USER`)                   |
| `service` | service PAM (`PAM_SERVICE` : `sudo`, `gdm-password`, …)   |
| `tty`     | `PAM_TTY` (informatif)                                    |
| `rhost`   | `PAM_RHOST` ; non vide ⇒ session distante                 |
| `ruser`   | `PAM_RUSER` (informatif, journalisation)                  |

Le démon ne fait **pas** confiance à ces champs pour les décisions de
sécurité qu'il peut recouper lui-même : l'UID de l'appelant vient de
`SO_PEERCRED`, la session logind (locale / distante) est déduite du PID de
l'appelant.

## Démon → module

La première réponse est toujours `ACCEPT` ou `SKIP`.

```
ACCEPT mode=parallel-tty timeout=8.0
SKIP reason=not-enrolled
```

* `ACCEPT` : la tentative démarre. `mode` indique comment le module doit
  gérer le mot de passe pendant le scan, `timeout` est la durée maximale de
  l'ensemble (secondes) : reconnaissance **et** défi de tête quand il est actif.
* `SKIP` : ne rien faire ; le module renvoie `PAM_IGNORE` et la pile PAM
  continue avec le mot de passe. `reason` ∈ `not-enrolled`, `disabled`,
  `service-denied`, `remote-session`, `lid-closed`, `no-camera`,
  `camera-class`, `camera-unverified` (caméra « infrarouge » pas encore
  vérifiée par `facial-auth check-camera`), `busy`, `locked-out`,
  `root-denied`, `user-unknown`, `bad-request`, `internal`.

Après `ACCEPT`, le démon envoie zéro ou plusieurs `STATE` puis exactement un
message final :

```
STATE phase=searching
STATE phase=face
STATE phase=challenge seq=lr timeout=8.0
OK score=0.612
FAIL reason=timeout
```

`STATE phase=challenge seq=lr|rl timeout=8.0` : le visage est reconnu, la personne doit
maintenant tourner la tête (`lr` : vers *sa* gauche puis vers sa droite ; `rl` :
l'inverse, voir `challenge.py`). `timeout` est la durée du défi seul : à partir de là, le
module n'attend plus que cette durée (+ 3 s de marge) au lieu de ce qui reste du budget annoncé
par `ACCEPT`. Le démon n'envoie que ces codes ; **le texte de
l'instruction et sa traduction sont dans le module**, qui l'affiche par
`pam_info`. En mode `sequential` c'est immédiat ; en `parallel-tty` le module
annule d'abord l'invite de mot de passe en attente (comme pour un visage
reconnu : état du terminal rétabli) pour avoir la conversation à lui, et, si le
défi échoue, `pam_unix` redemande le mot de passe ; en `parallel` (dialogue
graphique qui garde son invite ouverte) l'invite ne peut pas être interrompue :
le démon n'y demande pas de défi (il passe le service en `sequential`).

`FAIL reason` ∈ `timeout`, `no-face`, `mismatch`, `spoof` (surface plane ou
autre personne pendant le défi), `challenge` (visage reconnu mais défi non
accompli : délai dépassé, pas assez de texture, visage perdu), `camera-error`,
`cancelled`, `error`.

Un module ne considère l'authentification réussie que sur `OK`, reçu sur une
socket dont le pair est `root` (ou l'utilisateur système du démon). Tout
autre cas (EOF, ligne illisible, délai dépassé) équivaut à un échec : le
module renvoie `PAM_IGNORE`, jamais `PAM_AUTH_ERR`, de sorte qu'un échec
facial ne compte pas comme une tentative de mot de passe et ne verrouille
jamais le compte.

## Délais : toutes les attentes du module sont bornées par sa propre horloge

Le démon est de confiance mais pas infaillible : rien de ce qu'il dit ou ne dit pas ne peut faire
attendre une connexion indéfiniment.

| Étape | Borne |
|---|---|
| `connect()` (socket non bloquante) | file d'attente pleine : nouvelles tentatives pendant 1 s au plus |
| envoi de `VERIFY` | `connect_timeout` (4 s par défaut) |
| attente de `ACCEPT`/`SKIP` | `connect_timeout` (4 s par défaut) |
| scan (tous modes) | `timeout` annoncé + 3 s de marge ; un `timeout` hors de `[0.5, 60]` ou non numérique (`nan`, `inf`…) devient 8 s |
| ligne reçue | 1024 octets au plus, terminée par `\n` : sinon la connexion est abandonnée |

Passé une borne, le module renvoie `PAM_IGNORE` et la pile demande le mot de passe. Les seules
attentes sans borne sont celles que l'utilisateur impose lui-même : le mot de passe qu'il tape.

## Modes d'interaction

| `mode`         | comportement du module                                                       |
|----------------|------------------------------------------------------------------------------|
| `sequential`   | scan d'abord ; en cas d'échec la pile PAM invite ensuite au mot de passe     |
| `parallel`     | l'invite « Password: » est affichée *pendant* le scan (thread dédié) ; si le visage gagne, l'invite en attente est **abandonnée** (frontaux graphiques) |
| `parallel-tty` | comme `parallel`, mais l'invite en attente est **annulée** (`pthread_cancel`) et l'état du terminal restauré (`sudo`, `su`, `login`) |

Dans les modes parallèles, si l'utilisateur valide un mot de passe vide, le
module relance un scan (jusqu'à `max_rescans` fois) : c'est le geste « je
veux réessayer avec mon visage ». Un mot de passe non vide est transmis au
module suivant de la pile (`pam_unix`, `pam_gnome_keyring`, …) via
`PAM_AUTHTOK` ; le module renvoie alors `PAM_IGNORE`.
