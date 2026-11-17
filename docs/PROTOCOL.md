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
  gérer le mot de passe pendant le scan, `timeout` est la durée maximale du
  scan (secondes).
* `SKIP` : ne rien faire ; le module renvoie `PAM_IGNORE` et la pile PAM
  continue avec le mot de passe. `reason` ∈ `not-enrolled`, `disabled`,
  `service-denied`, `remote-session`, `lid-closed`, `no-camera`,
  `camera-class`, `busy`, `locked-out`, `root-denied`, `user-unknown`,
  `bad-request`, `internal`.

Après `ACCEPT`, le démon envoie zéro ou plusieurs `STATE` puis exactement un
message final :

```
STATE phase=searching
STATE phase=face
OK score=0.612
FAIL reason=timeout
```

`FAIL reason` ∈ `timeout`, `no-face`, `mismatch`, `spoof`, `camera-error`,
`cancelled`, `error`.

Un module ne considère l'authentification réussie que sur `OK`, reçu sur une
socket dont le pair est `root` (ou l'utilisateur système du démon). Tout
autre cas (EOF, ligne illisible, délai dépassé) équivaut à un échec : le
module renvoie `PAM_IGNORE`, jamais `PAM_AUTH_ERR`, de sorte qu'un échec
facial ne compte pas comme une tentative de mot de passe et ne verrouille
jamais le compte.

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
