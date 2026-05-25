# Exceptions

Toutes les exceptions de Pycryptox héritent de `PycryptoxError`, elle-même héritant de `Exception`. Elles sont exposées directement au niveau du module racine : `crx.DecryptionError`, `crx.KeyxError`, etc.


## Hiérarchie

```
Exception
└── PycryptoxError               Exception de base de Pycryptox.
    ├── VersionNotFoundError     Version de protocole inconnue.
    ├── ArgumentTypeError        Type d'argument invalide.
    ├── DecryptionError          Échec de déchiffrement.
    ├── EncryptionError          Échec de chiffrement.
    ├── StegaError               Échec de stéganographie (YELLOW, futur).
    ├── UnstegaError             Échec de déstéganographie (YELLOW, futur).
    ├── KeyxError            Erreur de Keyx (fichier, format, état).
    ├── KeyNameError             Erreur liée au nom d'une entrée dans un Keyx.
    ├── WrongPasswordError       Mot de passe incorrect pour un Keyx.
    └── DowngradeError           Downgrade refusé dans `update_bundle` (forcer avec `downgrade=True`).
```


## Descriptions détaillées

### `PycryptoxError`

Exception de base. Ne doit pas être levée directement. Permet d'intercepter toutes les erreurs Pycryptox avec un seul `except crx.PycryptoxError`.


### `VersionNotFoundError`

Levée quand le paramètre `version` ne correspond à aucune version implémentée dans le protocole.

Message : `"The version '<version>' being sought could not be found"`.

Exemples de déclenchement :
- `crx.purple.encrypt("99", ...)` — version 99 n'existe pas.
- `crx.blue.decrypt("1", ...)` sur un bundle dont la version extraite est `"2.0"` et `"2.0"` n'est pas implémentée.


### `ArgumentTypeError`

Levée quand un argument a un type Python incorrect. Chaque protocole et chaque méthode keyx valide les types de ses arguments avant de procéder.

Message : `"The variable type '<type>' used for the value of the argument '<nom>' is invalid"`.

Exemples de déclenchement :
- `crx.purple.encrypt("1", 123, "msg")` — `key` est un `int`, pas un `str`.
- `crx.red.genkeys("1", 2.0, 3)` — `t` est un `float`, pas un `int`.
- `crx.red.genkeys("1", True, 3)` — les booléens sont rejetés (même si `bool` est un sous-type de `int` en Python, RED les refuse explicitement).


### `DecryptionError`

Levée quand le déchiffrement échoue, quelle qu'en soit la cause.

Message : `"Error during decryption because '<raison>'"`.

Causes possibles (non exhaustif) :
- Mot de passe ou clé privée incorrects.
- Message corrompu ou tronqué.
- Version du bundle incompatible avec la version demandée.
- Bundle base64 invalide.
- Parts RED insuffisantes ou invalides.
- Clé chimique BLUE invalide.

Par conception, un mot de passe faux et un message corrompu produisent la même exception avec le même type de message. L'appelant ne peut pas distinguer ces cas, ce qui est un choix de sécurité.


### `EncryptionError`

Levée quand le chiffrement échoue.

Message : `"Error during encryption because '<raison>'"`.

Causes possibles :
- Clé publique invalide (taille incorrecte, base64 malformé).
- Paramètres de seuil RED invalides.
- Messages BLUE dans des buckets différents.
- Message BLUE trop grand (> 1 Mo).


### `StegaError`

Réservée pour YELLOW v1.0. Non utilisée dans la version actuelle.

Message : `"Error during stega because '<raison>'"`.


### `UnstegaError`

Réservée pour YELLOW v1.0. Non utilisée dans la version actuelle.

Message : `"Error during unstega because '<raison>'"`.


### `KeyxError`

Levée pour toute erreur liée à l'état ou au format d'un Keyx.

Message : `"Error with Keyx because '<raison>'"`.

Causes possibles :
- Extension de fichier incorrecte.
- Magic de fichier incompatible (mauvais type de Keyx).
- Fichier corrompu.
- Fichier introuvable.
- Opération sur une session fermée.
- Champ vide dans une entrée bluekeys.


### `KeyNameError`

Levée pour les erreurs liées aux noms d'entrées dans un Keyx.

Message : `"Error with key name because '<raison>'"`.

Causes possibles :
- Entrée non trouvée (dans `getkey`, `get`, `update`, `rename`, `delete`).
- Nom dupliqué (dans `add`).
- Nom vide (dans `add`, `rename`).
- Collision de noms (dans `rename`).


### `WrongPasswordError`

Levée quand le mot de passe fourni à un Keyx est incorrect.

Message : `"Wrong password because '<raison>'"`.

Levée par `open()`, `destroy()` (si `passwordrequired=True`), et `changepwd()` (si l'ancien mot de passe est faux).


### `DowngradeError`

Levée par `update_bundle` quand la migration ferait passer un bundle à une version de protocole plus ancienne, et que `downgrade=True` n'a pas été passé explicitement.

Message : `"Refused to downgrade from v<old> to v<new>; pass downgrade=True to force"`.

Le défaut `downgrade=False` impose des migrations uniquement ascendantes. Passer `downgrade=True` comme dernier argument d'`update_bundle` pour contourner ce contrôle quand on veut vraiment écrire un bundle plus ancien (tests, interop avec des lecteurs legacy).


## Usage en interception

```python
import pycryptox as crx

# Intercepter toutes les erreurs Pycryptox
try:
    crx.purple.decrypt("1", "wrong-pwd", bundle)
except crx.DecryptionError:
    print("Déchiffrement échoué")
except crx.PycryptoxError:
    print("Autre erreur Pycryptox")

# Intercepter spécifiquement les erreurs de Keyx
try:
    with crx.keyx.purplekeys.open("pwd", "store.purple") as s:
        s.getkey("unknown")
except crx.WrongPasswordError:
    print("Mot de passe incorrect")
except crx.KeyNameError:
    print("Entrée non trouvée")
except crx.KeyxError:
    print("Problème de Keyx")
```
