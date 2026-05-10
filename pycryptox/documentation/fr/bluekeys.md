# keyx.bluekeys

`bluekeys` est un gestionnaire de clés chiffrées pour stocker les canaux de communication BLUE. Il se compose de deux sous-modules :

- **`crx.keyx.bluekeys.keys`** — stocke les canaux BLUE standard (extension `.keys`).
- **`crx.keyx.bluekeys.ckeys`** — stocke les canaux BLUE critiques/déniables (extension `.ckeys`).

Les deux sous-modules ont la même API à trois détails près : l'extension de fichier, le magic du fichier, et le nom du champ de clé privée (`privkey` vs `cprivkey`).


## Pourquoi deux sous-modules séparés

La séparation entre `keys` et `ckeys` sert la **déniabilité plausible** du protocole BLUE.

Dans un scénario de déniabilité, l'utilisateur possède deux clés privées pour chaque canal : une clé de leurre et une clé réelle. La clé de leurre est stockée dans le keystore `keys`, accessible sur la machine de l'utilisateur. Pourquoi stocker le leurre dans le keystore principal ? Parce que c'est le keystore que l'adversaire forcera l'utilisateur à ouvrir en cas de coercition. L'adversaire y trouvera la clé de leurre, déchiffrera le message leurre, et obtiendra un résultat crédible — sans savoir qu'une autre clé existe ailleurs.

La clé réelle est stockée dans le keystore `ckeys`, sur un support physiquement séparé (clé USB, disque externe, etc.) qui n'est pas présent au moment de la coercition. L'adversaire ne peut pas forcer l'ouverture d'un fichier dont il ignore l'existence et qui est physiquement absent.

La bibliothèque fournit les deux stores. La gestion du support physique (USB, séparation des fichiers) est de la responsabilité de l'utilisateur ou du logiciel CLI.


## Schéma des entrées

Chaque entrée dans un keystore bluekeys représente un **canal de correspondance** (pas une personne). L'utilisateur choisit librement le nom de chaque canal.

### `keys` — champs par entrée

| Champ | Type | Description |
|---|---|---|
| `mygpubkey` | `str` | Ma clé publique composite BLUE pour ce canal. |
| `hgpubkey` | `str` | La clé publique composite BLUE de mon interlocuteur. |
| `privkey` | `str` | Ma clé privée pour ce canal. |

### `ckeys` — champs par entrée

| Champ | Type | Description |
|---|---|---|
| `mygpubkey` | `str` | Ma clé publique composite BLUE pour ce canal. |
| `hgpubkey` | `str` | La clé publique composite BLUE de mon interlocuteur. |
| `cprivkey` | `str` | Ma clé privée critique pour ce canal. |

La seule différence de schéma est le nom du troisième champ : `privkey` dans `keys`, `cprivkey` dans `ckeys`. Tous les champs sont des `str` (base64url), non vides, obligatoires.


## Format de fichier

Les deux sous-modules utilisent le même layout que purplekeys :

```
[16 octets : magic]  [4 octets : head_len (BE32)]  [head_ct]  [payload_ct]
```

| Sous-module | Magic | Extension |
|---|---|---|
| `keys` | `CRXKX_BLUEKEYS_1` | `.keys` |
| `ckeys` | `CRXKX_BLUECKEY_1` | `.ckeys` |

Les fichiers sont chiffrés avec PURPLE. L'intégrité est garantie par le tag Poly1305. Les écritures sont atomiques.

La discrimination par magic empêche d'ouvrir un fichier `.ckeys` avec le module `keys` (et inversement), même si l'extension est renommée manuellement. C'est une double protection : extension + magic.


## API

L'API est identique entre `keys` et `ckeys`. Les exemples ci-dessous utilisent `keys` ; pour `ckeys`, remplacer `keys` par `ckeys`, `.keys` par `.ckeys`, et `privkey` par `cprivkey`.


### Fonctions de module

#### `createdb(password, dbpath) -> None`

Crée un nouveau keystore vide.

```python
crx.keyx.bluekeys.keys.createdb("master-pwd", "channels.keys")
crx.keyx.bluekeys.ckeys.createdb("master-pwd", "/usb/critical.ckeys")
```

**Exceptions** :
- `KeystoreError` — si le fichier existe déjà ou si l'extension est incorrecte.
- `ArgumentTypeError` — si `password` n'est pas un `str`.

#### `open(password, dbpath) -> _KeysSession / _CKeysSession`

Ouvre un keystore existant. Retourne une session (context manager).

```python
with crx.keyx.bluekeys.keys.open("master-pwd", "channels.keys") as s:
    ...
```

**Exceptions** :
- `WrongPasswordError` — mot de passe incorrect.
- `KeystoreError` — fichier introuvable, corrompu, magic invalide, ou extension incorrecte.

#### `verify(password, dbpath) -> bool`

Vérifie le mot de passe sans ouvrir le keystore. `True` = correct, `False` = incorrect. Lève `KeystoreError` si le fichier n'est pas un keystore valide du bon type.

#### `destroy(password, dbpath, passwordrequired=True) -> None`

Supprime le keystore. Lève `WrongPasswordError` si le mot de passe est faux (sauf si `passwordrequired=False`).


### Méthodes de session

Toutes les méthodes lèvent `KeystoreError` si la session est fermée.

#### `session.add(name, mygpubkey, hgpubkey, privkey) -> None`

Pour `ckeys` : `session.add(name, mygpubkey, hgpubkey, cprivkey)`.

Ajoute un canal. Tous les champs sont `str`, non vides, obligatoires.

**Exceptions** :
- `KeyNameError` — si `name` existe déjà ou est vide.
- `KeystoreError` — si une valeur est vide.
- `ArgumentTypeError` — si un argument n'est pas un `str`.

#### `session.get(name) -> dict[str, str]`

Retourne un dictionnaire avec les trois champs de l'entrée. Le dictionnaire retourné est indépendant de la session : le modifier ne change rien au keystore.

```python
entry = s.get("alice")
# keys:  {"mygpubkey": ..., "hgpubkey": ..., "privkey": ...}
# ckeys: {"mygpubkey": ..., "hgpubkey": ..., "cprivkey": ...}
```

Lève `KeyNameError` si `name` n'existe pas.

#### `session.update(name, mygpubkey=None, hgpubkey=None, privkey=None) -> None`

Pour `ckeys` : utiliser `cprivkey=` au lieu de `privkey=`.

Mise à jour partielle : seuls les champs fournis (non `None`) sont modifiés. Les champs non fournis restent inchangés. Appeler `update(name)` sans aucun champ est un no-op silencieux.

**Exceptions** :
- `KeyNameError` — si `name` n'existe pas.
- `KeystoreError` — si une valeur fournie est vide.

#### `session.exists(name) -> bool`

#### `session.__contains__(name) -> bool`

Permet `"alice" in session`.

#### `session.__len__() -> int`

#### `session.listallnames() -> list[str]`

Retourne la liste triée de tous les noms de canaux.

#### `session.search(keyword, maxlen=20) -> list[str]`

Recherche floue par nom de canal. Même algorithme que purplekeys.

#### `session.getdb() -> dict[str, dict[str, str]]`

Retourne une copie indépendante de toutes les entrées. Le dictionnaire retourné et ses sous-dictionnaires peuvent être modifiés sans affecter la session.

#### `session.rename(old_name, new_name) -> None`

Renomme un canal. Mêmes règles que purplekeys.

#### `session.delete(name) -> None`

Supprime un canal. Lève `KeyNameError` si `name` n'existe pas.

#### `session.changepwd(old_password, new_password) -> None`

Change le mot de passe maître. Lève `WrongPasswordError` si l'ancien mot de passe est faux.

#### `session.backup(target_path) -> None`

Crée une copie du keystore. L'extension de `target_path` doit correspondre au type de keystore (`.keys` pour keys, `.ckeys` pour ckeys).

#### `session.close(commit=True) -> None`

Ferme la session. `commit=True` = écriture des modifications. `commit=False` = abandon. Idempotent.


## Discrimination inter-modules

Un fichier `.keys` ne peut pas être ouvert par `ckeys.open()` et inversement. La vérification s'effectue à deux niveaux :

1. **Extension** : `keys` refuse tout ce qui n'est pas `.keys`, `ckeys` refuse tout ce qui n'est pas `.ckeys`.
2. **Magic** : même si l'extension est manuellement renommée, le magic de 16 octets dans l'en-tête du fichier identifie le type réel. Un magic incompatible lève `KeystoreError`.

De même, ni `keys` ni `ckeys` ne peuvent ouvrir un fichier `purplekeys` (extension `.purple`, magic `CRXKX_PURPLE_V1\x00`), et réciproquement.
