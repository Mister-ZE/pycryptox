# keyx.bluekeys

`bluekeys` est un gestionnaire de clés chiffrées pour stocker les canaux de communication BLUE. Il se compose de deux sous-modules :

- **`crx.keyx.bluekeys.keys`** — stocke les canaux BLUE standard (extension `.keys`).
- **`crx.keyx.bluekeys.ckeys`** — stocke les canaux BLUE critiques/déniables (extension `.ckeys`).

Les deux sous-modules ont la même API à trois détails près : l'extension de fichier, le magic du fichier, et le nom du champ de clé privée (`privkey` vs `cprivkey`).


## Pourquoi deux sous-modules séparés

La séparation entre `keys` et `ckeys` sert la **déniabilité plausible** du protocole BLUE.

Dans un scénario de déniabilité, l'utilisateur possède deux clés privées pour chaque canal : une clé de leurre et une clé réelle. La clé de leurre est stockée dans le Keyx `keys`, accessible sur la machine de l'utilisateur. Pourquoi stocker le leurre dans le Keyx principal ? Parce que c'est le Keyx que l'adversaire forcera l'utilisateur à ouvrir en cas de coercition. L'adversaire y trouvera la clé de leurre, déchiffrera le message leurre, et obtiendra un résultat crédible — sans savoir qu'une autre clé existe ailleurs.

La clé réelle est stockée dans le Keyx `ckeys`, sur un support physiquement séparé (clé USB, disque externe, etc.) qui n'est pas présent au moment de la coercition. L'adversaire ne peut pas forcer l'ouverture d'un fichier dont il ignore l'existence et qui est physiquement absent.

La bibliothèque fournit les deux stores. La gestion du support physique (USB, séparation des fichiers) est de la responsabilité de l'utilisateur ou du logiciel CLI.


## Schéma des entrées

Chaque entrée dans un Keyx bluekeys représente un **canal de correspondance** (pas une personne). L'utilisateur choisit librement le nom de chaque canal.

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

#### `createdb(password, dbpath, level="strong") -> None`

Crée un nouveau Keyx vide.

```python
crx.keyx.bluekeys.keys.createdb("master-pwd", "channels.keys")                     # level par défaut = "strong"
crx.keyx.bluekeys.ckeys.createdb("master-pwd", "/usb/critical.ckeys", level="extreme")
```

| Paramètre | Type | Description |
|---|---|---|
| `password` | `str` | Mot de passe maître. |
| `dbpath` | `str \| Path` | Chemin du fichier. Doit se terminer par `.keys` (pour `keys`) ou `.ckeys` (pour `ckeys`). |
| `level` | `str` | Force Argon2id. `"low"`, `"normal"`, `"strong"`, ou `"extreme"`. Défaut `"strong"`. |

Le level est embarqué dans le fichier et lu automatiquement à l'`open()`.

**Exceptions** :
- `KeyxError` — si le fichier existe déjà, l'extension est incorrecte, ou `level` est inconnu.
- `ArgumentTypeError` — si `password` ou `level` n'est pas un `str`.

#### `open(password, dbpath) -> _KeysSession / _CKeysSession`

Ouvre un Keyx existant. Retourne une session (context manager).

```python
with crx.keyx.bluekeys.keys.open("master-pwd", "channels.keys") as s:
    ...
```

La session hérite du level Argon2id depuis le fichier. Utiliser `session.getlevel()` pour l'inspecter et `session.changelevel(new_level)` pour migrer vers un autre level au prochain save.

**Exceptions** :
- `WrongPasswordError` — mot de passe incorrect.
- `KeyxError` — fichier introuvable, corrompu, magic invalide, extension incorrecte, ou créé par pycryptox < 3.0.0 (les fichiers keyx avec PURPLE v1.0 ne sont plus supportés ; voir *Migration depuis 2.x* en bas).

#### `verify(password, dbpath) -> bool`

Vérifie le mot de passe sans ouvrir le Keyx. `True` = correct, `False` = incorrect. Lève `KeyxError` si le fichier n'est pas un Keyx valide du bon type ou s'il a été créé par pycryptox < 3.0.0.

#### `destroy(password, dbpath, passwordrequired=True) -> None`

Supprime le Keyx. Lève `WrongPasswordError` si le mot de passe est faux (sauf si `passwordrequired=False`). Lève `KeyxError` si le fichier a été créé par pycryptox < 3.0.0 et `passwordrequired=True`.


### Méthodes de session

Toutes les méthodes lèvent `KeyxError` si la session est fermée.

#### `session.add(name, mygpubkey, hgpubkey, privkey) -> None`

Pour `ckeys` : `session.add(name, mygpubkey, hgpubkey, cprivkey)`.

Ajoute un canal. Tous les champs sont `str`, non vides, obligatoires.

**Exceptions** :
- `KeyNameError` — si `name` existe déjà ou est vide.
- `KeyxError` — si une valeur est vide.
- `ArgumentTypeError` — si un argument n'est pas un `str`.

#### `session.get(name) -> dict[str, str]`

Retourne un dictionnaire avec les trois champs de l'entrée. Le dictionnaire retourné est indépendant de la session : le modifier ne change rien au Keyx.

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
- `KeyxError` — si une valeur fournie est vide.

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

#### `session.changelevel(new_level) -> None` *(nouveau en v3.0.0)*

Change le level Argon2id pour les saves suivants. `new_level` doit être `"low"`, `"normal"`, `"strong"`, ou `"extreme"`.

Le changement s'applique au prochain commit. Appeler avec le level courant est un no-op.

**Exceptions** :
- `ArgumentTypeError` — si `new_level` n'est pas un `str`.
- `KeyxError` — si `new_level` n'est pas un nom de level reconnu.

#### `session.getlevel() -> str` *(nouveau en v3.0.0)*

Retourne le level Argon2id courant de la session.

#### `session.backup(target_path) -> None`

Crée une copie du Keyx au level courant de la session. L'extension de `target_path` doit correspondre au type de Keyx (`.keys` pour keys, `.ckeys` pour ckeys).

#### `session.close(commit=True) -> None`

Ferme la session. `commit=True` = écriture des modifications. `commit=False` = abandon. Idempotent.


## Migration depuis 2.x

Pycryptox 3.0.0 hard-break la compatibilité avec les fichiers `.keys` et `.ckeys` créés par les releases 2.x (qui contenaient des bundles PURPLE v1.0). Ouvrir un tel fichier en 3.0.0+ lève une erreur claire :

```
KeyxError: Error with Keyx because 'unsupported keyx PURPLE version v1.0;
this build expects v2.x (created by pycryptox 3.0.0+)'
```

Il n'y a pas d'outil de migration in-place. Utiliser un venv 2.x pour dumper les entrées, puis recréer le Keyx en 3.0.0+ au level de ton choix.


## Discrimination inter-modules

Un fichier `.keys` ne peut pas être ouvert par `ckeys.open()` et inversement. La vérification s'effectue à deux niveaux :

1. **Extension** : `keys` refuse tout ce qui n'est pas `.keys`, `ckeys` refuse tout ce qui n'est pas `.ckeys`.
2. **Magic** : même si l'extension est manuellement renommée, le magic de 16 octets dans l'en-tête du fichier identifie le type réel. Un magic incompatible lève `KeyxError`.

De même, ni `keys` ni `ckeys` ne peuvent ouvrir un fichier `purplekeys` (extension `.purple`, magic `CRXKX_PURPLE_V1\x00`), et réciproquement.
