# keyx.purplekeys

`purplekeys` est un gestionnaire de clés chiffrées pour stocker des paires nom/clé (chaînes de caractères). Le fichier Keyx est chiffré intégralement avec le protocole PURPLE. Sans le mot de passe maître, le contenu est illisible.


## Cas d'usage

L'utilité principale de purplekeys est de stocker les clés liées au protocole PURPLE : mots de passe et passphrases générés par `crx.purple.genkeys()`, associés à un nom qui identifie le secret chiffré correspondant.

Plus largement, purplekeys peut stocker toute paire nom → valeur textuelle confidentielle : tokens API, clés de configuration, identifiants de service.


## Format de fichier

L'extension obligatoire est **`.purple`**. Le fichier binaire a la structure :

```
[16 octets : magic]  [4 octets : head_len (BE32)]  [head_ct]  [payload_ct]
```

- **Magic** : `CRXKX_PURPLE_V1\x00` (16 octets). Identifie le type de Keyx.
- **head_ct** : blob aléatoire chiffré avec PURPLE. Sert uniquement à vérifier le mot de passe sans lire le payload.
- **payload_ct** : JSON sérialisé chiffré avec PURPLE. Contient les entrées.

Toute modification du fichier (y compris un bit flip) est détectée au déchiffrement grâce au tag Poly1305. L'intégrité est garantie par construction (AEAD), sans besoin d'un HMAC séparé.

Les écritures sont **atomiques** : le fichier est écrit dans un fichier temporaire puis renommé. Une coupure de courant pendant l'écriture ne corrompt jamais le fichier existant.


## API

### Fonctions de module

#### `crx.keyx.purplekeys.createdb(password, dbpath, level="strong") -> None`

Crée un nouveau Keyx vide.

| Paramètre | Type | Description |
|---|---|---|
| `password` | `str` | Mot de passe maître. |
| `dbpath` | `str \| Path` | Chemin du fichier. Doit se terminer par `.purple`. |
| `level` | `str` | Force Argon2id. `"low"`, `"normal"`, `"strong"`, ou `"extreme"`. Défaut `"strong"`. |

Les répertoires parents sont créés automatiquement s'ils n'existent pas. Le level est embarqué dans le fichier et lu automatiquement à l'`open()`.

**Exceptions** :
- `KeyxError` — si le fichier existe déjà, si l'extension n'est pas `.purple`, ou si `level` est inconnu.
- `ArgumentTypeError` — si `password` ou `level` n'est pas un `str`.


#### `crx.keyx.purplekeys.open(password, dbpath) -> _PurpleSession`

Ouvre un Keyx existant et retourne une session.

| Paramètre | Type | Description |
|---|---|---|
| `password` | `str` | Mot de passe maître. |
| `dbpath` | `str \| Path` | Chemin du fichier `.purple`. |
| **Retour** | `_PurpleSession` | Objet session (context manager). |

**Exceptions** :
- `WrongPasswordError` — si le mot de passe est incorrect.
- `KeyxError` — si le fichier est introuvable, corrompu, a un magic invalide, ou a été créé par pycryptox < 3.0.0 (les fichiers keyx avec PURPLE v1.0 ne sont plus supportés ; voir *Migration depuis 2.x* en bas).
- `ArgumentTypeError` — si `password` n'est pas un `str`.

La session hérite du level Argon2id depuis le fichier. Utiliser `session.getlevel()` pour l'inspecter et `session.changelevel(new_level)` pour migrer vers un autre level au prochain save.

Utilisation recommandée avec `with` :

```python
with crx.keyx.purplekeys.open("master-pwd", "store.purple") as s:
    s.add("gmail", "MyP@ssw0rd")
    print(s.getkey("gmail"))
```

À la sortie du `with` :
- **Sortie normale** : les modifications sont commitées (écrites dans le fichier).
- **Exception non interceptée** : les modifications sont abandonnées (le fichier reste inchangé).


#### `crx.keyx.purplekeys.verify(password, dbpath) -> bool`

Vérifie si un mot de passe est correct pour un Keyx donné, sans l'ouvrir.

| Paramètre | Type | Description |
|---|---|---|
| `password` | `str` | Mot de passe à tester. |
| `dbpath` | `str \| Path` | Chemin du fichier `.purple`. |
| **Retour** | `bool` | `True` si le mot de passe est correct, `False` sinon. |

`verify` retourne un booléen uniquement pour la question "est-ce le bon mot de passe ?". Si le fichier est introuvable, corrompu, ou a un magic invalide, une `KeyxError` est levée (pas `False`).


#### `crx.keyx.purplekeys.destroy(password, dbpath, passwordrequired=True) -> None`

Supprime définitivement un Keyx.

| Paramètre | Type | Description |
|---|---|---|
| `password` | `str` | Mot de passe maître. |
| `dbpath` | `str \| Path` | Chemin du fichier `.purple`. |
| `passwordrequired` | `bool` | Si `False`, supprime sans vérifier le mot de passe. Défaut : `True`. |

**Exceptions** :
- `WrongPasswordError` — si le mot de passe est incorrect (et `passwordrequired=True`).
- `KeyxError` — si le fichier est introuvable.


### Méthodes de session

Une session est obtenue via `open()`. Toutes les méthodes ci-dessous lèvent `KeyxError` si la session a été fermée.

#### `session.add(name, key) -> None`

Ajoute une entrée.

- `name` : `str`, non vide, unique.
- `key` : `str`, non vide.
- Lève `KeyNameError` si `name` existe déjà ou est vide.
- Lève `ArgumentTypeError` si `name` ou `key` n'est pas un `str`.

#### `session.getkey(name) -> str`

Retourne la clé associée à `name`. Lève `KeyNameError` si `name` n'existe pas.

#### `session.exists(name) -> bool`

Retourne `True` si `name` existe dans le Keyx.

#### `session.__contains__(name) -> bool`

Permet `"gmail" in session`. Identique à `exists`.

#### `session.__len__() -> int`

Permet `len(session)`. Retourne le nombre d'entrées.

#### `session.listallnames() -> list[str]`

Retourne la liste triée de tous les noms.

#### `session.search(keyword, maxlen=20) -> list[str]`

Recherche floue par nom. Retourne jusqu'à `maxlen` résultats triés par pertinence.

La recherche utilise `rapidfuzz` avec des bonus pour les correspondances de préfixe, de sous-chaîne et de casse camelCase. Si `keyword` est vide, retourne tous les noms.

#### `session.getdb() -> dict[str, str]`

Retourne une copie de l'intégralité des entrées sous forme `{name: key, ...}`. Le dictionnaire retourné est indépendant de la session : le modifier ne change rien au Keyx.

#### `session.update(name, new_key) -> None`

Remplace la clé d'une entrée existante. Lève `KeyNameError` si `name` n'existe pas.

#### `session.rename(old_name, new_name) -> None`

Renomme une entrée. Lève `KeyNameError` si `old_name` n'existe pas, si `new_name` existe déjà, ou si `new_name` est vide. Renommer vers le même nom est un no-op silencieux.

#### `session.delete(name) -> None`

Supprime une entrée. Lève `KeyNameError` si `name` n'existe pas.

#### `session.changepwd(old_password, new_password) -> None`

Change le mot de passe maître du Keyx. Lève `WrongPasswordError` si `old_password` est incorrect.

Le changement de mot de passe prend effet immédiatement dans le fichier (pas besoin de `close` ou de sortir du `with`). Le nouveau mot de passe sera utilisé lors du prochain commit (à la sortie du `with` ou à l'appel de `close`).

#### `session.changelevel(new_level) -> None` *(nouveau en v3.0.0)*

Change le level Argon2id pour les saves suivants. `new_level` doit être `"low"`, `"normal"`, `"strong"`, ou `"extreme"`.

Le changement s'applique au prochain commit. Appeler `changelevel` avec la valeur actuelle est un no-op (la session n'est pas marquée dirty).

**Exceptions** :
- `ArgumentTypeError` — si `new_level` n'est pas un `str`.
- `KeyxError` — si `new_level` n'est pas un nom de level reconnu.

#### `session.getlevel() -> str` *(nouveau en v3.0.0)*

Retourne le level Argon2id courant de la session (défini par `open()` à la lecture du fichier, ou modifié par `changelevel`).

#### `session.backup(target_path) -> None`

Crée une copie du Keyx dans son état actuel (y compris les modifications non encore commitées). Le fichier de backup est un Keyx valide, ouvrable avec le même mot de passe et au level courant de la session. `target_path` doit se terminer par `.purple`.

#### `session.close(commit=True) -> None`

Ferme la session. Si `commit=True` (défaut), écrit les modifications dans le fichier. Si `commit=False`, abandonne les modifications.

Appeler `close()` sur une session déjà fermée est un no-op (pas d'exception).


## Migration depuis 2.x

Pycryptox 3.0.0 hard-break la compatibilité avec les fichiers `.purple` créés par les releases 2.x. Raison : le protocole PURPLE sous-jacent a été upgradé de v1.0 à v2.0 pour introduire la force Argon2id ajustable. Les fichiers 2.x contiennent des bundles PURPLE v1.0, que 3.0.0 refuse d'ouvrir avec une erreur claire :

```
KeyxError: Error with Keyx because 'unsupported keyx PURPLE version v1.0;
this build expects v2.x (created by pycryptox 3.0.0+)'
```

Un script de migration peut être écrit en utilisant un install pycryptox 2.x pour dumper les entrées, et un install 3.0.0+ pour recréer le Keyx. Il n'y a pas d'outil de migration in-place : garder un venv 2.x sous la main si tu as besoin de lire les anciens fichiers.

