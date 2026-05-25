# Protocole PURPLE

PURPLE est le protocole de chiffrement basé sur mot de passe de Pycryptox. Il permet de chiffrer un message avec un secret mémorisable (mot de passe, passphrase) sans aucune infrastructure de clés.

PURPLE est le seul protocole qui ne dépend pas de ML-KEM-512. Il est entièrement symétrique.

Pycryptox 3.0.0 introduit **PURPLE v2.0**, qui ajoute une force Argon2id ajustable via un paramètre `level` (`"low" | "normal" | "strong" | "extreme"`). Le level est embarqué dans le bundle ; le déchiffrement n'a donc besoin d'aucun argument supplémentaire. v1.0 reste supporté pour le déchiffrement des bundles legacy ; pour tout nouveau chiffrement, utiliser v2.0 avec au minimum `"normal"`.


## Primitives cryptographiques

| Composant | Algorithme | Notes |
|---|---|---|
| Dérivation de clé (KDF) | Argon2id | Paramètres par version de protocole et (en v2.0+) par level. |
| Chiffrement symétrique | ChaCha20-Poly1305 (AEAD) | clé 256 bits, nonce 96 bits, tag 128 bits. |

Argon2id est le gagnant de la Password Hashing Competition (2015). Il combine résistance aux attaques GPU (Argon2d) et résistance aux attaques par canaux auxiliaires (Argon2i).

ChaCha20-Poly1305 est un schéma AEAD standardisé par la RFC 8439. Il chiffre et authentifie simultanément : toute modification du ciphertext est détectée au déchiffrement.


### Paramètres Argon2id par version et level

| Version | Level | time_cost (t) | memory_cost (m) | parallelism (p) | Justification |
|---|---|---:|---:|---:|---|
| v1.0 | (aucun) | 2 | 64 MiB (65 536 KiB) | 2 | Fixe, design d'origine. Sous le plancher RFC 9106. |
| v2.0 | `low` | 2 | 64 MiB | 2 | Équivalent à v1.0 ; pour appareils peu puissants ou force de compatibilité. |
| v2.0 | `normal` | 3 | 64 MiB | 4 | Plancher RFC 9106 en config mémoire contrainte. |
| v2.0 | `strong` | 4 | 512 MiB (524 288 KiB) | 4 | Défaut. Défense mid-tier face aux attaques de masse. |
| v2.0 | `extreme` | 2 | 2 GiB (2 097 152 KiB) | 4 | Gold standard RFC 9106. Requiert 2 GiB de RAM par dérivation. |

Le memory_cost est la défense principale contre les ASIC/FPGA ; le nombre d'itérations et le parallelism sont secondaires.


## Format de bundle

### v1.0

```
[2 octets : version 1.0] [16 octets : salt] [12 octets : nonce] [N octets : ciphertext + tag Poly1305]
```

### v2.0

```
[2 octets : version 2.0] [1 octet : level (0=low,1=normal,2=strong,3=extreme)] [16 octets : salt] [12 octets : nonce] [N octets : ciphertext + tag Poly1305]
```

Le bundle final est encodé en base64url et retourné comme `str`.


## API

### `crx.purple.encrypt(version, key, msg, level="strong") -> str`

Chiffre un message avec un mot de passe.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"`, `"1"`, `"2.0"` ou `"2"`. |
| `key` | `str` | Mot de passe ou passphrase. |
| `msg` | `str` | Message en clair à chiffrer. |
| `level` | `str` | (v2.0+ uniquement) Force Argon2id. `"low"`, `"normal"`, `"strong"`, ou `"extreme"`. Défaut `"strong"`. Passer `level` à un appel v1.0 lève `TypeError`. |
| **Retour** | `str` | Bundle chiffré (base64url). |

**Exceptions** :
- `ArgumentTypeError` — si `key`, `msg`, ou `level` ne sont pas `str`.
- `EncryptionError` — si `level` n'est pas dans `{"low", "normal", "strong", "extreme"}` (v2.0+), ou si le format de version est invalide.
- `VersionNotFoundError` — si `version` ne correspond à aucune version connue.

Chaque appel produit un bundle différent pour la même entrée, grâce au salt et au nonce aléatoires.


### `crx.purple.decrypt(version, key, msg) -> str`

Déchiffre un bundle PURPLE.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version attendue. `"1.0"`, `"1"`, `"2.0"` ou `"2"`. |
| `key` | `str` | Mot de passe utilisé au chiffrement. |
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Message en clair. |

**Exceptions** :
- `ArgumentTypeError` — si `key` ou `msg` ne sont pas `str`.
- `DecryptionError` — si le bundle est mal formé, le mot de passe faux, le message corrompu, l'octet de level invalide (v2.0+), ou la version du bundle ne correspond pas à `version`.
- `VersionNotFoundError` — si la version extraite du bundle n'est pas implémentée.

Pour les bundles v2.0+, le level est lu automatiquement depuis le bundle ; pas besoin de le passer en argument.

Un mauvais mot de passe est indistinguable d'un message corrompu — les deux produisent un `DecryptionError`. C'est intentionnel : l'attaquant ne peut pas distinguer ces deux cas.


### `crx.purple.genkeys(version, level="strong") -> str`

Génère une passphrase aléatoire. En v2.0+, l'argument `level` ajuste le nombre de mots.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"`, `"1.1"`, `"1"`, `"2.0"` ou `"2"`. |
| `level` | `str` | `"low"`, `"normal"`, `"strong"` (par défaut en v2.0+) ou `"extreme"`. Ignoré pour v1.x. |
| **Retour** | `str` | Passphrase de N mots séparés par des espaces. |

En v2.0+, le nombre de mots dépend du `level` :

| Level | Mots | Entropie approximative |
|---|---|---|
| `"low"` | 6 | ~77,5 bits (défaut legacy de v1.x) |
| `"normal"` | 7 | ~90,4 bits |
| `"strong"` (défaut) | 8 | ~103,3 bits |
| `"extreme"` | 10 | ~129,1 bits |

Pour v1.0 et v1.1, la fonction retourne toujours une passphrase de 6 mots et ignore silencieusement tout argument `level`.

Les mots sont sélectionnés depuis la wordlist EFF (7776 mots) via `secrets.choice` (CSPRNG de l'OS). Chaque mot contribue `log2(7776) ≈ 12,92 bits` d'entropie. Le KDF Argon2id appliqué pendant le chiffrement multiplie le coût de toute tentative de brute-force contre la passphrase ; l'argument `level` sur `encrypt` scale ensuite ce multiplicateur encore plus.

Le défaut v2.0+ de `"strong"` (8 mots) a été choisi pour correspondre au défaut `level="strong"` de `encrypt` et fournir une baseline de sécurité haute saine. Les appelants nécessitant la compatibilité legacy avec l'output v1.x peuvent passer `level="low"` explicitement.

**Exceptions** :
- `ArgumentTypeError` — si `level` n'est pas un `str`.
- `EncryptionError` — si `level` n'est pas une des quatre valeurs acceptées.


### `crx.purple.getversion(msg) -> str`

Extrait la version d'un bundle sans le déchiffrer.

| Paramètre | Type | Description |
|---|---|---|
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Version au format `"M.m"` (ex : `"1.0"`, `"2.0"`). |

**Exceptions** :
- `ArgumentTypeError` — si `msg` n'est pas un `str`.
- `DecryptionError` — si le bundle est trop court ou le base64 invalide.


### `crx.purple.getlevel(msg) -> str` *(nouveau en v3.0.0)*

Extrait le level de chiffrement d'un bundle v2.0+ sans le déchiffrer.

| Paramètre | Type | Description |
|---|---|---|
| `msg` | `str` | Bundle v2.0+ chiffré (base64url). |
| **Retour** | `str` | `"low"`, `"normal"`, `"strong"`, ou `"extreme"`. |

**Exceptions** :
- `ArgumentTypeError` — si `msg` n'est pas un `str`.
- `DecryptionError` — si le bundle est mal formé, a un octet de level invalide, ou est sous v2.0 (où le level n'existe pas).


### `crx.purple.update_bundle(old_to_new, key, old_msg, level="strong", downgrade=False) -> str` *(nouveau en v3.0.0)*

Re-chiffre un bundle PURPLE d'une version de protocole à une autre. Wrapper de commodité autour de `decrypt(old_version, key, old_msg)` suivi de `encrypt(new_version, key, plaintext, level=level)`.

| Paramètre | Type | Description |
|---|---|---|
| `old_to_new` | `str` | Spec de la forme `"A.a to B.b"` où chaque côté est une version exacte (`"1.0"`) ou un specifier major-only (`"1"`, qui résout au dernier minor). Exemples : `"1.0 to 2"`, `"1 to 2.0"`, `"1 to 2"`. |
| `key` | `str` | Mot de passe utilisé pour déchiffrer l'ancien bundle et chiffrer le nouveau. |
| `old_msg` | `str` | Le bundle à re-chiffrer. |
| `level` | `str` | Level du nouveau bundle quand la cible est v2.0+. Ignoré pour les cibles v1.0. Défaut `"strong"`. |
| `downgrade` | `bool` | Si `False` (défaut), refuse de migrer vers une version plus ancienne. Si `True`, autorise. |
| **Retour** | `str` | Le bundle re-chiffré. Si les versions source et cible résolues sont égales, retourne `old_msg` inchangé (aucun decrypt/encrypt n'est effectué). |

**Exceptions** :
- `ArgumentTypeError` — si un argument a un mauvais type.
- `VersionNotFoundError` — si la spec est mal formée (ex : `"garbage"`, `"1->2"`) ou si l'une des versions résolues n'est pas implémentée.
- `DowngradeError` — si `downgrade=False` (défaut) et que la cible est plus ancienne que la source.
- `DecryptionError` — si `old_msg` ne déchiffre pas sous `key`.
- `EncryptionError` — si `level` est invalide pour la cible.

**Exemples** :

```python
import pycryptox as crx

# Migrer un bundle v1.0 vers v2.0 au level par défaut
old_bundle = crx.purple.encrypt("1", "pwd", "data")
new_bundle = crx.purple.update_bundle("1 to 2", "pwd", old_bundle)
assert crx.purple.getlevel(new_bundle) == "strong"

# Migrer et choisir un level plus fort
hardened = crx.purple.update_bundle("1 to 2", "pwd", old_bundle, level="extreme")

# Même version cible -> no-op, mêmes octets retournés
ct = crx.purple.encrypt("2", "pwd", "stable")
assert crx.purple.update_bundle("2 to 2", "pwd", ct) == ct

# Downgrade refusé par défaut
try:
    crx.purple.update_bundle("2 to 1", "pwd", ct)
except crx.DowngradeError:
    pass

# Forcer un downgrade si on le veut vraiment
forced = crx.purple.update_bundle("2 to 1", "pwd", ct, downgrade=True)
```


## Cas d'usage typiques

**Chiffrement de fichiers personnels** : mots de passe, notes privées, journaux. Le mot de passe est mémorisé ; aucune clé à sauvegarder.

**Chiffrement de sauvegardes** : chiffrer un export de base de données avant de le stocker sur un cloud. La passphrase est écrite sur papier dans un coffre physique.

**Keyx** : PURPLE v2.0 est le protocole utilisé en interne par tous les Keyx (purplekeys, bluekeys.keys, bluekeys.ckeys) pour chiffrer les fichiers `.purple`, `.keys`, et `.ckeys`. Pycryptox 3.0.0 hard-break la compatibilité avec les Keyx 2.x (qui contenaient du PURPLE v1.0) ; voir la doc keyx pour le chemin de migration.


## Exemple complet

```python
import pycryptox as crx

# Générer une passphrase sécurisée
passphrase = crx.purple.genkeys("2")
print(passphrase)  # → "correct horse battery staple lunar orbit" (exemple)

# Chiffrer en v2.0 (level par défaut "strong")
ct = crx.purple.encrypt("2", passphrase, "Données confidentielles d'entreprise")

# Inspecter le bundle
print(crx.purple.getversion(ct))  # → "2.0"
print(crx.purple.getlevel(ct))    # → "strong"

# Déchiffrer
pt = crx.purple.decrypt("2", passphrase, ct)
print(pt)  # → "Données confidentielles d'entreprise"

# Un mauvais mot de passe lève DecryptionError
try:
    crx.purple.decrypt("2", "wrong-password", ct)
except crx.DecryptionError:
    print("Mot de passe incorrect ou message corrompu")
```


## Historique des versions

### Version 2.0 (stable, depuis 3.0.0)

Force Argon2id ajustable via le paramètre `level`. Le format de bundle ajoute un octet de level après l'en-tête de version. Le level par défaut est `"strong"` (t=4, m=512 MiB, p=4) — substantiellement au-dessus du plancher RFC 9106 et calibré pour la défense face aux attaques de masse.

### Version 1.1 (depuis 3.0.0)

Même format de bundle et mêmes paramètres Argon2id que v1.0 (t=2, m=64 MiB, p=2), avec gestion d'exceptions interne resserrée (catches spécifiques au lieu d'un `except Exception` large). Fonctionnellement indistinguable de v1.0 du point de vue de l'appelant — produit et consomme du plaintext byte-compatible sous le même mot de passe. Seul l'octet de version dans l'en-tête du bundle diffère (`1.1` au lieu de `1.0`). Sous le plancher RFC 9106 ; préférer v2.0 pour tout nouveau chiffrement.

### Version 1.0 (legacy, recommandé uniquement pour déchiffrement)

Paramètres Argon2id fixes (t=2, m=64 MiB, p=2). Sous les recommandations RFC 9106. Utiliser `update_bundle("1 to 2", ...)` pour migrer les bundles v1.0 existants vers v2.0.

### Version 0.0

Version initiale du protocole. Les fonctions retournent des réponses fixes sans effectuer d'opération cryptographique.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
