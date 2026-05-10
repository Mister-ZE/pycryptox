# Protocole PURPLE

PURPLE est le protocole de chiffrement par mot de passe de Pycryptox. Il permet de chiffrer un message avec un secret mémorisable (mot de passe, passphrase) sans aucune infrastructure de clés.

PURPLE est le seul protocole qui ne dépend pas de ML-KEM-512. Il est entièrement symétrique.


## Primitives cryptographiques (v1.0)

| Composant | Algorithme | Paramètres |
|---|---|---|
| Dérivation de clé (KDF) | Argon2id | time_cost=2, memory_cost=64 Mo, parallelism=2, hash_len=32 |
| Chiffrement symétrique | ChaCha20-Poly1305 (AEAD) | Clé 256 bits, nonce 96 bits, tag 128 bits |

Argon2id est le vainqueur du Password Hashing Competition (2015). Il combine résistance aux attaques par GPU (Argon2d) et résistance aux attaques par canaux auxiliaires (Argon2i). Les paramètres choisis (64 Mo de mémoire, 2 itérations) rendent le brute-force coûteux tout en restant rapide sur une machine utilisateur (~50 ms par dérivation).

ChaCha20-Poly1305 est un schéma AEAD (Authenticated Encryption with Associated Data) standardisé dans la RFC 8439. Il chiffre et authentifie simultanément : toute modification du ciphertext est détectée au déchiffrement.


## Format du bundle (v1.0)

Après chiffrement, le bundle brut (avant encodage base64) a la structure :

```
[2 octets : version] [16 octets : salt] [12 octets : nonce] [N octets : ciphertext + tag Poly1305]
```

Le bundle final est encodé en base64url et retourné comme `str`.


## API

### `crx.purple.encrypt(version, key, msg) -> str`

Chiffre un message avec un mot de passe.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"` ou `"1"`. |
| `key` | `str` | Mot de passe ou passphrase. |
| `msg` | `str` | Message en clair à chiffrer. |
| **Retour** | `str` | Bundle chiffré (base64url). |

**Exceptions** :
- `ArgumentTypeError` — si `key` ou `msg` ne sont pas des `str`.
- `VersionNotFoundError` — si `version` ne correspond à aucune version connue.
- `EncryptionError` — si le format de version est invalide.

**Comportement** :

1. Génère un salt aléatoire de 16 octets.
2. Dérive une clé 256 bits via Argon2id(password, salt).
3. Génère un nonce aléatoire de 12 octets.
4. Chiffre le message avec ChaCha20-Poly1305(clé, nonce, message).
5. Concatène version + salt + nonce + ciphertext.
6. Encode en base64url.

Chaque appel produit un bundle différent pour le même message et le même mot de passe, grâce au salt et au nonce aléatoires.


### `crx.purple.decrypt(version, key, msg) -> str`

Déchiffre un bundle PURPLE.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version attendue. `"1.0"` ou `"1"`. |
| `key` | `str` | Mot de passe utilisé lors du chiffrement. |
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Message en clair. |

**Exceptions** :
- `ArgumentTypeError` — si `key` ou `msg` ne sont pas des `str`.
- `DecryptionError` — si le bundle est malformé, le mot de passe est faux, le message est corrompu, ou la version du bundle ne correspond pas à `version`.
- `VersionNotFoundError` — si la version extraite du bundle n'est pas implémentée.

**Comportement** :

1. Décode le base64url.
2. Extrait les 2 octets de version et vérifie la correspondance avec `version`.
3. Extrait salt (16 octets), nonce (12 octets), ciphertext (le reste).
4. Dérive la clé via Argon2id(password, salt).
5. Déchiffre avec ChaCha20-Poly1305. Si le tag d'authentification ne correspond pas (mot de passe faux ou données corrompues), lève `DecryptionError`.

Un mot de passe incorrect ne se distingue pas d'un message corrompu — les deux produisent un `DecryptionError` avec le message `"invalid key or corrupted message"`. C'est un comportement voulu : l'attaquant ne peut pas distinguer ces deux cas.


### `crx.purple.genkeys(version) -> str`

Génère une passphrase aléatoire.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"` ou `"1"`. |
| **Retour** | `str` | Passphrase de 6 mots séparés par des espaces. |

**Comportement** :

Sélectionne 6 mots aléatoires dans la liste de mots EFF (7776 mots, fournie par l'Electronic Frontier Foundation). La source d'aléa est `secrets.choice`, qui utilise le CSPRNG (générateur de nombres pseudo-aléatoires cryptographiquement sûr) du système d'exploitation.

Entropie de la passphrase : 6 × log2(7776) ≈ **77.5 bits**. C'est suffisant pour résister au brute-force en ligne (limité par le coût Argon2id) mais faible contre un brute-force hors-ligne sur un fichier capturé si l'attaquant peut paralléliser massivement. Pour les scénarios à haute sécurité, allonger la passphrase manuellement ou concaténer deux passphrases.


### `crx.purple.getversion(msg) -> str`

Extrait la version d'un bundle sans le déchiffrer.

| Paramètre | Type | Description |
|---|---|---|
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Version au format `"M.m"` (par exemple `"1.0"`). |

**Exceptions** :
- `ArgumentTypeError` — si `msg` n'est pas un `str`.
- `DecryptionError` — si le bundle est trop court ou le base64 invalide.


## Cas d'usage typiques

**Chiffrement de fichiers personnels** : mots de passe, notes privées, journaux. Le mot de passe est mémorisé ; aucune clé ne doit être sauvegardée.

**Chiffrement de sauvegardes** : chiffrer un export de base de données avant de le stocker sur un cloud. La passphrase est notée sur papier dans un coffre physique.

**Keystores** : PURPLE est le protocole utilisé en interne par tous les keystores keyx (purplekeys, bluekeys.keys, bluekeys.ckeys) pour chiffrer les fichiers `.purple`, `.keys` et `.ckeys`.


## Exemple complet

```python
import pycryptox as crx

# Générer une passphrase sécurisée
passphrase = crx.purple.genkeys("1")
print(passphrase)  # → "correct horse battery staple lunar orbit" (exemple)

# Chiffrer un message
ct = crx.purple.encrypt("1", passphrase, "Données confidentielles de l'entreprise")

# Déchiffrer
pt = crx.purple.decrypt("1", passphrase, ct)
print(pt)  # → "Données confidentielles de l'entreprise"

# Extraire la version sans déchiffrer
version = crx.purple.getversion(ct)
print(version)  # → "1.0"

# Un mauvais mot de passe lève DecryptionError
try:
    crx.purple.decrypt("1", "mauvais-mot-de-passe", ct)
except crx.DecryptionError:
    print("Mot de passe incorrect ou message corrompu")
```


## Historique des versions

### Version 1.0 (stable)

Version actuelle, documentée dans les sections ci-dessus.

### Version 0.0

Version initiale du protocole. Les fonctions retournent des réponses fixes sans effectuer d'opération cryptographique.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
