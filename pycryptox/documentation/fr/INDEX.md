# Documentation Pycryptox

Pycryptox est une bibliothèque Python de cryptographie post-quantique. Elle fournit quatre protocoles de chiffrement (PURPLE, BLUE, RED, YELLOW), un protocole interne (BLACK), et un système de gestion de clés chiffrées (keyx).

Chaque protocole répond à un besoin précis. PURPLE chiffre avec un mot de passe. BLUE chiffre avec des clés asymétriques et offre la déniabilité plausible. RED chiffre avec un seuil de confiance (t parmi n personnes). YELLOW est réservé à la stéganographie (non implémenté dans cette version).

Toutes les opérations asymétriques utilisent ML-KEM-512 (FIPS 203), le standard NIST de cryptographie post-quantique, via la bibliothèque liboqs. Le chiffrement symétrique repose sur ChaCha20-Poly1305 (AEAD). La dérivation de clé par mot de passe utilise Argon2id.


## Table des matières

1. [Installation](installation.md) — Prérequis et installation.

2. [Architecture](architecture.md) — Arborescence des fichiers, conventions, système de versioning des protocoles.

3. **Protocoles** :
   - [PURPLE](purple.md) — Chiffrement par mot de passe (Argon2id + ChaCha20-Poly1305).
   - [BLUE](blue.md) — Chiffrement asymétrique déniable (ML-KEM-512 + ChaCha20-Poly1305, double canal x/y).
   - [RED](red.md) — Chiffrement à seuil (Shamir + ML-KEM-512, t parmi n).
   - [YELLOW](yellow.md) — Stéganographie (placeholder, non implémenté).
   - [BLACK](black.md) — Protocole interne (ML-KEM-512 + ChaCha20-Poly1305). Non accessible directement.

4. **Gestion de clés (keyx)** :
   - [purplekeys](purplekeys.md) — Stockage chiffré de paires nom/clé.
   - [bluekeys](bluekeys.md) — Stockage chiffré de canaux BLUE (keys et ckeys).

5. [Exceptions](exceptions.md) — Toutes les exceptions levées par Pycryptox.

6. [Exemples](examples.md) — Exemples de code pour chaque fonctionnalité.

7. [Sécurité](securite.md) — Modèle de menace, limites connues, recommandations.


## Exemple rapide

```python
import pycryptox as crx

# PURPLE : chiffrer avec un mot de passe
ct = crx.purple.encrypt("1", "mon-mot-de-passe", "message secret")
pt = crx.purple.decrypt("1", "mon-mot-de-passe", ct)

# BLUE : chiffrer avec déniabilité
keys = crx.blue.genkeys("1")
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="vrai message", ymsg="leurre")
crx.blue.decrypt("1", keys["xprivkey"], bundle)  # → "vrai message"
crx.blue.decrypt("1", keys["yprivkey"], bundle)  # → "leurre"

# RED : chiffrer avec seuil 2-sur-3
keys = crx.red.genkeys("1", 2, 3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "secret partagé")
crx.red.decrypt("1", keys["privkeys"][:2], bundle)  # → "secret partagé"

# keyx : stocker des clés de manière chiffrée
crx.keyx.purplekeys.createdb("master-pwd", "secrets.purple")
with crx.keyx.purplekeys.open("master-pwd", "secrets.purple") as s:
    s.add("serveur-prod", "S3cur3T0ken!")
    print(s.getkey("serveur-prod"))  # → "S3cur3T0ken!"

# keyx : stocker un canal BLUE
crx.keyx.bluekeys.keys.createdb("master-pwd", "channels.keys")
with crx.keyx.bluekeys.keys.open("master-pwd", "channels.keys") as s:
    blue_keys = crx.blue.genkeys("1")
    s.add("alice", blue_keys["gpubkey"], alice_gpubkey, blue_keys["xprivkey"])
```


## Conventions de cette documentation

- Toutes les données en transit (bundles, clés, ciphertexts) sont encodées en **base64url** (RFC 4648 §5) et manipulées comme des `str` Python.
- Le paramètre `version` est toujours le premier argument de `encrypt`, `decrypt` et `genkeys`. Il accepte une version exacte (`"1.0"`) ou un spécificateur de version majeure (`"1"`, qui résout vers la dernière mineure disponible).
- Les exemples de code utilisent `import pycryptox as crx` par convention.
