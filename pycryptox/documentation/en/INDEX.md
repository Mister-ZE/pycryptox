# Pycryptox Documentation

Pycryptox is a Python post-quantum cryptography library. It provides four encryption protocols (PURPLE, BLUE, RED, YELLOW), an internal protocol (BLACK), and an encrypted key management system (keyx).

Each protocol addresses a specific need. PURPLE encrypts with a password. BLUE encrypts with asymmetric keys and offers plausible deniability. RED encrypts with a trust threshold (t out of n people). YELLOW is reserved for steganography (not implemented in this version).

All asymmetric operations use ML-KEM-512 (FIPS 203), the NIST standard for post-quantum cryptography, via the liboqs library. Symmetric encryption relies on ChaCha20-Poly1305 (AEAD). Password-based key derivation uses Argon2id.


## Table of contents

1. [Installation](installation.md) — Prerequisites and installation.

2. [Architecture](architecture.md) — File tree, conventions, protocol versioning system.

3. **Protocols**:
   - [PURPLE](purple.md) — Password-based encryption (Argon2id + ChaCha20-Poly1305).
   - [BLUE](blue.md) — Deniable asymmetric encryption (ML-KEM-512 + ChaCha20-Poly1305, dual x/y channel).
   - [RED](red.md) — Threshold encryption (Shamir + ML-KEM-512, t out of n).
   - [YELLOW](yellow.md) — Steganography (placeholder, not implemented).
   - [BLACK](black.md) — Internal protocol (ML-KEM-512 + ChaCha20-Poly1305). Not directly accessible.

4. **Key management (keyx)**:
   - [purplekeys](purplekeys.md) — Encrypted storage of name/key pairs.
   - [bluekeys](bluekeys.md) — Encrypted storage of BLUE channels (keys and ckeys).

5. [Exceptions](exceptions.md) — All exceptions raised by Pycryptox.

6. [Examples](examples.md) — Code examples for every feature.

7. [Security](security.md) — Threat model, known limits, recommendations.


## Quick example

```python
import pycryptox as crx

# PURPLE: encrypt with a password
ct = crx.purple.encrypt("1", "my-password", "secret message")
pt = crx.purple.decrypt("1", "my-password", ct)

# BLUE: encrypt with deniability
keys = crx.blue.genkeys("1")
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="real message", ymsg="decoy")
crx.blue.decrypt("1", keys["xprivkey"], bundle)  # → "real message"
crx.blue.decrypt("1", keys["yprivkey"], bundle)  # → "decoy"

# RED: encrypt with a 2-of-3 threshold
keys = crx.red.genkeys("1", 2, 3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "shared secret")
crx.red.decrypt("1", keys["privkeys"][:2], bundle)  # → "shared secret"

# keyx: store keys in encrypted form
crx.keyx.purplekeys.createdb("master-pwd", "secrets.purple")
with crx.keyx.purplekeys.open("master-pwd", "secrets.purple") as s:
    s.add("prod-server", "S3cur3T0ken!")
    print(s.getkey("prod-server"))  # → "S3cur3T0ken!"

# keyx: store a BLUE channel
crx.keyx.bluekeys.keys.createdb("master-pwd", "channels.keys")
with crx.keyx.bluekeys.keys.open("master-pwd", "channels.keys") as s:
    blue_keys = crx.blue.genkeys("1")
    s.add("alice", blue_keys["gpubkey"], alice_gpubkey, blue_keys["xprivkey"])
```


## Conventions used in this documentation

- All in-transit data (bundles, keys, ciphertexts) is encoded in **base64url** (RFC 4648 §5) and handled as Python `str`.
- The `version` parameter is always the first argument of `encrypt`, `decrypt`, and `genkeys`. It accepts an exact version (`"1.0"`) or a major-version specifier (`"1"`, which resolves to the latest available minor).
- Code examples use `import pycryptox as crx` by convention.
