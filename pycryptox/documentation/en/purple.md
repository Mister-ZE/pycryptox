# PURPLE protocol

PURPLE is the password-based encryption protocol of Pycryptox. It allows encrypting a message with a memorable secret (password, passphrase) without any key infrastructure.

PURPLE is the only protocol that does not depend on ML-KEM-512. It is fully symmetric.


## Cryptographic primitives (v1.0)

| Component | Algorithm | Parameters |
|---|---|---|
| Key derivation (KDF) | Argon2id | time_cost=2, memory_cost=64 MB, parallelism=2, hash_len=32 |
| Symmetric encryption | ChaCha20-Poly1305 (AEAD) | 256-bit key, 96-bit nonce, 128-bit tag |

Argon2id is the winner of the Password Hashing Competition (2015). It combines resistance to GPU attacks (Argon2d) and resistance to side-channel attacks (Argon2i). The chosen parameters (64 MB of memory, 2 iterations) make brute-force costly while remaining fast on a user machine (~50 ms per derivation).

ChaCha20-Poly1305 is an AEAD (Authenticated Encryption with Associated Data) scheme standardized in RFC 8439. It encrypts and authenticates simultaneously: any modification of the ciphertext is detected at decryption.


## Bundle format (v1.0)

After encryption, the raw bundle (before base64 encoding) has the structure:

```
[2 bytes: version] [16 bytes: salt] [12 bytes: nonce] [N bytes: ciphertext + Poly1305 tag]
```

The final bundle is encoded in base64url and returned as a `str`.


## API

### `crx.purple.encrypt(version, key, msg) -> str`

Encrypts a message with a password.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"` or `"1"`. |
| `key` | `str` | Password or passphrase. |
| `msg` | `str` | Plaintext message to encrypt. |
| **Return** | `str` | Encrypted bundle (base64url). |

**Exceptions**:
- `ArgumentTypeError` — if `key` or `msg` are not `str`.
- `VersionNotFoundError` — if `version` does not match any known version.
- `EncryptionError` — if the version format is invalid.

**Behavior**:

1. Generates a random 16-byte salt.
2. Derives a 256-bit key via Argon2id(password, salt).
3. Generates a random 12-byte nonce.
4. Encrypts the message with ChaCha20-Poly1305(key, nonce, message).
5. Concatenates version + salt + nonce + ciphertext.
6. Encodes in base64url.

Each call produces a different bundle for the same message and password, thanks to the random salt and nonce.


### `crx.purple.decrypt(version, key, msg) -> str`

Decrypts a PURPLE bundle.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Expected version. `"1.0"` or `"1"`. |
| `key` | `str` | Password used during encryption. |
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Plaintext message. |

**Exceptions**:
- `ArgumentTypeError` — if `key` or `msg` are not `str`.
- `DecryptionError` — if the bundle is malformed, the password is wrong, the message is corrupted, or the bundle's version does not match `version`.
- `VersionNotFoundError` — if the version extracted from the bundle is not implemented.

**Behavior**:

1. Decodes the base64url.
2. Extracts the 2 version bytes and verifies the match with `version`.
3. Extracts salt (16 bytes), nonce (12 bytes), ciphertext (the rest).
4. Derives the key via Argon2id(password, salt).
5. Decrypts with ChaCha20-Poly1305. If the authentication tag does not match (wrong password or corrupted data), raises `DecryptionError`.

A wrong password is indistinguishable from a corrupted message — both produce a `DecryptionError` with the message `"invalid key or corrupted message"`. This is intentional behavior: the attacker cannot distinguish these two cases.


### `crx.purple.genkeys(version) -> str`

Generates a random passphrase.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"` or `"1"`. |
| **Return** | `str` | Passphrase of 6 words separated by spaces. |

**Behavior**:

Selects 6 random words from the EFF wordlist (7776 words, provided by the Electronic Frontier Foundation). The randomness source is `secrets.choice`, which uses the operating system's CSPRNG (cryptographically secure pseudo-random number generator).

Passphrase entropy: 6 × log2(7776) ≈ **77.5 bits**. This is sufficient to resist online brute-force (limited by the Argon2id cost) but weak against offline brute-force on a captured file if the attacker can parallelize massively. For high-security scenarios, lengthen the passphrase manually or concatenate two passphrases.


### `crx.purple.getversion(msg) -> str`

Extracts the version of a bundle without decrypting it.

| Parameter | Type | Description |
|---|---|---|
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Version in `"M.m"` format (e.g. `"1.0"`). |

**Exceptions**:
- `ArgumentTypeError` — if `msg` is not a `str`.
- `DecryptionError` — if the bundle is too short or the base64 is invalid.


## Typical use cases

**Encryption of personal files**: passwords, private notes, journals. The password is memorized; no key needs to be saved.

**Encryption of backups**: encrypt a database export before storing it on a cloud. The passphrase is written on paper in a physical safe.

**Keystores**: PURPLE is the protocol used internally by all keyx keystores (purplekeys, bluekeys.keys, bluekeys.ckeys) to encrypt the `.purple`, `.keys`, and `.ckeys` files.


## Complete example

```python
import pycryptox as crx

# Generate a secure passphrase
passphrase = crx.purple.genkeys("1")
print(passphrase)  # → "correct horse battery staple lunar orbit" (example)

# Encrypt a message
ct = crx.purple.encrypt("1", passphrase, "Confidential company data")

# Decrypt
pt = crx.purple.decrypt("1", passphrase, ct)
print(pt)  # → "Confidential company data"

# Extract the version without decrypting
version = crx.purple.getversion(ct)
print(version)  # → "1.0"

# A wrong password raises DecryptionError
try:
    crx.purple.decrypt("1", "wrong-password", ct)
except crx.DecryptionError:
    print("Incorrect password or corrupted message")
```


## Version history

### Version 1.0 (stable)

Current version, documented in the sections above.

### Version 0.0

Initial version of the protocol. The functions return fixed responses without performing any cryptographic operation.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
