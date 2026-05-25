# PURPLE protocol

PURPLE is the password-based encryption protocol of Pycryptox. It allows encrypting a message with a memorable secret (password, passphrase) without any key infrastructure.

PURPLE is the only protocol that does not depend on ML-KEM-512. It is fully symmetric.

Pycryptox 3.0.0 introduces **PURPLE v2.0**, which adds an adjustable Argon2id strength via a `level` parameter (`"low" | "normal" | "strong" | "extreme"`). The level is embedded in the bundle, so decryption requires no extra argument. v1.0 remains supported for decrypting legacy bundles; for new encryption, use v2.0 with at least `"normal"`.


## Cryptographic primitives

| Component | Algorithm | Notes |
|---|---|---|
| Key derivation (KDF) | Argon2id | Parameters per protocol version and (in v2.0+) per level. |
| Symmetric encryption | ChaCha20-Poly1305 (AEAD) | 256-bit key, 96-bit nonce, 128-bit tag. |

Argon2id is the winner of the Password Hashing Competition (2015). It combines resistance to GPU attacks (Argon2d) and resistance to side-channel attacks (Argon2i).

ChaCha20-Poly1305 is an AEAD scheme standardized in RFC 8439. It encrypts and authenticates simultaneously: any modification of the ciphertext is detected at decryption.


### Argon2id parameters by version and level

| Version | Level | time_cost (t) | memory_cost (m) | parallelism (p) | Rationale |
|---|---|---:|---:|---:|---|
| v1.0 | (none) | 2 | 64 MiB (65 536 KiB) | 2 | Fixed, original design. Below RFC 9106 floor. |
| v2.0 | `low` | 2 | 64 MiB | 2 | Equivalent to v1.0; for low-power devices or compatibility-grade strength. |
| v2.0 | `normal` | 3 | 64 MiB | 4 | RFC 9106 memory-constrained floor. |
| v2.0 | `strong` | 4 | 512 MiB (524 288 KiB) | 4 | Default. Mid-tier mass-attack defence. |
| v2.0 | `extreme` | 2 | 2 GiB (2 097 152 KiB) | 4 | RFC 9106 gold standard. Requires 2 GiB RAM per derivation. |

Memory cost is the primary defence against ASIC/FPGA attacks; iteration count and parallelism are secondary.


## Bundle format

### v1.0

```
[2 bytes: version 1.0] [16 bytes: salt] [12 bytes: nonce] [N bytes: ciphertext + Poly1305 tag]
```

### v2.0

```
[2 bytes: version 2.0] [1 byte: level (0=low,1=normal,2=strong,3=extreme)] [16 bytes: salt] [12 bytes: nonce] [N bytes: ciphertext + Poly1305 tag]
```

The final bundle is encoded in base64url and returned as a `str`.


## API

### `crx.purple.encrypt(version, key, msg, level="strong") -> str`

Encrypts a message with a password.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"`, `"1"`, `"2.0"`, or `"2"`. |
| `key` | `str` | Password or passphrase. |
| `msg` | `str` | Plaintext message to encrypt. |
| `level` | `str` | (v2.0+ only) Argon2id strength. One of `"low"`, `"normal"`, `"strong"`, `"extreme"`. Default `"strong"`. Passing `level` to a v1.0 call raises `TypeError`. |
| **Return** | `str` | Encrypted bundle (base64url). |

**Exceptions**:
- `ArgumentTypeError` — if `key`, `msg`, or `level` are not `str`.
- `EncryptionError` — if `level` is not in `{"low", "normal", "strong", "extreme"}` (v2.0+), or if the version format is invalid.
- `VersionNotFoundError` — if `version` does not match any known version.

Each call produces a different bundle for the same input, thanks to the random salt and nonce.


### `crx.purple.decrypt(version, key, msg) -> str`

Decrypts a PURPLE bundle.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Expected version. `"1.0"`, `"1"`, `"2.0"`, or `"2"`. |
| `key` | `str` | Password used during encryption. |
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Plaintext message. |

**Exceptions**:
- `ArgumentTypeError` — if `key` or `msg` are not `str`.
- `DecryptionError` — if the bundle is malformed, the password is wrong, the message is corrupted, the level byte is invalid (v2.0+), or the bundle's version does not match `version`.
- `VersionNotFoundError` — if the version extracted from the bundle is not implemented.

For v2.0+ bundles, the level is read from the bundle automatically; no `level` argument is needed at decryption.

A wrong password is indistinguishable from a corrupted message — both produce a `DecryptionError`. This is intentional: the attacker cannot distinguish these two cases.


### `crx.purple.genkeys(version, level="strong") -> str`

Generates a random passphrase. In v2.0+, the `level` argument scales the number of words.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"`, `"1.1"`, `"1"`, `"2.0"`, or `"2"`. |
| `level` | `str` | `"low"`, `"normal"`, `"strong"` (default in v2.0+), or `"extreme"`. Ignored for v1.x. |
| **Return** | `str` | Passphrase of N words separated by spaces. |

In v2.0+, the number of words depends on `level`:

| Level | Words | Approximate entropy |
|---|---|---|
| `"low"` | 6 | ~77.5 bits (legacy default of v1.x) |
| `"normal"` | 7 | ~90.4 bits |
| `"strong"` (default) | 8 | ~103.3 bits |
| `"extreme"` | 10 | ~129.1 bits |

For v1.0 and v1.1, the function always returns a 6-word passphrase and silently ignores any `level` argument.

Words are selected from the EFF wordlist (7776 words) using `secrets.choice` (OS CSPRNG). Each word contributes `log2(7776) ≈ 12.92 bits` of entropy. The Argon2id KDF applied during encryption multiplies the cost of any brute-force attempt against the passphrase; the `level` argument on `encrypt` then scales that multiplier further.

The v2.0+ default of `"strong"` (8 words) was chosen to match `encrypt`'s default `level="strong"` and to provide a sane high-security baseline. Callers who need legacy compatibility with v1.x output can pass `level="low"` explicitly.

**Exceptions**:
- `ArgumentTypeError` — if `level` is not a `str`.
- `EncryptionError` — if `level` is not one of the four accepted values.


### `crx.purple.getversion(msg) -> str`

Extracts the version of a bundle without decrypting it.

| Parameter | Type | Description |
|---|---|---|
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Version in `"M.m"` format (e.g. `"1.0"`, `"2.0"`). |

**Exceptions**:
- `ArgumentTypeError` — if `msg` is not a `str`.
- `DecryptionError` — if the bundle is too short or the base64 is invalid.


### `crx.purple.getlevel(msg) -> str` *(new in v3.0.0)*

Extracts the encryption level of a v2.0+ bundle without decrypting it.

| Parameter | Type | Description |
|---|---|---|
| `msg` | `str` | Encrypted v2.0+ bundle (base64url). |
| **Return** | `str` | One of `"low"`, `"normal"`, `"strong"`, `"extreme"`. |

**Exceptions**:
- `ArgumentTypeError` — if `msg` is not a `str`.
- `DecryptionError` — if the bundle is malformed, has a bad level byte, or is below v2.0 (where the level concept does not apply).


### `crx.purple.update_bundle(old_to_new, key, old_msg, level="strong", downgrade=False) -> str` *(new in v3.0.0)*

Re-encrypt a PURPLE bundle from one protocol version to another. Convenience wrapper around `decrypt(old_version, key, old_msg)` followed by `encrypt(new_version, key, plaintext, level=level)`.

| Parameter | Type | Description |
|---|---|---|
| `old_to_new` | `str` | Spec of the form `"A.a to B.b"` where each side is an exact version (`"1.0"`) or a major-only specifier (`"1"`, resolving to the latest minor). Examples: `"1.0 to 2"`, `"1 to 2.0"`, `"1 to 2"`. |
| `key` | `str` | Password used to decrypt the old bundle and encrypt the new one. |
| `old_msg` | `str` | The bundle to re-encrypt. |
| `level` | `str` | Level for the new bundle when the target is v2.0+. Ignored for v1.0 targets. Default `"strong"`. |
| `downgrade` | `bool` | If `False` (default), refuses to migrate to an older version. If `True`, allows it. |
| **Return** | `str` | The re-encrypted bundle. If the resolved source and target versions are equal, returns `old_msg` unchanged (no decrypt/encrypt is performed). |

**Exceptions**:
- `ArgumentTypeError` — if any argument has a wrong type.
- `VersionNotFoundError` — if the spec is malformed (e.g. `"garbage"`, `"1->2"`) or if either resolved version is not implemented.
- `DowngradeError` — if `downgrade=False` (default) and the target version is older than the source.
- `DecryptionError` — if `old_msg` does not decrypt under `key`.
- `EncryptionError` — if `level` is invalid for the target.

**Examples**:

```python
import pycryptox as crx

# Upgrade a v1.0 bundle to v2.0 at default strength
old_bundle = crx.purple.encrypt("1", "pwd", "data")
new_bundle = crx.purple.update_bundle("1 to 2", "pwd", old_bundle)
assert crx.purple.getlevel(new_bundle) == "strong"

# Upgrade and pick a stronger level
hardened = crx.purple.update_bundle("1 to 2", "pwd", old_bundle, level="extreme")

# Same target version -> no-op, exact same bytes returned
ct = crx.purple.encrypt("2", "pwd", "stable")
assert crx.purple.update_bundle("2 to 2", "pwd", ct) == ct

# Downgrade refused by default
try:
    crx.purple.update_bundle("2 to 1", "pwd", ct)
except crx.DowngradeError:
    pass

# Force a downgrade if you really mean it
forced = crx.purple.update_bundle("2 to 1", "pwd", ct, downgrade=True)
```


## Typical use cases

**Encryption of personal files**: passwords, private notes, journals. The password is memorized; no key needs to be saved.

**Encryption of backups**: encrypt a database export before storing it on a cloud. The passphrase is written on paper in a physical safe.

**Keyxs**: PURPLE v2.0 is the protocol used internally by all keyx Keyxs (purplekeys, bluekeys.keys, bluekeys.ckeys) to encrypt the `.purple`, `.keys`, and `.ckeys` files. Pycryptox 3.0.0 hard-breaks compatibility with 2.x Keyx files (which embedded PURPLE v1.0); see `keyx` docs for the migration path.


## Complete example

```python
import pycryptox as crx

# Generate a secure passphrase
passphrase = crx.purple.genkeys("2")
print(passphrase)  # → "correct horse battery staple lunar orbit" (example)

# Encrypt at v2.0 (default level "strong")
ct = crx.purple.encrypt("2", passphrase, "Confidential company data")

# Inspect the bundle
print(crx.purple.getversion(ct))  # → "2.0"
print(crx.purple.getlevel(ct))    # → "strong"

# Decrypt
pt = crx.purple.decrypt("2", passphrase, ct)
print(pt)  # → "Confidential company data"

# A wrong password raises DecryptionError
try:
    crx.purple.decrypt("2", "wrong-password", ct)
except crx.DecryptionError:
    print("Incorrect password or corrupted message")
```


## Version history

### Version 2.0 (stable, since 3.0.0)

Adjustable Argon2id strength via `level` parameter. Bundle format adds a level byte after the version header. Default level is `"strong"` (t=4, m=512 MiB, p=4) — substantially above RFC 9106 floor and tuned for mass-attack defence.

### Version 1.1 (since 3.0.0)

Same wire format and Argon2id parameters as v1.0 (t=2, m=64 MiB, p=2), with tightened internal exception handling (specific catches instead of a broad `except Exception`). Functionally indistinguishable from v1.0 at the caller level — produces and consumes byte-compatible plaintext under the same password. The version byte in the bundle header differs (`1.1` instead of `1.0`). Below RFC 9106 floor; prefer v2.0 for any new encryption.

### Version 1.0 (legacy, decryption only recommended)

Fixed Argon2id parameters (t=2, m=64 MiB, p=2). Below RFC 9106 recommendations. Use `update_bundle("1 to 2", ...)` to migrate existing v1.0 bundles to v2.0.

### Version 0.0

Initial version of the protocol. The functions return fixed responses without performing any cryptographic operation.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
