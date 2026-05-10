# RED protocol

RED is the threshold encryption protocol of Pycryptox. It allows encrypting a message such that decryption requires the cooperation of at least `t` people out of `n`. No single person can access the message alone.

RED is designed for shared secrets: wallet recovery key, vault access code, password of a critical account.


## Concept

RED combines two primitives:

1. **ML-KEM-512 + ChaCha20-Poly1305 (via BLACK)** — for message encryption.
2. **Shamir secret sharing in GF(256)** — to split the ML-KEM-512 private key into `n` shares of which `t` are sufficient to reconstruct it.

Shamir secret sharing is a threshold scheme based on polynomial interpolation, invented by Adi Shamir in 1979. For a threshold `t`, a random polynomial of degree `t-1` is generated, whose constant term is the secret. Each share is a point on this polynomial. With `t` points, the polynomial is uniquely determined by Lagrange interpolation, and the constant term (the secret) is recoverable. With `t-1` points or fewer, the secret remains informationally undetermined: all possible values of the secret are equally likely.

The Pycryptox implementation operates in **GF(256)**, the finite field (algebraic structure) of 256 elements. Each byte of the ML-KEM-512 private key (1632 bytes) is processed independently. The polynomial's random coefficients are generated via `secrets.randbelow(256)` (system CSPRNG).

The message is encrypted only once with an ordinary ML-KEM-512 public key via BLACK. The corresponding private key is then split into `n` shares with a threshold `t`. To decrypt, it suffices to gather `t` shares (any of the `n`) to reconstruct the private key and decrypt the bundle.

On the wire, a RED bundle is identical to a BLACK bundle. The threshold property is entirely contained in the share format — it is not visible in the ciphertext.


## "Trusted dealer" model

Version 1.0 of RED uses a "trusted dealer" model. This means that the entity that calls `genkeys()` sees the complete ML-KEM-512 private key before splitting it into shares, and the entity that calls `encrypt()` sees the plaintext message. These two entities must be trusted and destroy their copies after use.

Pycryptox performs symbolic destruction (overwrite with zeros + `gc.collect()`), but in Python, `bytes` objects are immutable and memory zeroization is not guaranteed by the garbage collector. For a cryptographic guarantee of destruction, a hardware module would be required.


## API

### `crx.red.genkeys(version, t, n) -> dict`

Generates a public key and `n` shares of the private key.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"` or `"1"`. |
| `t` | `int` | Threshold: minimum number of shares required for decryption. |
| `n` | `int` | Total number of shares to generate. |
| **Return** | `dict` | `{"gpubkey": str, "privkeys": [str, ...]}` |

**Constraints**: `1 ≤ t ≤ n ≤ 255`.

Each element of `privkeys` is a share encoded in base64url. Internally, each share is a 1633-byte blob: 1 byte of index (1..n) followed by the 1632 bytes of the Shamir share.

**Exceptions**:
- `ArgumentTypeError` — if `t` or `n` are not `int` (booleans are rejected).
- `EncryptionError` — if the constraints `1 ≤ t ≤ n ≤ 255` are not satisfied.
- `VersionNotFoundError` — if the version is unknown.


### `crx.red.encrypt(version, gpubkey, msg) -> str`

Encrypts a message with the RED public key.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"` or `"1"`. |
| `gpubkey` | `str` | Public key (base64url, 800 raw bytes). |
| `msg` | `str` | Plaintext message. |
| **Return** | `str` | Encrypted bundle (base64url). |

RED encryption is strictly identical to BLACK encryption. The public key is an ordinary ML-KEM-512 key. The only difference is that the corresponding private key has been split into shares during `genkeys`.

**Exceptions**:
- `ArgumentTypeError` — if `gpubkey` or `msg` are not `str`.
- `EncryptionError` — if the public key is invalid.


### `crx.red.decrypt(version, privkeys, msg) -> str`

Decrypts a RED bundle by reconstructing the private key from the shares.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Expected version. `"1.0"` or `"1"`. |
| `privkeys` | `list[str]` | List of shares (each in base64url). At least `t` shares are required. |
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Plaintext message. |

**Behavior with an insufficient number of shares**: if fewer than `t` shares are provided, Lagrange reconstruction produces an incorrect private key. BLACK decryption then fails on the Poly1305 authentication tag, raising a `DecryptionError`. The error is indistinguishable from an invalid key — the attacker cannot tell whether shares are missing or the shares are wrong.

**Exceptions**:
- `ArgumentTypeError` — if `privkeys` is not a `list` or if an element is not a `str`.
- `DecryptionError` — if the shares are insufficient, invalid, corrupted, duplicated, or if the version does not match.


### `crx.red.getversion(msg) -> str`

Extracts the version of a RED bundle without decrypting it. Identical to other protocols.


## Complete example

```python
import pycryptox as crx

# Scenario: 3 directors, threshold of 2
keys = crx.red.genkeys("1", t=2, n=3)

# Distribute the shares
part_alice = keys["privkeys"][0]
part_bob   = keys["privkeys"][1]
part_carol = keys["privkeys"][2]

# Encrypt the company secret
bundle = crx.red.encrypt("1", keys["gpubkey"], "The vault password is XYZ-789")

# Alice and Carol meet to decrypt (2 shares out of 3)
secret = crx.red.decrypt("1", [part_alice, part_carol], bundle)
print(secret)  # → "The vault password is XYZ-789"

# Bob alone cannot decrypt (1 share out of 2 required)
try:
    crx.red.decrypt("1", [part_bob], bundle)
except crx.DecryptionError:
    print("Impossible with a single share")
```


## Edge cases

**t = 1**: any single share is sufficient. Equivalent to distributing full copies of the key. Useful for redundancy, not for multi-party security.

**t = n**: all shares are required. If a single share is lost, the secret is unrecoverable.

**Duplicated shares**: if the same share is provided twice in `privkeys`, decryption raises a `DecryptionError("duplicate share indices")`.

**Shares from different groups**: if shares from two different `genkeys()` are mixed, reconstruction produces an incorrect key and decryption fails on the Poly1305 tag.


## Version history

### Version 1.0 (stable)

Current version, documented in the sections above. Uses Shamir GF(256) for splitting the ML-KEM-512 private key, and BLACK for message encryption.

### Version 0.0

Initial version of the protocol. The functions return fixed responses without performing any cryptographic operation.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
