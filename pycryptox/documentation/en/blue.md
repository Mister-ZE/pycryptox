# BLUE protocol

BLUE is the deniable asymmetric encryption protocol of Pycryptox. It allows the sender to encrypt two messages in a single bundle: a real message and a decoy. The recipient can decrypt either one depending on the private key used. An adversary who forces the disclosure of one private key obtains a message — but cannot prove that another message exists in the same bundle.

BLUE is the most powerful protocol in Pycryptox.


## Concept: dual x/y channel

Each BLUE keyring contains three keys:

- **`gpubkey`** — composite public key (concatenation of two ML-KEM-512 public keys).
- **`xprivkey`** — private key of the x channel.
- **`yprivkey`** — private key of the y channel.

During encryption, the sender provides a message for the x channel (`xmsg`), a message for the y channel (`ymsg`), or both. The two messages are encrypted independently via the BLACK protocol, then their bytes are **mixed** with random noise into a single monolithic bundle.

The position of each byte in the mix is recorded in a "chemical key", itself encrypted with the public key of the corresponding channel. The recipient decrypts their chemical key, extracts their bytes from the mix, and decrypts their message.


## Why an adversary cannot distinguish the channels

BLUE's deniability rests on a series of design decisions which, together, make the bundle opaque. Each one solves a specific problem that, if untreated, would betray the existence of two channels.

**Problem 1: message size can betray content.** If the two messages had different sizes in the bundle, an adversary could deduce which channel contains the real message (the longer or the shorter, depending on context). Solution: each message is **padded to a fixed size** determined by a bucket. Both messages must fall into the same bucket, otherwise encryption is refused. After padding, both ciphertexts have exactly the same size.

**Problem 2: two ciphertexts side by side would be recognizable.** If the bundle simply contained `[ciphertext_x][ciphertext_y]`, an observer would see two distinct blocks of identical size — a suspicious structure. Solution: the bytes of the two ciphertexts are **randomly mixed** with noise bytes into a single blob (chemical key mixing). The result is a stream of bytes with no visible structure.

**Problem 3: a single message would produce a shorter bundle.** If only one channel contained a real message and the other was empty, the bundle size would be halved, which would prove that only one channel is used. Solution: in mono mode (a single message provided), the protocol generates an **ephemeral ML-KEM-512 key** for the missing channel, encrypts random noise of the same size as the real message, then **destroys the ephemeral private key**. The bundle still contains two ciphertexts of equal size, indistinguishable from a dual bundle.

**Problem 4: the bundle header could reveal the sizes.** The bundle contains the size of the encrypted chemical keys (`len_xchem` and `len_ychem`) in plaintext. If these sizes differed, they would betray the size of each ciphertext. Solution: since both ciphertexts are of identical size (same bucket), both chemical keys contain the same number of positions, so `len_xchem == len_ychem` in all cases.

**Problem 5: identical bundles for the same message would be correlatable.** Solution: random noise of variable size (between 100 and 9000 bytes) is added to the mix. Each bundle has a non-deterministic size, even for identical messages.

The result: an adversary examining a BLUE bundle sees a blob of bytes of variable size, with no structure, no marker, and no way to know whether it contains one or two messages. Even with the key of one channel, they cannot prove the existence of the other.


## Plausible deniability

### Base scenario

Alice wants to send a confidential message to Bob. She knows that an adversary could one day force her to reveal her key.

1. Alice generates a BLUE keyring: `gpubkey`, `xprivkey`, `yprivkey`.
2. She encrypts the real message on the x channel and a credible decoy on the y channel.
3. She stores `yprivkey` (the decoy key) in her main keystore (`keyx.bluekeys.keys`, on her machine).
4. She stores `xprivkey` (the real key) in a separate keystore (`keyx.bluekeys.ckeys`, on a USB drive she keeps elsewhere).

### Coercion scenario

An adversary forces Alice to open her keystore. Alice opens `channels.keys`, which contains `yprivkey`. The adversary decrypts the bundle and obtains the decoy. They cannot prove that the x channel exists: the bundle they see is an opaque blob, and `yprivkey` produces a credible message.

The USB drive containing `xprivkey` is physically absent. The adversary does not even know it exists.

### Scenario without deniability

If Alice does not need deniability, she uses BLUE in mono mode:

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="confidential message")
```

She only stores `xprivkey`, no `ckeys`, no decoy. BLUE then works as a classic asymmetric encryption, but with the same indistinguishable bundle structure.

### Why everyone must use BLUE (and not BLACK directly)

If BLACK were exposed as a public protocol, two populations of users would coexist: those who use BLACK (no deniability) and those who use BLUE (deniability). An adversary who sees a BLUE bundle would immediately know that the user potentially has something to hide — otherwise they would have used BLACK.

By making BLACK internal and forcing all asymmetric encryption to go through BLUE, all bundles have the same structure. Users who do not need deniability and those who do produce identical bundles. The adversary cannot distinguish them.


## Cryptographic primitives (v1.0)

| Component | Algorithm |
|---|---|
| Key encapsulation | ML-KEM-512 (FIPS 203) via BLACK |
| Symmetric encryption | ChaCha20-Poly1305 via BLACK |
| Mixing (chemical mixing) | Random permutation (secrets.SystemRandom) |
| Padding | Fixed-size buckets |


## Padding

To prevent message size from betraying content, each message is padded up to the size of the smallest bucket that can contain it.

Available buckets (v1.0):

| Bucket | Size |
|---|---|
| 1 | 4 KB |
| 2 | 16 KB |
| 3 | 64 KB |
| 4 | 256 KB |
| 5 | 1 MB |

The padded format is:

```
[4 bytes: message length] [message] [random padding bytes]
```

If both messages (x and y) are provided, they must be in the **same bucket**. Otherwise, the difference in ciphertext size would break deniability. If the two messages do not fit in the same bucket, `encrypt` raises `EncryptionError`.

Current limit: the maximum bucket is 1 MB. Longer messages are not supported in v1.0.


## Encryption modes

### Dual mode (x and y)

The sender provides both messages. Both are encrypted and mixed in the bundle.

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="real", ymsg="decoy")
```

### Mono-x mode (x only)

The sender provides only `xmsg`. The protocol generates an **ephemeral** ML-KEM-512 key pair for the y channel, encrypts random noise as `ymsg`, then destroys the ephemeral private key. The y channel is then physically undecryptable — even by the sender. The bundle remains indistinguishable from a dual bundle.

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="real message")
```

### Mono-y mode (y only)

Identical to mono-x but reversed: the x channel contains undecryptable noise.

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], ymsg="real message")
```


## API

### `crx.blue.encrypt(version, gpubkey, xmsg=None, ymsg=None) -> str`

Encrypts one or two messages into a BLUE bundle.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"` or `"1"`. |
| `gpubkey` | `str` | Composite public key (base64url, 1600 raw bytes). |
| `xmsg` | `str \| None` | Message for the x channel. `None` if unused. |
| `ymsg` | `str \| None` | Message for the y channel. `None` if unused. |
| **Return** | `str` | Encrypted bundle (base64url). |

At least one of the two messages (`xmsg` or `ymsg`) must be provided. If both are provided, they must fit in the same padding bucket.

**Exceptions**:
- `ArgumentTypeError` — if an argument is not of the correct type.
- `EncryptionError` — if no message is provided, if `gpubkey` is invalid, if the messages do not fit in the same bucket, or if a message exceeds 1 MB.
- `VersionNotFoundError` — if the version is unknown.

### `crx.blue.decrypt(version, privkey, msg) -> str`

Decrypts a BLUE bundle with a private key (x or y).

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Expected version. `"1.0"` or `"1"`. |
| `privkey` | `str` | Private key of the x channel (`xprivkey`) or y channel (`yprivkey`). |
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Plaintext message corresponding to the channel of the provided key. |

The protocol automatically tries both channels (x then y). It returns the message of the first channel that decrypts correctly. The caller does not need to specify whether they are using xprivkey or yprivkey — the protocol detects it.

**Exceptions**:
- `ArgumentTypeError` — if `privkey` or `msg` are not `str`.
- `DecryptionError` — if the key matches no channel, the bundle is corrupted, or the version does not match.

### `crx.blue.genkeys(version) -> dict[str, str]`

Generates a BLUE keyring.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"1.0"` or `"1"`. |
| **Return** | `dict` | `{"gpubkey": str, "xprivkey": str, "yprivkey": str}` |

The `gpubkey` is the concatenation of two ML-KEM-512 public keys (800 + 800 = 1600 raw bytes, encoded in base64url).

### `crx.blue.getversion(msg) -> str`

Extracts the version of a BLUE bundle without decrypting it.

| Parameter | Type | Description |
|---|---|---|
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Version in `"M.m"` format. |


## Bundle structure (v1.0)

The raw bundle (after removal of the 2 version bytes and before base64 encoding):

```
[4 bytes: len(enc_xchemkey)]
[4 bytes: len(enc_ychemkey)]
[enc_xchemkey]                    → x chemical key, encrypted via BLACK with xpubkey
[enc_ychemkey]                    → y chemical key, encrypted via BLACK with ypubkey
[mixmsg]                          → mix of enc_xmsg + enc_ymsg + noise
```

The chemical keys contain the positions (indices in `mixmsg`) of each channel's bytes, encoded as big-endian 4 bytes per position.


## Security considerations

**Decryption oracle**: applications using BLUE must avoid exposing decryption success/failure status to unauthenticated parties. The noise portion of the bundle is not authenticated. A decryption oracle could be used to map the positions of the chemical keys across many trials.

**Decoy credibility**: deniability is useless if the decoy message is not credible. An empty or absurd decoy ("test", "nothing") will convince no one. The decoy must look like a real message that the user would reasonably have sent.

**Physical key separation**: deniability assumes that the adversary has access to only one private key. If both keys (`xprivkey` and `yprivkey`) are stored in the same place, the adversary finds them both and deniability is null. The keyx system provides two separate keystores (`keys` and `ckeys`) for exactly this reason.

**Unprotected metadata**: BLUE protects message content, not metadata. Send time, exchange frequency, the identity of the sender and recipient are not concealed by BLUE. To mask this metadata, an additional layer (anonymous network, steganography via YELLOW) is required.

**Bundle size**: the bundle size can reveal which bucket the message is in, and therefore an approximate size range of the message (0-4 KB, 4-16 KB, etc.). It does not reveal the exact size of the message within the bucket.


## Complete example

```python
import pycryptox as crx

# Generate a keyring
keys = crx.blue.genkeys("1")

# Dual encryption (real message + decoy)
bundle = crx.blue.encrypt("1", keys["gpubkey"],
                          xmsg="GPS coordinates of the meeting point: 48.8566, 2.3522",
                          ymsg="No news, all is well.")

# The recipient decrypts with xprivkey → real message
real = crx.blue.decrypt("1", keys["xprivkey"], bundle)
print(real)  # → "GPS coordinates of the meeting point: 48.8566, 2.3522"

# Under coercion, they hand over yprivkey → credible decoy
decoy = crx.blue.decrypt("1", keys["yprivkey"], bundle)
print(decoy)  # → "No news, all is well."

# Mono encryption (no deniability needed)
bundle_mono = crx.blue.encrypt("1", keys["gpubkey"], xmsg="Simple message")
plain = crx.blue.decrypt("1", keys["xprivkey"], bundle_mono)
print(plain)  # → "Simple message"

# Extract the version without decrypting
version = crx.blue.getversion(bundle)
print(version)  # → "1.0"
```


## Version history

### Version 1.0 (stable)

Current version, documented in the sections above. Uses ML-KEM-512 via BLACK, bucket padding, and chemical key mixing.

### Version 0.0

Initial version of the protocol. The functions return fixed responses without performing any cryptographic operation.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
