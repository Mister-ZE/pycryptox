# BLUE protocol

BLUE is the deniable asymmetric encryption protocol of Pycryptox. It allows the sender to encrypt two messages in a single bundle: a real message and a decoy. The recipient can decrypt either one depending on the private key used. An adversary who forces the disclosure of one private key obtains a message — but cannot prove that another message exists in the same bundle.

BLUE is the most powerful protocol in Pycryptox.


## Concept: dual x/y channel

Each BLUE keyring contains three keys:

- **`gpubkey`** — composite public key (concatenation of two ML-KEM-512 public keys).
- **`xprivkey`** — private key of the x channel.
- **`yprivkey`** — private key of the y channel.

During encryption, the sender provides a message for the x channel (`xmsg`), a message for the y channel (`ymsg`), or both. The two messages are encrypted independently via the BLACK protocol with the respective channel public key, then concatenated into a single bundle with a randomized slot order.


## Me vs Opponent: attacker scenarios and defences

BLUE's deniability rests on a series of design decisions. The clearest way to motivate each one is to think as an attacker first: pick an attack that would expose the hidden channel, then describe the design choice that defeats it. The four attacks below are the ones a competent adversary will actually try on a BLUE bundle.

### Attack 1 — Message-size correlation

> **Attacker's reasoning.** "The two messages probably do not have the same length. The 'real' message is the more informative one, which is usually the longer (it carries content, not just a placeholder). If I can see two distinct ciphertext sizes in the bundle, I know which slot is the real one."

**Defence.** Each message is **padded to a fixed bucket size** before encryption. v2.0 offers eight buckets (4 KB, 16 KB, 64 KB, 256 KB, 1 MB, 16 MB, 256 MB, 1 GiB). If `xmsg` and `ymsg` do not fit in the same bucket, encryption is refused (`EncryptionError`). After padding, both BLACK ciphertexts have **exactly the same byte length**. The attacker cannot tell them apart by size.

### Attack 2 — Timing oracle on decryption

> **Attacker's reasoning.** "If the bundle is always `[enc_x][enc_y]` in that order, then a recipient who holds `xprivkey` decrypts the first slot directly (≈ 1 KEM decap), while a recipient who holds `yprivkey` has to skip the first and decrypt the second (≈ 2 decaps, or some extra logic that telegraphs the choice). By measuring how long decryption takes — over a network, or via a side channel — I can correlate timing with which key the recipient holds. After enough observations, I know which side is the 'real' channel for that user."

**Defence.** The **slot order is randomised at encryption time** via `secrets.randbits(1)` and stored in a 1-byte `order_flag` in the clear. Each fresh encryption flips the order independently. A recipient reads the flag, identifies the slot matching their key, and decrypts only that slot in constant work (1 KEM decap + 1 AEAD verify). Over many bundles, the half/half flag distribution makes the cumulative time symmetric for both channels: an external timing observation reveals nothing about which channel the recipient holds.

### Attack 3 — Mono-mode detection by bundle size

> **Attacker's reasoning.** "If only one of the two channels was actually used (mono-mode), the bundle is probably half the size of a dual one — only one BLACK ciphertext plus some metadata. If I see a 'short' BLUE bundle, I know mono-mode was used; if I see a 'long' one, I know dual mode. Mono-mode tells me there is no decoy, which means whatever is in there is the only thing worth coercing the user to reveal."

**Defence.** In mono mode, the protocol **generates an ephemeral ML-KEM-512 keypair** for the unused side, encrypts uniformly random bytes of the same length as the real message, and then **destroys the ephemeral private key** immediately. The resulting bundle is byte-for-byte structurally identical to a dual bundle: two full BLACK ciphertexts of equal size, an order flag, a length prefix. No external observer can distinguish a mono bundle from a dual bundle. (Even the sender cannot decrypt the decoy slot afterwards — the ephemeral private key is gone.)

### Attack 4 — Structural fingerprinting of the bundle

> **Attacker's reasoning.** "Encrypted blobs often have recognisable structure: tag positions, alignment patterns, magic bytes for ML-KEM and AEAD inside the ciphertexts. If I see two blocks side-by-side with identifiable BLACK headers at their boundaries, I can confirm that the bundle uses BLUE's dual-channel pattern, even if I cannot read the content. That alone is incriminating in some contexts (the simple act of using deniable encryption is suspicious)."

**Defence.** Each BLACK ciphertext is itself indistinguishable from uniform random bytes (ML-KEM ciphertexts are CCA-secure encapsulations; ChaCha20 stream output and Poly1305 tags are pseudo-random). Concatenating two such blobs produces a string that is itself pseudo-random — the only non-random bytes in the entire bundle are the 1-byte order flag (uniformly distributed) and the 4-byte length prefix (deterministic from the bucket choice). Combined with the protocol's policy of routing **all** asymmetric encryption through BLUE (see *Why everyone must use BLUE* below), there is no way to fingerprint a BLUE bundle as different from any other post-quantum encrypted payload.

### Attacks not addressed by BLUE

BLUE solves a precise threat model and does not pretend to solve adjacent ones. It is honest about its limits:

- **Coerced disclosure of both keys at once.** If the adversary obtains both `xprivkey` and `yprivkey`, both messages are decryptable. This is why the keyx system stores them in separate Keyx (`bluekeys.keys` and `bluekeys.ckeys`), expected to live on different devices. *See the "Physical key separation" subsection below.*
- **Forensic recovery of plaintext in RAM.** BLUE protects bundles at rest and in transit. It does not protect the plaintext while the application is using it. Memory forensics, swap dumps, and OS-level snapshots are out of scope.
- **Metadata leakage.** Send time, frequency, sender/receiver identity, network path — all visible to a network observer regardless of BLUE's content protection. To mask metadata, an additional layer (anonymous network, message-mixing, steganography via YELLOW) is required.
- **Decoy credibility.** If the decoy message is empty, absurd, or obviously fake ("test", "asdf"), no amount of cryptographic indistinguishability will save the deniability. The decoy must look like a real message the user would plausibly have written. This is a UX/operational responsibility on the application built on top of BLUE.


## Plausible deniability

### Base scenario

Alice wants to send a confidential message to Bob. She knows that an adversary could one day force her to reveal her key.

1. Alice generates a BLUE keyring: `gpubkey`, `xprivkey`, `yprivkey`.
2. She encrypts the real message on the x channel and a credible decoy on the y channel.
3. She stores `yprivkey` (the decoy key) in her main Keyx (`keyx.bluekeys.keys`, on her machine).
4. She stores `xprivkey` (the real key) in a separate Keyx (`keyx.bluekeys.ckeys`, on a USB drive she keeps elsewhere).

### Coercion scenario

An adversary forces Alice to open her Keyx. Alice opens `bluekeys.keys`, which contains `yprivkey`. The adversary decrypts the bundle and obtains the decoy. They cannot prove that the x channel exists: the bundle they see is an opaque blob, and `yprivkey` produces a credible message.

The USB drive containing `xprivkey` is physically absent. The adversary does not even know it exists.

### Scenario without deniability

If Alice does not need deniability, she uses BLUE in mono mode:

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], xmsg="confidential message")
```

She only stores `xprivkey`, no `ckeys`, no decoy. BLUE then works as a classic asymmetric encryption, but with the same indistinguishable bundle structure.

### Why everyone must use BLUE (and not BLACK directly)

If BLACK were exposed as a public protocol, two populations of users would coexist: those who use BLACK (no deniability) and those who use BLUE (deniability). An adversary who sees a BLUE bundle would immediately know that the user potentially has something to hide — otherwise they would have used BLACK.

By making BLACK internal and forcing all asymmetric encryption to go through BLUE, all bundles have the same structure. Users who do not need deniability and those who do produce identical bundles. The adversary cannot distinguish them.


## Cryptographic primitives (v2.0)

| Component | Algorithm |
|---|---|
| Key encapsulation | ML-KEM-512 (FIPS 203) via BLACK |
| Symmetric encryption | ChaCha20-Poly1305 via BLACK |
| Slot order | Random bit (`secrets.randbits(1)`) |
| Padding | Fixed-size buckets (8 sizes up to 1 GiB) |


## Padding

To prevent message size from betraying content, each message is padded up to the size of the smallest bucket that can contain it.

Available buckets (v2.0):

| Bucket | Size |
|---|---|
| 1 | 4 KB |
| 2 | 16 KB |
| 3 | 64 KB |
| 4 | 256 KB |
| 5 | 1 MB |
| 6 | 16 MB |
| 7 | 256 MB |
| 8 | 1 GiB |

The padded format is:

```
[4 bytes: message length] [message] [random padding bytes]
```

If both messages (x and y) are provided, they must be in the **same bucket**. Otherwise, the difference in ciphertext size would break deniability. If the two messages do not fit in the same bucket, `encrypt` raises `EncryptionError`.

Hard size cap: each individual message must not exceed **1 GiB** (`2³⁰` bytes). At sizes approaching this cap, the encryption peak RAM usage may reach ~7-9 GiB; users on memory-constrained machines should stay well below.


## Encryption modes

### Dual mode (x and y)

The sender provides both messages. Both are encrypted and assembled in the bundle.

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], xmsg="real", ymsg="decoy")
```

### Mono-x mode (x only)

The sender provides only `xmsg`. The protocol generates an **ephemeral** ML-KEM-512 key pair for the y channel, encrypts random noise as `ymsg`, then destroys the ephemeral private key. The y channel is then physically undecryptable — even by the sender. The bundle remains indistinguishable from a dual bundle.

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], xmsg="real message")
```

### Mono-y mode (y only)

Identical to mono-x but reversed: the x channel contains undecryptable noise.

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], ymsg="real message")
```


## Asynchronous mode (v2.0+)

For large messages (typically > 100 MB), the encryption or decryption work can take several seconds. To avoid blocking the main thread and give the caller visibility on progress, BLUE v2.0 provides an asynchronous mode triggered by passing an `id` argument.

```python
# Launch encryption in background, no return value
crx.blue.encrypt("2", keys["gpubkey"], xmsg="big_data", id="job1")

# Poll progress (returns a float in [0.0, 1.0])
while crx.blue.show_encryption_progress(id="job1") < 1.0:
    update_ui()
    time.sleep(0.05)

# Retrieve the bundle (blocks if not yet done; auto-removes the job from the registry)
bundle = crx.blue.get_encryption_result(id="job1")
```

Symmetric API exists for decryption: `show_decryption_progress(id)` and `get_decryption_result(id)`.

### Stepped progress reporting

Progress is reported as a sequence of discrete paliers, each corresponding to a real completed phase of the work. The encryption pipeline passes through the following paliers:

| Value | Meaning |
|---|---|
| 0.00 | Job created, work not yet started |
| 0.05 | Input validation and gpubkey decoding complete |
| 0.10 | Bucket selected and both messages padded |
| 0.50 | x slot encryption complete |
| 0.85 | y slot encryption complete |
| 1.00 | Bundle assembled, base64-encoded, ready |

Decryption uses a shorter sequence: `0.10` (header parsed and slot located), `0.90` (target slot decrypted), `1.00` (unpadded and decoded).

The library reports the truth: the latest palier reached. No interpolation, no estimation, no animation is performed internally. This is a deliberate design choice: smoothing a progress bar is a presentation concern best handled by the application layer, where the rendering framework (Rich, tqdm, Qt, web UIs, etc.) already has its own animation primitives and can ease between two values with proper frame timing.

If the application needs a smooth visual, it can interpolate between successive polls using its own state. For example, with `rich`:

```python
from rich.progress import Progress
import time

with Progress() as p:
    task = p.add_task("Encrypting...", total=1.0)
    crx.blue.encrypt("2", gpubkey, xmsg=big, id="job1")
    while crx.blue.show_encryption_progress(id="job1") < 1.0:
        p.update(task, completed=crx.blue.show_encryption_progress(id="job1"))
        time.sleep(0.05)
    p.update(task, completed=1.0)
```

Rich interpolates the bar position between updates internally, producing a smooth animation from the stepped values.

### Identifier semantics

The `id` argument is **caller-provided** and must be unique across active jobs. Any hashable value works: integers, strings, tuples. If an `id` is already in use by an unconsumed job, a second `encrypt(..., id=X)` raises `EncryptionError`.

The job is **automatically removed from the registry** as soon as `get_encryption_result(id)` (or its decryption counterpart) returns. After retrieval, the same id can be reused. Calling `show_*` or `get_*` on a non-existent id, or on an id belonging to a job of a different kind, raises the appropriate exception.

### Deferred error handling

Exceptions raised inside the background work (e.g. wrong key, malformed bundle) are stored in the registry and re-raised when `get_*_result(id)` is called. Type-validation errors that occur at call time (such as a non-str `gpubkey`) are raised synchronously.

### When asynchronous mode is unnecessary

For small messages (typically under 1 MB), the work completes within microseconds and the overhead of spawning a background thread is not justified. Synchronous mode (`id=None`, the default) is preferable in those cases.


## Bundle migration

BLUE v1.0 bundles can be migrated to v2.0 via `update_bundle`. The function decrypts the source bundle, then re-encrypts it under the new version.

```python
new_bundle = crx.blue.update_bundle(
    "1 to 2",            # spec: "<old>.<minor> to <new>.<minor>" (minors optional)
    keys["gpubkey"],
    old_bundle,
    xprivkey=keys["xprivkey"],   # at least one of x/y privkey required
    yprivkey=keys["yprivkey"],   # provide both for lossless migration
)
```

If only one of `xprivkey` or `yprivkey` is provided when the source bundle was dual-mode, the slot corresponding to the missing privkey is replaced by a random decoy in the new bundle — **the information in that slot is lost**. This behaviour is deliberate; the caller is responsible for ensuring that the loss is acceptable for their use case, or for supplying both privkeys when a lossless migration is required.

Downgrades (e.g. `"2 to 1"`) require `downgrade=True`; otherwise `DowngradeError` is raised.

Same-version specs (`"2 to 2"`, `"2.0 to 2"`) return the input unchanged.


## API

### `crx.blue.encrypt(version, gpubkey, xmsg=None, ymsg=None, *, id=None) -> str | None`

Encrypts one or two messages into a BLUE bundle.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. `"2.0"`, `"2"`, `"1.0"`, or `"1"`. |
| `gpubkey` | `str` | Composite public key (base64url, 1600 raw bytes). |
| `xmsg` | `str \| None` | Message for the x channel. `None` if unused. |
| `ymsg` | `str \| None` | Message for the y channel. `None` if unused. |
| `id` | `Any \| None` | If provided, encryption runs in the background. v2.0+ only. |
| **Return** | `str \| None` | Encrypted bundle (sync mode), or `None` (async mode). |

At least one of `xmsg` or `ymsg` must be provided. If both are provided, they must fit in the same padding bucket.

**Exceptions**:
- `ArgumentTypeError` — if an argument is not of the correct type.
- `EncryptionError` — if no message is provided, if `gpubkey` is invalid, if the messages do not fit in the same bucket, if a message exceeds 1 GiB, if an async `id` is already in use, or if async mode is requested on a non-v2.0+ version.
- `VersionNotFoundError` — if the version is unknown.

### `crx.blue.decrypt(version, privkey, msg, *, slot=..., id=None) -> str | None`

Decrypts a BLUE bundle with a private key (x or y).

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Expected version. |
| `privkey` | `str` | `xprivkey` or `yprivkey`. |
| `msg` | `str` | Encrypted bundle (base64url). |
| `slot` | `str` | **Required in v2.0+ (keyword-only)**. `"x"` or `"y"` — identifies which slot the privkey decrypts. Not used in v1.0. |
| `id` | `Any \| None` | If provided, decryption runs in the background. v2.0+ only. |
| **Return** | `str \| None` | Plaintext (sync mode), or `None` (async mode). |

In v1.0, the protocol automatically tries both channels (no `slot` argument). In v2.0+, the `slot` argument is required: the order flag in the bundle locates the matching slot's ciphertext, and only that slot is decrypted.

**Exceptions**:
- `ArgumentTypeError` — if an argument is not `str`.
- `DecryptionError` — if the key does not decrypt the requested slot, the bundle is corrupted, or async mode is requested on a non-v2.0+ version.

### `crx.blue.genkeys(version) -> dict[str, str]`

Generates a BLUE keyring.

| Parameter | Type | Description |
|---|---|---|
| `version` | `str` | Protocol version. |
| **Return** | `dict` | `{"gpubkey": str, "xprivkey": str, "yprivkey": str}` |

The `gpubkey` is the concatenation of two ML-KEM-512 public keys (800 + 800 = 1600 raw bytes, encoded in base64url).

### `crx.blue.getversion(msg) -> str`

Extracts the version of a BLUE bundle without decrypting it.

| Parameter | Type | Description |
|---|---|---|
| `msg` | `str` | Encrypted bundle (base64url). |
| **Return** | `str` | Version in `"M.m"` format. |

### `crx.blue.update_bundle(old_to_new, gpubkey, old_msg, xprivkey=None, yprivkey=None, downgrade=False) -> str`

Re-encrypts a BLUE bundle from one protocol version to another.

| Parameter | Type | Description |
|---|---|---|
| `old_to_new` | `str` | Specifier in the form `"1 to 2"`, `"1.0 to 2.0"`, or any combination of major-only and exact versions separated by ` to `. |
| `gpubkey` | `str` | Composite public key for the new bundle. |
| `old_msg` | `str` | The bundle to migrate. |
| `xprivkey` | `str \| None` | x-side private key. At least one of x/y required. |
| `yprivkey` | `str \| None` | y-side private key. Optional but recommended for lossless dual migration. |
| `downgrade` | `bool` | If `True`, permits migration to an older version. Default `False`. |
| **Return** | `str` | Re-encrypted bundle. |

**Exceptions**:
- `ArgumentTypeError` — invalid types.
- `VersionNotFoundError` — invalid `old_to_new` spec or unknown version.
- `DowngradeError` — old > new and `downgrade=False`.
- `DecryptionError` — neither privkey decrypts the bundle.
- `EncryptionError` — no privkey provided, or re-encryption fails.

### `crx.blue.show_encryption_progress(id) -> float`
### `crx.blue.show_decryption_progress(id) -> float`

Return the current progress (0.0 to 1.0) of a background encrypt/decrypt job. Raise `EncryptionError` / `DecryptionError` if no such job exists or its kind does not match.

### `crx.blue.show_encryption_eta(id) -> float | None`
### `crx.blue.show_decryption_eta(id) -> float | None`

Estimate the number of seconds remaining for the background job with the given `id`. Returns `None` when progress is below 1 % (too low to project), and `0.0` when the job has completed. The estimate is derived from elapsed wall-clock time divided by the current palier value, projected to the remaining fraction; accuracy improves as more paliers are reached. Raise `EncryptionError` / `DecryptionError` if no such job exists or its kind does not match.

### `crx.blue.get_encryption_result(id) -> str`
### `crx.blue.get_decryption_result(id) -> str`

Block until the background job with the given `id` completes, return the bundle (encrypt) or plaintext (decrypt), and auto-remove the job from the registry. Re-raise any exception that occurred during the work. Raise `EncryptionError` / `DecryptionError` if no such job exists or its kind does not match.


## Bundle structure (v2.0)

The raw bundle (after removal of the 2 version bytes and before base64 encoding):

```
[1 byte : order_flag]              → 0 = enc_x first, 1 = enc_y first
[4 bytes: len(enc_first)]          → big-endian length of the first slot
[enc_first bytes]                  → BLACK ciphertext for the first-slot channel
[enc_second bytes]                 → BLACK ciphertext for the second-slot channel
```

Each `enc_*` is itself a BLACK v1.0 ciphertext: ML-KEM-512 encapsulation + ChaCha20-Poly1305 (nonce + ciphertext + tag), base64-encoded. Both slots are padded to the same bucket size before BLACK encryption, ensuring both `enc_*` blobs have identical sizes.

The `order_flag` is read in the clear by `decrypt` to identify which slot is x and which is y, but conveys no information about the contents (it is a uniformly random bit).


## Security considerations

**Decoy credibility**: deniability is useless if the decoy message is not credible. An empty or absurd decoy ("test", "nothing") will convince no one. The decoy must look like a real message that the user would reasonably have sent.

**Physical key separation**: deniability assumes that the adversary has access to only one private key. If both keys (`xprivkey` and `yprivkey`) are stored in the same place, the adversary finds them both and deniability is null. The keyx system provides two separate Keyx (`keys` and `ckeys`) for exactly this reason.

**Unprotected metadata**: BLUE protects message content, not metadata. Send time, exchange frequency, the identity of the sender and recipient are not concealed by BLUE. To mask this metadata, an additional layer (anonymous network, steganography via YELLOW) is required.

**Bundle size**: the bundle size can reveal which bucket the message is in, and therefore an approximate size range of the message (e.g. 0-4 KB, 4-16 KB, 16-256 MB, etc.). It does not reveal the exact size of the message within the bucket.

**Async job security**: the `id` registry stores results in memory until retrieved. Sensitive plaintexts in finished decrypt jobs persist until `get_decryption_result(id)` is called. Callers handling sensitive data should retrieve results promptly.


## Complete example

```python
import pycryptox as crx
import time

# Generate a keyring
keys = crx.blue.genkeys("2")

# --- Synchronous use (small messages) ---
bundle = crx.blue.encrypt("2", keys["gpubkey"],
                          xmsg="GPS coordinates: 48.8566, 2.3522",
                          ymsg="No news, all is well.")

# Recipient decrypts with xprivkey → real message
real = crx.blue.decrypt("2", keys["xprivkey"], bundle, slot="x")
print(real)  # → "GPS coordinates: 48.8566, 2.3522"

# Under coercion, hand over yprivkey → credible decoy
decoy = crx.blue.decrypt("2", keys["yprivkey"], bundle, slot="y")
print(decoy)  # → "No news, all is well."

# --- Asynchronous use (large messages) ---
big_data = "X" * (10 * 1024 * 1024)   # 10 MB
crx.blue.encrypt("2", keys["gpubkey"], xmsg=big_data, id="bigjob")

while (p := crx.blue.show_encryption_progress(id="bigjob")) < 1.0:
    print(f"  progress: {p:.0%}")
    time.sleep(0.1)

big_bundle = crx.blue.get_encryption_result(id="bigjob")

# --- Migration from v1.0 ---
old_keys = crx.blue.genkeys("1")
old_bundle = crx.blue.encrypt("1", old_keys["gpubkey"], xmsg="legacy data")
new_bundle = crx.blue.update_bundle("1 to 2", old_keys["gpubkey"],
                                    old_bundle, xprivkey=old_keys["xprivkey"])
print(crx.blue.getversion(new_bundle))   # → "2.0"
```


## Version history

### Version 2.0 (stable, since 3.0.0)

Current version. Streamlined wire format `[order_flag][len][enc_x][enc_y]`, expanded bucket range (up to 1 GiB), public-only BLACK API usage, asynchronous job mode with stepped progress reporting, and `update_bundle` for migrating v1.0 bundles. The order flag is randomized per encryption (random bit recorded in clear), and decryption uses an explicit `slot` argument to identify the matching channel without try-both fallback.

### Version 1.0 (legacy)

Previous stable version. Uses ML-KEM-512 via BLACK, bucket padding (up to 1 MB), and chemical key mixing — encrypted messages are byte-interleaved with random noise via two encrypted position lists (chemkeys). The mixing added no measurable deniability beyond what is already provided by ML-KEM + ChaCha20-Poly1305 ciphertext indistinguishability, and its byte-level placement constituted the bottleneck responsible for the 1 MB cap. v2.0 replaces it with a simple concatenation + length prefix + random order flag.

### Version 0.0

Initial version of the protocol. The functions return fixed responses without performing any cryptographic operation.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
