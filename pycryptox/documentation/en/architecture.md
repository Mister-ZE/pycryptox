# Architecture

## File tree

```
Pycryptox/
├── __init__.py                  Exposes purple, blue, red, yellow, keyx, and the exceptions.
├── README.md
├── CREDITS.md
│
├── _assets/
│   └── words.txt                EFF wordlist for passphrase generation (PURPLE).
│
├── _exceptions/
│   └── _exceptions.py           All Pycryptox exception classes.
│
├── _colorx/                     The encryption protocols.
│   ├── _black.py                Internal protocol (ML-KEM-512 + ChaCha20-Poly1305).
│   ├── _versioning.py           Internal version-dispatch helpers shared by purple, blue, red.
│   ├── purple.py                Password-based encryption.
│   ├── blue.py                  Deniable asymmetric encryption.
│   ├── red.py                   Threshold encryption.
│   └── yellow.py                Steganography (placeholder).
│
└── _keyx/                       Encrypted key management.
    ├── keyx.py                  Entry point: imports purplekeys and bluekeys.
    ├── purplekeys.py            Storage of name/key pairs.
    └── bluekeys/                Package for BLUE channel storage.
        ├── __init__.py          Imports keys and ckeys.
        ├── _common.py           Shared functions between keys and ckeys.
        ├── keys.py              Storage of standard BLUE channels.
        └── ckeys.py             Storage of critical (deniable) BLUE channels.
```


## Naming conventions

**Underscore prefix**: modules and folders starting with `_` are internal. They are not part of the public API. The user must never import directly from `_colorx`, `_keyx`, `_exceptions`, or `_black`. Everything is exposed via `pycryptox.__init__`.

**Namespace packages**: the `_colorx/`, `_keyx/`, and `_exceptions/` folders have no `__init__.py` file. Python 3.3+ treats them as "namespace packages", which allows relative imports without an initialization file. The only sub-package that has an `__init__.py` is `bluekeys/`, because it needs to export its `keys` and `ckeys` sub-modules.


## Public access

After installation via `pip install pycryptox`, the public API is accessible through the root module:

```python
import pycryptox as crx

crx.purple          # PURPLE protocol
crx.blue            # BLUE protocol
crx.red             # RED protocol
crx.yellow          # YELLOW protocol

crx.keyx.purplekeys             # PURPLE Keyx
crx.keyx.bluekeys.keys          # Standard BLUE Keyx
crx.keyx.bluekeys.ckeys         # Critical BLUE Keyx

crx.PycryptoxError                # Base exception
crx.DecryptionError             # Decryption failure
crx.EncryptionError             # Encryption failure
crx.KeyxError               # Keyx error
# ... etc.
```


## Data flow between protocols

```
PURPLE (standalone)
   Argon2id → 256-bit key → ChaCha20-Poly1305

BLACK (internal, never called directly)
   ML-KEM-512 encaps → 256-bit shared secret → ChaCha20-Poly1305

BLUE → uses BLACK
   Generates two sub-keys (x, y) via BLACK
   Pads both slots to a common bucket size, randomises slot order
   Provides plausible deniability

RED → uses BLACK
   Generates an ML-KEM-512 key via BLACK
   Splits the private key into N shares (Shamir GF(256))
   The bundle on the wire is identical to a BLACK bundle
```

PURPLE is fully independent — it does not use ML-KEM and does not depend on BLACK. It is the only protocol based on a memorable password.

BLACK is not a protocol exposed to the user. It is an internal module that encapsulates the ML-KEM-512 + ChaCha20-Poly1305 logic. BLUE and RED use it as a building block.


## Versioning system

Each public protocol (PURPLE, BLUE, RED, YELLOW) implements a **versioning system** embedded in the encrypted bundles.

### Version encoding

During encryption, the effective version is encoded in **2 bytes** (major, minor) prepended to the start of the bundle, before the final base64 encoding:

```
[1 byte: major] [1 byte: minor] [encrypted payload]
```

Each bundle carries its own version. Decryption extracts these 2 bytes, verifies that they match the version requested by the caller, and routes to the correct internal handler.

### Version specifier

The `version` parameter accepts two formats:

- **Exact version**: `"1.0"` → uses precisely version 1.0.
- **Major version**: `"1"` → resolves to the latest available minor for major 1 (currently `"1.0"`).

The major version is a convenience shortcut. It guarantees forward compatibility within a single major: a bundle encrypted with `"1.0"` will be accepted by `decrypt("1", ...)`.

### `getversion` function

Each public protocol exposes a `getversion(msg) -> str` function that extracts the version of a bundle without decrypting it. It returns a `"M.m"` string (e.g. `"1.0"`).

```python
version = crx.purple.getversion(bundle)  # → "1.0"
```

This function is useful for routing (knowing which protocol/version produced a bundle) or migration (converting bundles from one version to another).

### Limits

The major and minor values are unsigned bytes: from 0 to 255. This allows 256 × 256 = 65536 versions per protocol.

### Current versions

| Protocol | Stable version | Notes |
|---|---|---|
| PURPLE | 2.0 | Argon2id (adjustable: low/normal/strong/extreme) + ChaCha20-Poly1305 |
| BLUE | 2.0 | ML-KEM-512 + randomized slot order + bucket padding (up to 1 GiB) + async mode |
| RED | 1.0 | Shamir GF(256) + BLACK |
| YELLOW | 0.0 | Placeholder, non-functional |
| BLACK | 1.0 | Internal, no versioning in the bundle |

BLACK does not participate in the versioning system: its internal functions are called directly by BLUE and RED, and the bundle's version header is managed by the calling protocol.
