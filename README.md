# Pycryptox

**Post-quantum cryptography, plausible deniability, secure software, secure hardware, and more.**

Pycryptox is a Python library that takes cryptographic engineering seriously. Every primitive choice, every wire format, every API decision is documented and motivated against a concrete threat model. The goal is not "encrypt this for me" — it is "protect this against the adversary I am actually worried about, today and after a quantum computer arrives."

```python
import pycryptox as crx

keys = crx.blue.genkeys("2")
bundle = crx.blue.encrypt("2", keys["gpubkey"], xmsg="real message", ymsg="credible decoy")

# Same bundle, two recipients, two different plaintexts:
crx.blue.decrypt("2", keys["xprivkey"], bundle, slot="x")  # → "real message"
crx.blue.decrypt("2", keys["yprivkey"], bundle, slot="y")  # → "credible decoy"

# Under coercion, the user reveals only yprivkey. The adversary obtains the
# decoy, has no cryptographic way to prove the real message exists, and the
# real key is physically elsewhere on a separate device. This is BLUE.
```


## What is in the box

| Protocol | What it does | Primary use |
|---|---|---|
| **PURPLE** | Password-based encryption with adjustable Argon2id strength | Brain-only secrets you can recover from a passphrase alone |
| **BLUE** | Deniable asymmetric encryption with plausible-deniability dual-channel | Sensitive content where coercion is a realistic threat |
| **RED** | Threshold encryption (t-of-n secret sharing) | Distributed trust, recovery shares, multi-party access |
| **YELLOW** | Steganography *(placeholder, coming soon)* | Concealing the existence of a message itself |
| **Keyx** | Self-contained key storage with two trust tiers (`keys` / `ckeys`) | On-device persistence with physical separation of critical keys |

All asymmetric work is post-quantum from day one: **ML-KEM-512 (FIPS 203)** via [liboqs](https://github.com/open-quantum-safe/liboqs) handles every key encapsulation, and **ChaCha20-Poly1305** handles every symmetric step. No RSA, no ECC, no classical Diffie-Hellman.


## Why a serious project

This is not a hobby toy. Pycryptox was designed for cases where getting the threat model wrong has real consequences: journalists protecting sources, activists under surveillance, custody of long-term secrets that must outlive today's cryptanalytic state. The library is honest about what it does and does not protect against — every protocol has a dedicated **Me vs Opponent** section in its documentation that walks through the attacks a competent adversary will try, the design decision that defeats each one, and the attacks that are explicitly out of scope.

The codebase reflects that posture:
- Versioning is mandatory: every bundle carries its protocol version, every migration is explicit through `update_bundle`.
- Old versions are frozen byte-for-byte after release. Cryptanalysis of a deployed version cannot be silently patched away.
- Bundle structures are exhaustively documented down to the byte.
- 264+ tests covering all protocols, Keyx storage, version dispatch, and error paths.


## Feedback I am looking for

This library is maintained by a single person under the Cryptox identity, and I want **serious feedback** to improve it: cryptanalysis attempts on the protocols, threat-model holes, API criticism, documentation clarity, performance issues on real workloads. Send anything substantive to:

**📧 [z.e.pro@outlook.fr](mailto:z.e.pro@outlook.fr)**

I read everything. I will not always agree, but I will engage. The library is at its best when it is challenged.


## Proposing features

If you have a use case Pycryptox does not yet cover, or a protocol idea that fits the project's posture (post-quantum, deniability-aware, explicit threat model), I am open to discussion. Same address: **[z.e.pro@outlook.fr](mailto:z.e.pro@outlook.fr)**. Please describe:

1. The threat model (what is the adversary, what are their capabilities, what do they want)
2. The use case (who needs this, in what context)
3. The deniability / security properties you would expect

I will not implement features without a clear motivation, but a good motivation goes a long way.


## Prerequisites

Pycryptox uses [liboqs](https://github.com/open-quantum-safe/liboqs) (via `liboqs-python`) for all ML-KEM-512 post-quantum operations. This dependency is **not** installed automatically because the current PyPI release of `liboqs-python` is broken — it must be installed from GitHub:

```bash
pip install git+https://github.com/open-quantum-safe/liboqs-python@0.12.0
```

This requires a C compiler, CMake, and Git. The first `import oqs` automatically downloads and compiles the liboqs C library (~2-5 min, one-time only). See the [installation guide](pycryptox/documentation/en/installation.md) for platform-specific instructions.


## Installation

```bash
pip install pycryptox
```


## Documentation

📖 [English](pycryptox/documentation/en/INDEX.md) · [Français](pycryptox/documentation/fr/INDEX.md)

Each protocol has its own document with cryptographic primitives, wire format, threat model (**Me vs Opponent**), API reference, complete examples, and version history.


## Tests

🧪 [Test suite](pycryptox/tests/) — 269 tests covering all protocols and Keyx.

```bash
cd pycryptox/tests
python run_all.py
```


## Acknowledgments

📜 See [THANKS.md](THANKS.md) — Pycryptox builds on the work of Open Quantum Safe, PyCA, the Argon2 team, the EFF, and many others.


## Credits

See [CREDITS.md](pycryptox/CREDITS.md)


## License

MIT — see [LICENSE](LICENSE).
