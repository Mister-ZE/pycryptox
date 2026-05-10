# Pycryptox

Post-quantum cryptography library for Python.

Four protocols, one goal: protect your data against today's threats and tomorrow's quantum computers.

| Protocol | What it does |
|---|---|
| **PURPLE** | Encrypt with a password |
| **BLUE** | Encrypt with asymmetric keys + plausible deniability |
| **RED** | Encrypt with a threshold (t-of-n) |
| **YELLOW** | Steganography *(coming soon)* |

```python
import pycryptox as crx

keys = crx.blue.genkeys("1")
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="real", ymsg="decoy")
crx.blue.decrypt("1", keys["xprivkey"], bundle)  # → "real"
crx.blue.decrypt("1", keys["yprivkey"], bundle)  # → "decoy"
```


## Prerequisites

Pycryptox uses [liboqs](https://github.com/open-quantum-safe/liboqs) (via `liboqs-python`) for all ML-KEM-512 post-quantum operations. This dependency is **not** installed automatically because the current PyPI release of `liboqs-python` is broken — it must be installed from GitHub:

```bash
pip install git+https://github.com/open-quantum-safe/liboqs-python@0.12.0
```

This requires a C compiler, CMake, and Git. The first `import oqs` automatically downloads and compiles the liboqs C library (~2-5 min, one-time only). See [installation guide](pycryptox/documentation/en/installation.md) for platform-specific instructions.


## Installation

```bash
pip install pycryptox
```


## Documentation

📖 [English](pycryptox/documentation/en/INDEX.md) · [Français](pycryptox/documentation/fr/INDEX.md)


## Tests

🧪 [Test suite](pycryptox/tests/) — 162 tests covering all protocols and keystores.

```bash
cd pycryptox/tests
python run_all.py
```


## Credits

See [CREDITS.md](pycryptox/CREDITS.md)
