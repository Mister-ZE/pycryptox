# Installation

## Prerequisites

Pycryptox requires **Python 3.10** or higher.

Pycryptox depends on four external libraries:

| Dependency | Role | Why |
|---|---|---|
| `liboqs-python` | Python wrapper for liboqs (ML-KEM-512) | All asymmetric operations (BLACK, BLUE, RED) |
| `cryptography` | ChaCha20-Poly1305 (AEAD) | Symmetric encryption in all protocols |
| `argon2-cffi` | Argon2id (KDF) | Password-based key derivation (PURPLE, keyx) |
| `rapidfuzz` | Fuzzy search | `search()` function in Keyx (keyx) |

The `liboqs-python` dependency is the only one that requires a specific preparation step, because it relies on the C `liboqs` library to perform ML-KEM-512 operations. This C library is compiled automatically on the first `import oqs` if it is not already installed on the system.


## Installing liboqs-python

### System prerequisites (one-time setup)

The automatic compilation of liboqs requires a C compiler, CMake, and Git.

**Linux (Ubuntu/Debian)**:

```bash
sudo apt install build-essential cmake ninja-build git libssl-dev
```

**macOS**:

```bash
xcode-select --install
brew install cmake ninja
```

**Windows**:

1. Install **Visual Studio 2022 Build Tools** from https://visualstudio.microsoft.com/downloads/ ("Tools for Visual Studio" section). During installation, check the **"Desktop development with C++"** workload.
2. Install **CMake** from https://cmake.org/download/. During installation, check **"Add CMake to the system PATH for all users"**.
3. Install **Git** from https://git-scm.com/download/win if not already done.

An automated `install_pycryptox_pq.py` script is provided to automate these steps on Windows via `winget`.

### Installing the Python wrapper

```bash
pip install git+https://github.com/open-quantum-safe/liboqs-python@0.12.0
```

The first `import oqs` after this installation triggers the download and compilation of the liboqs C library. This operation takes 2 to 5 minutes and only happens once.


## Installing pycryptox

```bash
pip install pycryptox
```

The dependencies (`cryptography`, `argon2-cffi`, `rapidfuzz`) are installed automatically.


## Verification

After installation, verify that everything works:

```python
import pycryptox as crx

# Verify PURPLE (password)
ct = crx.purple.encrypt("1", "test", "hello")
assert crx.purple.decrypt("1", "test", ct) == "hello"
print("PURPLE OK")

# Verify BLUE (asymmetric)
keys = crx.blue.genkeys("1")
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="x", ymsg="y")
assert crx.blue.decrypt("1", keys["xprivkey"], bundle) == "x"
print("BLUE OK")

# Verify RED (threshold)
keys = crx.red.genkeys("1", 2, 3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "secret")
assert crx.red.decrypt("1", keys["privkeys"][:2], bundle) == "secret"
print("RED OK")
```

If all three lines display `OK`, the installation is complete.
