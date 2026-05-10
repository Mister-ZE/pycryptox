# Installation

## Prérequis

Pycryptox nécessite **Python 3.10** ou supérieur.

Pycryptox dépend de quatre bibliothèques externes :

| Dépendance | Rôle | Pourquoi |
|---|---|---|
| `liboqs-python` | Wrapper Python pour liboqs (ML-KEM-512) | Toutes les opérations asymétriques (BLACK, BLUE, RED) |
| `cryptography` | ChaCha20-Poly1305 (AEAD) | Chiffrement symétrique dans tous les protocoles |
| `argon2-cffi` | Argon2id (KDF) | Dérivation de clé par mot de passe (PURPLE, keyx) |
| `rapidfuzz` | Recherche floue | Fonction `search()` dans les keystores (keyx) |

La dépendance `liboqs-python` est la seule qui demande une étape de préparation spécifique, car elle s'appuie sur la bibliothèque C `liboqs` pour effectuer les opérations ML-KEM-512. Cette bibliothèque C est compilée automatiquement lors du premier `import oqs` si elle n'est pas déjà installée sur le système.


## Installation de liboqs-python

### Prérequis système (à faire une seule fois)

La compilation automatique de liboqs nécessite un compilateur C, CMake et Git.

**Linux (Ubuntu/Debian)** :

```bash
sudo apt install build-essential cmake ninja-build git libssl-dev
```

**macOS** :

```bash
xcode-select --install
brew install cmake ninja
```

**Windows** :

1. Installer **Visual Studio 2022 Build Tools** depuis https://visualstudio.microsoft.com/downloads/ (section "Tools for Visual Studio"). Pendant l'installation, cocher la charge de travail **"Desktop development with C++"**.
2. Installer **CMake** depuis https://cmake.org/download/. Pendant l'installation, cocher **"Add CMake to the system PATH for all users"**.
3. Installer **Git** depuis https://git-scm.com/download/win si ce n'est pas déjà fait.

Un script automatisé `install_pycryptox_pq.py` est fourni pour automatiser ces étapes sur Windows via `winget`.

### Installation du wrapper Python

```bash
pip install git+https://github.com/open-quantum-safe/liboqs-python@0.12.0
```

Le premier `import oqs` après cette installation déclenche le téléchargement et la compilation de la bibliothèque C liboqs. Cette opération prend 2 à 5 minutes et ne se produit qu'une seule fois.


## Installation de Pycryptox

```bash
pip install pycryptox
```

Les dépendances (`cryptography`, `argon2-cffi`, `rapidfuzz`) sont installées automatiquement.


## Vérification

Après installation, vérifier que tout fonctionne :

```python
import pycryptox as crx

# Vérifier PURPLE (mot de passe)
ct = crx.purple.encrypt("1", "test", "hello")
assert crx.purple.decrypt("1", "test", ct) == "hello"
print("PURPLE OK")

# Vérifier BLUE (asymétrique)
keys = crx.blue.genkeys("1")
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="x", ymsg="y")
assert crx.blue.decrypt("1", keys["xprivkey"], bundle) == "x"
print("BLUE OK")

# Vérifier RED (seuil)
keys = crx.red.genkeys("1", 2, 3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "secret")
assert crx.red.decrypt("1", keys["privkeys"][:2], bundle) == "secret"
print("RED OK")
```

Si les trois lignes affichent `OK`, l'installation est complète.
