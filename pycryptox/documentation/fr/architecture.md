# Architecture

## Arborescence

```
pycryptox/
├── __init__.py                  Expose purple, blue, red, yellow, keyx, et les exceptions.
├── README.md
├── CREDITS.md
│
├── _assets/
│   └── words.txt                Liste de mots EFF pour la génération de passphrases (PURPLE).
│
├── _exceptions/
│   └── _exceptions.py           Toutes les classes d'exception de Pycryptox.
│
├── _colorx/                     Les protocoles de chiffrement.
│   ├── _black.py                Protocole interne (ML-KEM-512 + ChaCha20-Poly1305).
│   ├── purple.py                Chiffrement par mot de passe.
│   ├── blue.py                  Chiffrement asymétrique déniable.
│   ├── red.py                   Chiffrement à seuil.
│   └── yellow.py                Stéganographie (placeholder).
│
└── _keyx/                       Gestion de clés chiffrées.
    ├── keyx.py                  Point d'entrée : importe purplekeys et bluekeys.
    ├── purplekeys.py            Stockage de paires nom/clé.
    └── bluekeys/                Package pour le stockage de canaux BLUE.
        ├── __init__.py          Importe keys et ckeys.
        ├── _common.py           Fonctions partagées entre keys et ckeys.
        ├── keys.py              Stockage de canaux BLUE standard.
        └── ckeys.py             Stockage de canaux BLUE critiques (deniable).
```


## Conventions de nommage

**Préfixe underscore** : les modules et dossiers qui commencent par `_` sont internes. Ils ne font pas partie de l'API publique. L'utilisateur ne doit jamais importer directement depuis `_colorx`, `_keyx`, `_exceptions` ou `_black`. Tout est exposé via `pycryptox.__init__`.

**Namespace packages** : les dossiers `_colorx/`, `_keyx/` et `_exceptions/` n'ont pas de fichier `__init__.py`. Python 3.3+ les traite comme des "namespace packages", ce qui permet les imports relatifs sans fichier d'initialisation. Le seul sous-package qui possède un `__init__.py` est `bluekeys/`, parce qu'il a besoin d'exporter ses sous-modules `keys` et `ckeys`.


## Accès public

Après installation via `pip install pycryptox`, l'API publique est accessible via le module racine :

```python
import pycryptox as crx

crx.purple          # Protocole PURPLE
crx.blue            # Protocole BLUE
crx.red             # Protocole RED
crx.yellow          # Protocole YELLOW

crx.keyx.purplekeys             # Keystore PURPLE
crx.keyx.bluekeys.keys          # Keystore BLUE standard
crx.keyx.bluekeys.ckeys         # Keystore BLUE critique

crx.PycryptoxError                # Exception de base
crx.DecryptionError             # Échec de déchiffrement
crx.EncryptionError             # Échec de chiffrement
crx.KeystoreError               # Erreur de keystore
# ... etc.
```


## Flux de données entre protocoles

```
PURPLE (autonome)
   Argon2id → clé 256 bits → ChaCha20-Poly1305

BLACK (interne, jamais appelé directement)
   ML-KEM-512 encaps → shared secret 256 bits → ChaCha20-Poly1305

BLUE → utilise BLACK
   Génère deux sous-clés (x, y) via BLACK
   Mélange les ciphertexts avec du bruit (chemical key mixing)
   Offre la déniabilité plausible

RED → utilise BLACK
   Génère une clé ML-KEM-512 via BLACK
   Découpe la clé privée en N parts (Shamir GF(256))
   Le bundle sur le fil est identique à un bundle BLACK
```

PURPLE est totalement indépendant — il n'utilise pas ML-KEM et ne dépend pas de BLACK. Il est le seul protocole à reposer sur un mot de passe mémorisable.

BLACK n'est pas un protocole exposé à l'utilisateur. C'est un module interne qui encapsule la logique ML-KEM-512 + ChaCha20-Poly1305. BLUE et RED l'utilisent comme brique de base.


## Système de versioning

Chaque protocole public (PURPLE, BLUE, RED, YELLOW) implémente un **système de versioning** intégré dans les bundles chiffrés.

### Encodage de la version

Lors du chiffrement, la version effective est encodée en **2 octets** (major, minor) préfixés au début du bundle, avant l'encodage base64 final :

```
[1 octet : major] [1 octet : minor] [payload chiffré]
```

Chaque bundle porte sa propre version. Le déchiffrement extrait ces 2 octets, vérifie qu'ils correspondent à la version demandée par l'appelant, et route vers le bon handler interne.

### Spécificateur de version

Le paramètre `version` accepte deux formats :

- **Version exacte** : `"1.0"` → utilise précisément la version 1.0.
- **Version majeure** : `"1"` → résout vers la dernière mineure disponible pour la majeure 1 (actuellement `"1.0"`).

La version majeure est un raccourci de commodité. Elle garantit la compatibilité ascendante au sein d'une même majeure : un bundle chiffré avec `"1.0"` sera accepté par un `decrypt("1", ...)`.

### Fonction `getversion`

Chaque protocole public expose une fonction `getversion(msg) -> str` qui extrait la version d'un bundle sans le déchiffrer. Elle renvoie une chaîne `"M.m"` (par exemple `"1.0"`).

```python
version = crx.purple.getversion(bundle)  # → "1.0"
```

Cette fonction est utile pour le routage (savoir quel protocole/version a produit un bundle) ou la migration (convertir des bundles d'une version à une autre).

### Limites

Les valeurs de major et minor sont des octets non signés : de 0 à 255. Cela autorise 256 × 256 = 65536 versions par protocole.

### Versions actuelles

| Protocole | Version stable | Notes |
|---|---|---|
| PURPLE | 1.0 | Argon2id + ChaCha20-Poly1305 |
| BLUE | 1.0 | ML-KEM-512 + chemical key mixing |
| RED | 1.0 | Shamir GF(256) + BLACK |
| YELLOW | 0.0 | Placeholder, non fonctionnel |
| BLACK | 1.0 | Interne, pas de versioning dans le bundle |

BLACK ne participe pas au système de versioning : ses fonctions internes sont appelées directement par BLUE et RED, et le version header du bundle est géré par le protocole appelant.
