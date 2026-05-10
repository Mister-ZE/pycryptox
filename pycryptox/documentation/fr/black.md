# Protocole BLACK (interne)

BLACK est le protocole de chiffrement asymétrique de base de Pycryptox. Il n'est pas exposé dans l'API publique. Il est utilisé en interne par BLUE et RED.

Ce document est fourni pour la compréhension de l'architecture. L'utilisateur n'a jamais besoin d'appeler BLACK directement.


## Pourquoi BLACK est interne

BLACK n'est pas exposé pour préserver la **déniabilité plausible** du protocole BLUE.

Si BLACK était un protocole public, deux populations d'utilisateurs coexisteraient : ceux qui chiffrent avec BLACK (sans déniabilité) et ceux qui chiffrent avec BLUE (avec déniabilité). Un adversaire qui identifierait un bundle comme un bundle BLUE saurait immédiatement que l'expéditeur utilise la déniabilité — et donc qu'il a potentiellement quelque chose à cacher. La simple utilisation de BLUE deviendrait un signal.

En rendant BLACK interne et en forçant tout le chiffrement asymétrique à passer par BLUE, tous les utilisateurs produisent des bundles de même structure. Ceux qui n'ont pas besoin de déniabilité (mode mono) et ceux qui en ont besoin (mode dual) sont indistinguables. L'uniformité du protocole protège tout le monde.


## Primitives cryptographiques

| Composant | Algorithme | Détail |
|---|---|---|
| Encapsulation de clé (KEM) | ML-KEM-512 (FIPS 203) | Via liboqs (implémentation C, constant-time) |
| Chiffrement symétrique | ChaCha20-Poly1305 (AEAD) | Clé = shared secret ML-KEM (256 bits) |


## Fonctionnement

1. **Chiffrement** : encapsulation ML-KEM-512 avec la clé publique du destinataire → ciphertext KEM (768 octets) + shared secret (32 octets). Le message est chiffré avec ChaCha20-Poly1305 en utilisant le shared secret comme clé.

2. **Déchiffrement** : décapsulation ML-KEM-512 avec la clé privée → shared secret. Déchiffrement ChaCha20-Poly1305.

3. **Génération de clés** : appel à `oqs.KeyEncapsulation("ML-KEM-512").generate_keypair()`. Retourne `{"pubkey": str, "privkey": str}` en base64url.


## Format du ciphertext BLACK

```
[768 octets : ciphertext ML-KEM-512] [12 octets : nonce] [N octets : ciphertext ChaCha20-Poly1305 + tag]
```

Ce format est identique pour les bundles RED (qui sont des bundles BLACK dont la clé privée a été découpée en parts Shamir).


## Helper `_mlkem_keygen`

BLACK expose une fonction interne `_mlkem_keygen() -> tuple[bytes, bytes]` qui génère un keypair ML-KEM-512 brut (bytes). Cette fonction est utilisée par BLUE (pour les clés éphémères et les genkeys) et par RED (pour le keypair du trusted dealer). Elle centralise l'interaction avec liboqs pour que le changement de backend soit toujours une modification d'un seul fichier.


## Historique des versions

### Version 1.0 (stable)

Version actuelle, documentée ci-dessus. Utilise ML-KEM-512 via liboqs et ChaCha20-Poly1305.

BLACK ne participe pas au système de versioning des bundles (pas de header 2 octets dans le ciphertext). Le versioning est géré par le protocole appelant (BLUE ou RED), qui préfixe son propre version header avant de déléguer à BLACK.

### Version 0.0

Version initiale du protocole. Les fonctions retournent des réponses fixes sans effectuer d'opération cryptographique.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
