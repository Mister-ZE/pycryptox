# Protocole RED

RED est le protocole de chiffrement à seuil de Pycryptox. Il permet de chiffrer un message de telle sorte que le déchiffrement nécessite la coopération d'au moins `t` personnes parmi `n`. Aucune personne seule ne peut accéder au message.

RED est conçu pour les secrets partagés : clé de récupération d'un portefeuille, code d'accès à un coffre-fort, mot de passe d'un compte critique.


## Concept

RED combine deux primitives :

1. **ML-KEM-512 + ChaCha20-Poly1305 (via BLACK)** — pour le chiffrement du message.
2. **Partage de secret de Shamir dans GF(256)** — pour découper la clé privée ML-KEM-512 en `n` parts dont `t` suffisent à la reconstruire.

Le partage de secret de Shamir est un schéma à seuil basé sur l'interpolation polynomiale, inventé par Adi Shamir en 1979. Pour un seuil `t`, un polynôme aléatoire de degré `t-1` est généré, dont le terme constant est le secret. Chaque part est un point sur ce polynôme. Avec `t` points, le polynôme est uniquement déterminé par interpolation de Lagrange, et le terme constant (le secret) est récupérable. Avec `t-1` points ou moins, le secret reste informationnellement indéterminé : toutes les valeurs possibles du secret sont équiprobables.

L'implémentation de Pycryptox opère dans **GF(256)**, le corps fini (structure algébrique) à 256 éléments. Chaque octet de la clé privée ML-KEM-512 (1632 octets) est traité indépendamment. Les coefficients aléatoires du polynôme sont générés via `secrets.randbelow(256)` (CSPRNG du système).

Le message est chiffré une seule fois avec une clé publique ML-KEM-512 ordinaire via BLACK. La clé privée correspondante est ensuite découpée en `n` parts avec un seuil `t`. Pour déchiffrer, il suffit de réunir `t` parts (n'importe lesquelles parmi les `n`) pour reconstruire la clé privée et déchiffrer le bundle.

Sur le réseau, un bundle RED est identique à un bundle BLACK. La propriété de seuil est entièrement contenue dans le format des parts — elle n'est pas visible dans le ciphertext.


## Modèle "trusted dealer"

La version 1.0 de RED utilise un modèle de "trusted dealer" (donneur de confiance). Cela signifie que l'entité qui appelle `genkeys()` voit la clé privée ML-KEM-512 complète avant de la découper en parts, et que l'entité qui appelle `encrypt()` voit le message en clair. Ces deux entités doivent être de confiance et détruire leurs copies après utilisation.

Pycryptox effectue une destruction symbolique (réécriture par des zéros + `gc.collect()`), mais en Python, les objets `bytes` sont immuables et la zéroisation de la mémoire n'est pas garantie par le ramasse-miettes. Pour une garantie cryptographique de destruction, un module matériel serait nécessaire.


## API

### `crx.red.genkeys(version, t, n) -> dict`

Génère une clé publique et `n` parts de la clé privée.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"` ou `"1"`. |
| `t` | `int` | Seuil : nombre minimum de parts nécessaires au déchiffrement. |
| `n` | `int` | Nombre total de parts à générer. |
| **Retour** | `dict` | `{"gpubkey": str, "privkeys": [str, ...]}` |

**Contraintes** : `1 ≤ t ≤ n ≤ 255`.

Chaque élément de `privkeys` est une part encodée en base64url. En interne, chaque part est un blob de 1633 octets : 1 octet d'index (1..n) suivi des 1632 octets de la part Shamir.

**Exceptions** :
- `ArgumentTypeError` — si `t` ou `n` ne sont pas des `int` (les booléens sont rejetés).
- `EncryptionError` — si les contraintes `1 ≤ t ≤ n ≤ 255` ne sont pas respectées.
- `VersionNotFoundError` — si la version est inconnue.


### `crx.red.encrypt(version, gpubkey, msg) -> str`

Chiffre un message avec la clé publique RED.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"` ou `"1"`. |
| `gpubkey` | `str` | Clé publique (base64url, 800 octets bruts). |
| `msg` | `str` | Message en clair. |
| **Retour** | `str` | Bundle chiffré (base64url). |

Le chiffrement RED est strictement identique au chiffrement BLACK. La clé publique est une clé ML-KEM-512 ordinaire. La seule différence est que la clé privée correspondante a été découpée en parts lors du `genkeys`.

**Exceptions** :
- `ArgumentTypeError` — si `gpubkey` ou `msg` ne sont pas des `str`.
- `EncryptionError` — si la clé publique est invalide.


### `crx.red.decrypt(version, privkeys, msg) -> str`

Déchiffre un bundle RED en reconstruisant la clé privée à partir des parts.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version attendue. `"1.0"` ou `"1"`. |
| `privkeys` | `list[str]` | Liste de parts (chacune en base64url). Au moins `t` parts sont nécessaires. |
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Message en clair. |

**Comportement avec un nombre insuffisant de parts** : si moins de `t` parts sont fournies, la reconstruction de Lagrange produit une clé privée incorrecte. Le déchiffrement BLACK échoue alors sur le tag d'authentification Poly1305, ce qui lève un `DecryptionError`. L'erreur est indistinguable d'une clé invalide — l'attaquant ne peut pas savoir s'il manque des parts ou si les parts sont fausses.

**Exceptions** :
- `ArgumentTypeError` — si `privkeys` n'est pas une `list` ou si un élément n'est pas un `str`.
- `DecryptionError` — si les parts sont insuffisantes, invalides, corrompues, dupliquées, ou si la version ne correspond pas.


### `crx.red.getversion(msg) -> str`

Extrait la version d'un bundle RED sans le déchiffrer. Identique aux autres protocoles.


## Exemple complet

```python
import pycryptox as crx

# Scénario : 3 directeurs, seuil de 2
keys = crx.red.genkeys("1", t=2, n=3)

# Distribuer les parts
part_alice = keys["privkeys"][0]
part_bob   = keys["privkeys"][1]
part_carol = keys["privkeys"][2]

# Chiffrer le secret de l'entreprise
bundle = crx.red.encrypt("1", keys["gpubkey"], "Le mot de passe du coffre est XYZ-789")

# Alice et Carol se réunissent pour déchiffrer (2 parts sur 3)
secret = crx.red.decrypt("1", [part_alice, part_carol], bundle)
print(secret)  # → "Le mot de passe du coffre est XYZ-789"

# Bob seul ne peut pas déchiffrer (1 part sur 2 nécessaires)
try:
    crx.red.decrypt("1", [part_bob], bundle)
except crx.DecryptionError:
    print("Impossible avec une seule part")
```


## Cas limites

**t = 1** : toute part seule suffit. Équivalent à distribuer des copies complètes de la clé. Utile pour la redondance, pas pour la sécurité multi-parties.

**t = n** : toutes les parts sont nécessaires. Si une seule part est perdue, le secret est irrécupérable.

**Parts dupliquées** : si la même part est fournie deux fois dans `privkeys`, le déchiffrement lève un `DecryptionError("duplicate share indices")`.

**Parts de groupes différents** : si des parts provenant de deux `genkeys()` différents sont mélangées, la reconstruction produit une clé incorrecte et le déchiffrement échoue sur le tag Poly1305.


## Historique des versions

### Version 1.0 (stable)

Version actuelle, documentée dans les sections ci-dessus. Utilise Shamir GF(256) pour le partage de la clé privée ML-KEM-512, et BLACK pour le chiffrement du message.

### Version 0.0

Version initiale du protocole. Les fonctions retournent des réponses fixes sans effectuer d'opération cryptographique.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
