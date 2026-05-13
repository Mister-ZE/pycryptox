# Protocole BLUE

BLUE est le protocole de chiffrement asymétrique déniable de Pycryptox. Il permet à l'expéditeur de chiffrer deux messages dans un seul bundle : un message réel et un leurre. Le destinataire peut déchiffrer l'un ou l'autre selon la clé privée qu'il utilise. Un adversaire qui force la révélation d'une clé privée obtient un message — mais ne peut pas prouver qu'un autre message existe dans le même bundle.

BLUE est le protocole le plus puissant de Pycryptox.


## Concept : double canal x/y

Chaque trousseau BLUE contient trois clés :

- **`gpubkey`** — clé publique composite (concaténation de deux clés publiques ML-KEM-512).
- **`xprivkey`** — clé privée du canal x.
- **`yprivkey`** — clé privée du canal y.

Lors du chiffrement, l'expéditeur fournit un message pour le canal x (`xmsg`), un message pour le canal y (`ymsg`), ou les deux. Les deux messages sont chiffrés indépendamment via le protocole BLACK, puis leurs octets sont **mélangés** avec du bruit aléatoire dans un seul bundle monolithique.

La position de chaque octet dans le mélange est enregistrée dans une "clé chimique" (chemical key), elle-même chiffrée avec la clé publique du canal correspondant. Le destinataire déchiffre sa clé chimique, extrait ses octets du mélange, et déchiffre son message.


## Pourquoi un adversaire ne peut pas distinguer les canaux

La déniabilité de BLUE repose sur une série de décisions de conception qui, ensemble, rendent le bundle opaque. Chacune résout un problème spécifique qui, s'il n'était pas traité, trahirait l'existence de deux canaux.

**Problème 1 : la taille du message peut trahir le contenu.** Si les deux messages avaient des tailles différentes dans le bundle, un adversaire pourrait déduire quel canal contient le vrai message (le plus long, ou le plus court, selon le contexte). Solution : chaque message est **rembourré (padded) à une taille fixe** déterminée par un bucket. Les deux messages doivent tomber dans le même bucket, sinon le chiffrement est refusé. Après padding, les deux ciphertexts ont exactement la même taille.

**Problème 2 : deux ciphertexts côte à côte seraient reconnaissables.** Si le bundle contenait simplement `[ciphertext_x][ciphertext_y]`, un observateur verrait deux blocs distincts de taille identique — une structure suspecte. Solution : les octets des deux ciphertexts sont **mélangés aléatoirement** avec des octets de bruit dans un seul blob (chemical key mixing). Le résultat est un flux d'octets sans structure visible.

**Problème 3 : un seul message produirait un bundle plus court.** Si un seul canal contenait un vrai message et l'autre était vide, la taille du bundle serait moitié moindre, ce qui prouverait qu'un seul canal est utilisé. Solution : en mode mono (un seul message fourni), le protocole génère une **clé ML-KEM-512 éphémère** pour le canal manquant, chiffre du bruit aléatoire de la même taille que le vrai message, puis **détruit la clé privée éphémère**. Le bundle contient toujours deux ciphertexts de même taille, indistinguable d'un bundle dual.

**Problème 4 : l'en-tête du bundle pourrait révéler les tailles.** Le bundle contient en clair la taille des clés chimiques chiffrées (`len_xchem` et `len_ychem`). Si ces tailles étaient différentes, elles trahiraient la taille de chaque ciphertext. Solution : puisque les deux ciphertexts sont de taille identique (même bucket), les deux clés chimiques contiennent le même nombre de positions, donc `len_xchem == len_ychem` dans tous les cas.

**Problème 5 : des bundles identiques pour un même message seraient corrélables.** Solution : un bruit aléatoire de taille variable (entre 100 et 9000 octets) est ajouté au mélange. Chaque bundle a une taille non déterministe, même pour des messages identiques.

Le résultat : un adversaire qui examine un bundle BLUE voit un blob d'octets de taille variable, sans structure, sans marqueur, sans moyen de savoir s'il contient un ou deux messages. Même avec la clé d'un canal, il ne peut pas prouver l'existence de l'autre.


## Déniabilité plausible

### Scénario de base

Alice veut envoyer un message confidentiel à Bob. Elle sait qu'un adversaire pourrait un jour la forcer à révéler sa clé.

1. Alice génère un trousseau BLUE : `gpubkey`, `xprivkey`, `yprivkey`.
2. Elle chiffre le vrai message sur le canal x et un leurre crédible sur le canal y.
3. Elle stocke `yprivkey` (la clé leurre) dans son Keyx principal (`keyx.bluekeys.keys`, sur sa machine).
4. Elle stocke `xprivkey` (la vraie clé) dans un Keyx séparé (`keyx.bluekeys.ckeys`, sur une clé USB qu'elle garde ailleurs).

### Scénario de coercition

Un adversaire contraint Alice à ouvrir son Keyx. Alice ouvre `channels.keys`, qui contient `yprivkey`. L'adversaire déchiffre le bundle et obtient le leurre. Il ne peut pas prouver que le canal x existe : le bundle qu'il voit est un blob opaque, et `yprivkey` produit un message crédible.

La clé USB contenant `xprivkey` est physiquement absente. L'adversaire ne sait même pas qu'elle existe.

### Scénario sans déniabilité

Si Alice n'a pas besoin de déniabilité, elle utilise BLUE en mode mono :

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="message confidentiel")
```

Elle ne stocke que `xprivkey`, pas de `ckeys`, pas de leurre. BLUE fonctionne alors comme un chiffrement asymétrique classique, mais avec la même structure de bundle indistinguable.

### Pourquoi tout le monde doit utiliser BLUE (et pas BLACK directement)

Si BLACK était exposé comme protocole public, deux populations d'utilisateurs coexisteraient : ceux qui utilisent BLACK (pas de déniabilité) et ceux qui utilisent BLUE (déniabilité). Un adversaire qui voit un bundle BLUE saurait immédiatement que l'utilisateur a potentiellement quelque chose à cacher — sinon il aurait utilisé BLACK.

En rendant BLACK interne et en forçant tout le chiffrement asymétrique à passer par BLUE, tous les bundles ont la même structure. Les utilisateurs qui n'ont pas besoin de déniabilité et ceux qui en ont besoin produisent des bundles identiques. L'adversaire ne peut pas les distinguer.


## Primitives cryptographiques (v1.0)

| Composant | Algorithme |
|---|---|
| Encapsulation de clé | ML-KEM-512 (FIPS 203) via BLACK |
| Chiffrement symétrique | ChaCha20-Poly1305 via BLACK |
| Mélange (chemical mixing) | Permutation aléatoire (secrets.SystemRandom) |
| Padding | Buckets de taille fixe |


## Padding

Pour éviter que la taille du message trahisse son contenu, chaque message est rembourré (padded) jusqu'à la taille du plus petit bucket qui peut le contenir.

Buckets disponibles (v1.0) :

| Bucket | Taille |
|---|---|
| 1 | 4 Ko |
| 2 | 16 Ko |
| 3 | 64 Ko |
| 4 | 256 Ko |
| 5 | 1 Mo |

Le format paddé est :

```
[4 octets : longueur du message] [message] [octets aléatoires de remplissage]
```

Si les deux messages (x et y) sont fournis, ils doivent être dans le **même bucket**. Sinon, la différence de taille de ciphertext briserait la déniabilité. Si les deux messages ne tiennent pas dans le même bucket, `encrypt` lève un `EncryptionError`.

Limite actuelle : le bucket maximum est 1 Mo. Les messages plus longs ne sont pas supportés en v1.0.


## Modes de chiffrement

### Mode dual (x et y)

L'expéditeur fournit les deux messages. Les deux sont chiffrés et mélangés dans le bundle.

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="réel", ymsg="leurre")
```

### Mode mono-x (x seul)

L'expéditeur ne fournit que `xmsg`. Le protocole génère une paire de clés ML-KEM-512 **éphémère** pour le canal y, chiffre du bruit aléatoire comme `ymsg`, puis détruit la clé privée éphémère. Le canal y est alors physiquement indéchiffrable — même par l'expéditeur. Le bundle reste indistinguable d'un bundle dual.

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="message réel")
```

### Mode mono-y (y seul)

Identique au mono-x, mais inversé : le canal x contient du bruit indéchiffrable.

```python
bundle = crx.blue.encrypt("1", keys["gpubkey"], ymsg="message réel")
```


## API

### `crx.blue.encrypt(version, gpubkey, xmsg=None, ymsg=None) -> str`

Chiffre un ou deux messages dans un bundle BLUE.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"` ou `"1"`. |
| `gpubkey` | `str` | Clé publique composite (base64url, 1600 octets bruts). |
| `xmsg` | `str \| None` | Message pour le canal x. `None` si non utilisé. |
| `ymsg` | `str \| None` | Message pour le canal y. `None` si non utilisé. |
| **Retour** | `str` | Bundle chiffré (base64url). |

Au moins un des deux messages (`xmsg` ou `ymsg`) doit être fourni. Si les deux sont fournis, ils doivent tenir dans le même bucket de padding.

**Exceptions** :
- `ArgumentTypeError` — si un argument n'est pas du bon type.
- `EncryptionError` — si aucun message n'est fourni, si la `gpubkey` est invalide, si les messages ne tiennent pas dans le même bucket, ou si un message dépasse 1 Mo.
- `VersionNotFoundError` — si la version est inconnue.

### `crx.blue.decrypt(version, privkey, msg) -> str`

Déchiffre un bundle BLUE avec une clé privée (x ou y).

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version attendue. `"1.0"` ou `"1"`. |
| `privkey` | `str` | Clé privée du canal x (`xprivkey`) ou y (`yprivkey`). |
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Message en clair correspondant au canal de la clé fournie. |

Le protocole essaie automatiquement les deux canaux (x puis y). Il retourne le message du premier canal qui déchiffre correctement. L'appelant n'a pas besoin de spécifier s'il utilise xprivkey ou yprivkey — le protocole le détecte.

**Exceptions** :
- `ArgumentTypeError` — si `privkey` ou `msg` ne sont pas des `str`.
- `DecryptionError` — si la clé ne correspond à aucun canal, le bundle est corrompu, ou la version ne correspond pas.

### `crx.blue.genkeys(version) -> dict[str, str]`

Génère un trousseau de clés BLUE.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"1.0"` ou `"1"`. |
| **Retour** | `dict` | `{"gpubkey": str, "xprivkey": str, "yprivkey": str}` |

La `gpubkey` est la concaténation de deux clés publiques ML-KEM-512 (800 + 800 = 1600 octets bruts, encodés en base64url).

### `crx.blue.getversion(msg) -> str`

Extrait la version d'un bundle BLUE sans le déchiffrer.

| Paramètre | Type | Description |
|---|---|---|
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Version au format `"M.m"`. |


## Structure du bundle (v1.0)

Le bundle brut (après retrait des 2 octets de version et avant encodage base64) :

```
[4 octets : len(enc_xchemkey)]
[4 octets : len(enc_ychemkey)]
[enc_xchemkey]                    → clé chimique x, chiffrée via BLACK avec xpubkey
[enc_ychemkey]                    → clé chimique y, chiffrée via BLACK avec ypubkey
[mixmsg]                          → mélange de enc_xmsg + enc_ymsg + bruit
```

Les clés chimiques contiennent les positions (indices dans `mixmsg`) des octets de chaque canal, encodées en big-endian 4 octets par position.


## Considérations de sécurité

**Oracle de déchiffrement** : les applications utilisant BLUE doivent éviter d'exposer le statut succès/échec du déchiffrement à des parties non authentifiées. La portion de bruit du bundle n'est pas authentifiée. Un oracle de déchiffrement pourrait être utilisé pour cartographier les positions des clés chimiques sur de nombreux essais.

**Crédibilité du leurre** : la déniabilité est inutile si le message leurre n'est pas crédible. Un leurre vide ou absurde ("test", "rien") ne convaincra personne. Le leurre doit ressembler à un vrai message que l'utilisateur aurait raisonnablement envoyé.

**Séparation physique des clés** : la déniabilité suppose que l'adversaire n'a accès qu'à une seule clé privée. Si les deux clés (`xprivkey` et `yprivkey`) sont stockées au même endroit, l'adversaire les trouve toutes les deux et la déniabilité est nulle. Le système keyx fournit deux Keyx séparés (`keys` et `ckeys`) exactement pour cette raison.

**Métadonnées non protégées** : BLUE protège le contenu des messages, pas les métadonnées. L'heure d'envoi, la fréquence des échanges, l'identité de l'expéditeur et du destinataire ne sont pas dissimulées par BLUE. Pour masquer ces métadonnées, une couche supplémentaire (réseau anonyme, stéganographie via YELLOW) est nécessaire.

**Taille du bundle** : la taille du bundle peut révéler dans quel bucket le message se trouve, et donc une plage de taille approximative du message (0-4 Ko, 4-16 Ko, etc.). Elle ne révèle pas la taille exacte du message au sein du bucket.


## Exemple complet

```python
import pycryptox as crx

# Générer un trousseau de clés
keys = crx.blue.genkeys("1")

# Chiffrement dual (message réel + leurre)
bundle = crx.blue.encrypt("1", keys["gpubkey"],
                          xmsg="Coordonnées GPS du point de rendez-vous : 48.8566, 2.3522",
                          ymsg="Pas de nouvelles, tout va bien.")

# Le destinataire déchiffre avec xprivkey → message réel
real = crx.blue.decrypt("1", keys["xprivkey"], bundle)
print(real)  # → "Coordonnées GPS du point de rendez-vous : 48.8566, 2.3522"

# Sous coercition, il donne yprivkey → leurre crédible
decoy = crx.blue.decrypt("1", keys["yprivkey"], bundle)
print(decoy)  # → "Pas de nouvelles, tout va bien."

# Chiffrement mono (pas de déniabilité nécessaire)
bundle_mono = crx.blue.encrypt("1", keys["gpubkey"], xmsg="Message simple")
plain = crx.blue.decrypt("1", keys["xprivkey"], bundle_mono)
print(plain)  # → "Message simple"

# Extraire la version sans déchiffrer
version = crx.blue.getversion(bundle)
print(version)  # → "1.0"
```


## Historique des versions

### Version 1.0 (stable)

Version actuelle, documentée dans les sections ci-dessus. Utilise ML-KEM-512 via BLACK, padding par buckets, chemical key mixing.

### Version 0.0

Version initiale du protocole. Les fonctions retournent des réponses fixes sans effectuer d'opération cryptographique.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
