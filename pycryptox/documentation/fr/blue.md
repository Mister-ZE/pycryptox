# Protocole BLUE

BLUE est le protocole de chiffrement asymétrique déniable de Pycryptox. Il permet à l'expéditeur de chiffrer deux messages dans un seul bundle : un message réel et un leurre. Le destinataire peut déchiffrer l'un ou l'autre selon la clé privée qu'il utilise. Un adversaire qui force la révélation d'une clé privée obtient un message — mais ne peut pas prouver qu'un autre message existe dans le même bundle.

BLUE est le protocole le plus puissant de Pycryptox.


## Concept : double canal x/y

Chaque trousseau BLUE contient trois clés :

- **`gpubkey`** — clé publique composite (concaténation de deux clés publiques ML-KEM-512).
- **`xprivkey`** — clé privée du canal x.
- **`yprivkey`** — clé privée du canal y.

Lors du chiffrement, l'expéditeur fournit un message pour le canal x (`xmsg`), un message pour le canal y (`ymsg`), ou les deux. Les deux messages sont chiffrés indépendamment via le protocole BLACK avec la clé publique du canal correspondant, puis concaténés dans un seul bundle avec un ordre de slot randomisé.


## Moi vs Adversaire : scénarios d'attaque et défenses

La déniabilité de BLUE repose sur une série de décisions de conception. La façon la plus claire de motiver chacune est de penser d'abord comme un attaquant : choisir une attaque qui exposerait le canal caché, puis décrire le choix de conception qui la défait. Les quatre attaques ci-dessous sont celles qu'un adversaire compétent essayera réellement sur un bundle BLUE.

### Attaque 1 — Corrélation par la taille du message

> **Raisonnement de l'attaquant.** « Les deux messages n'ont probablement pas la même longueur. Le 'vrai' message est le plus informatif, c'est-à-dire généralement le plus long (il porte du contenu, pas juste un placeholder). Si je peux voir deux tailles de ciphertexts distinctes dans le bundle, je sais quel slot est le vrai. »

**Défense.** Chaque message est **rembourré à une taille de bucket fixe** avant chiffrement. v2.0 offre huit buckets (4 Ko, 16 Ko, 64 Ko, 256 Ko, 1 Mo, 16 Mo, 256 Mo, 1 Gio). Si `xmsg` et `ymsg` ne tiennent pas dans le même bucket, le chiffrement est refusé (`EncryptionError`). Après padding, les deux ciphertexts BLACK ont **exactement la même longueur en octets**. L'attaquant ne peut pas les distinguer par la taille.

### Attaque 2 — Oracle de timing au déchiffrement

> **Raisonnement de l'attaquant.** « Si le bundle est toujours `[enc_x][enc_y]` dans cet ordre, alors un destinataire qui détient `xprivkey` déchiffre directement le premier slot (≈ 1 décap KEM), tandis qu'un destinataire qui détient `yprivkey` doit sauter le premier et déchiffrer le second (≈ 2 décaps, ou une logique supplémentaire qui télégraphie le choix). En mesurant combien de temps prend le déchiffrement — par le réseau, ou via un canal auxiliaire — je peux corréler le timing avec la clé que le destinataire détient. Après assez d'observations, je sais quel côté est le 'vrai' canal pour cet utilisateur. »

**Défense.** L'**ordre des slots est randomisé au moment du chiffrement** via `secrets.randbits(1)` et stocké dans un `order_flag` d'1 octet en clair. Chaque nouveau chiffrement inverse l'ordre indépendamment. Un destinataire lit le flag, identifie le slot correspondant à sa clé, et déchiffre ce slot uniquement avec un travail constant (1 décap KEM + 1 vérification AEAD). Sur de nombreux bundles, la distribution moitié/moitié du flag rend le temps cumulé symétrique pour les deux canaux : une observation de timing externe ne révèle rien sur le canal détenu par le destinataire.

### Attaque 3 — Détection du mode mono par la taille du bundle

> **Raisonnement de l'attaquant.** « Si seul un des deux canaux a réellement été utilisé (mode mono), le bundle fait probablement la moitié de la taille d'un dual — un seul ciphertext BLACK plus quelques métadonnées. Si je vois un bundle BLUE 'court', je sais que le mode mono a été utilisé ; si j'en vois un 'long', je sais que c'est le mode dual. Le mode mono me dit qu'il n'y a pas de leurre, ce qui signifie que ce qu'il y a dedans est la seule chose qui vaille la peine de contraindre l'utilisateur à révéler. »

**Défense.** En mode mono, le protocole **génère une paire de clés ML-KEM-512 éphémère** pour le côté inutilisé, chiffre des octets uniformément aléatoires de la même longueur que le vrai message, puis **détruit immédiatement la clé privée éphémère**. Le bundle résultant est structurellement identique octet par octet à un bundle dual : deux ciphertexts BLACK complets de taille égale, un flag d'ordre, un préfixe de longueur. Aucun observateur externe ne peut distinguer un bundle mono d'un bundle dual. (Même l'expéditeur ne peut pas déchiffrer le slot leurre par la suite — la clé privée éphémère a disparu.)

### Attaque 4 — Empreinte structurelle du bundle

> **Raisonnement de l'attaquant.** « Les blobs chiffrés ont souvent une structure reconnaissable : positions des tags, motifs d'alignement, magic bytes pour ML-KEM et AEAD à l'intérieur des ciphertexts. Si je vois deux blocs côte à côte avec des en-têtes BLACK identifiables à leurs frontières, je peux confirmer que le bundle utilise le pattern dual-canal de BLUE, même si je ne peux pas lire le contenu. À lui seul cela est incriminant dans certains contextes (le simple acte d'utiliser du chiffrement déniable est suspect). »

**Défense.** Chaque ciphertext BLACK est lui-même indistinguable d'octets aléatoires uniformes (les ciphertexts ML-KEM sont des encapsulations CCA-sûres ; l'output du stream ChaCha20 et les tags Poly1305 sont pseudo-aléatoires). Concaténer deux tels blobs produit une chaîne elle-même pseudo-aléatoire — les seuls octets non aléatoires dans tout le bundle sont le flag d'ordre d'1 octet (uniformément distribué) et le préfixe de longueur de 4 octets (déterministe à partir du choix du bucket). Combiné à la politique du protocole de router **tout** chiffrement asymétrique à travers BLUE (voir *Pourquoi tout le monde doit utiliser BLUE* ci-dessous), il n'y a pas moyen d'empreinter un bundle BLUE comme différent de n'importe quelle autre charge utile chiffrée post-quantique.

### Attaques que BLUE n'adresse pas

BLUE résout un modèle de menaces précis et ne prétend pas résoudre les modèles adjacents. Il est honnête sur ses limites :

- **Divulgation coercée des deux clés en même temps.** Si l'adversaire obtient à la fois `xprivkey` et `yprivkey`, les deux messages deviennent déchiffrables. C'est pourquoi le système keyx les stocke dans deux Keyx séparés (`bluekeys.keys` et `bluekeys.ckeys`), supposés vivre sur des appareils différents. *Voir la sous-section « Séparation physique des clés » ci-dessous.*
- **Récupération forensique du plaintext en RAM.** BLUE protège les bundles au repos et en transit. Il ne protège pas le plaintext pendant que l'application l'utilise. La forensique mémoire, les dumps de swap, et les snapshots au niveau OS sont hors périmètre.
- **Fuite de métadonnées.** Heure d'envoi, fréquence, identité expéditeur/destinataire, chemin réseau — tout visible pour un observateur réseau quel que soit la protection du contenu par BLUE. Pour masquer les métadonnées, une couche supplémentaire (réseau anonyme, mélange de messages, stéganographie via YELLOW) est requise.
- **Crédibilité du leurre.** Si le message leurre est vide, absurde, ou manifestement faux (« test », « asdf »), aucune indistinguabilité cryptographique ne sauvera la déniabilité. Le leurre doit ressembler à un vrai message que l'utilisateur aurait plausiblement écrit. C'est une responsabilité UX/opérationnelle de l'application construite par-dessus BLUE.


## Déniabilité plausible

### Scénario de base

Alice veut envoyer un message confidentiel à Bob. Elle sait qu'un adversaire pourrait un jour la forcer à révéler sa clé.

1. Alice génère un trousseau BLUE : `gpubkey`, `xprivkey`, `yprivkey`.
2. Elle chiffre le vrai message sur le canal x et un leurre crédible sur le canal y.
3. Elle stocke `yprivkey` (la clé leurre) dans son Keyx principal (`keyx.bluekeys.keys`, sur sa machine).
4. Elle stocke `xprivkey` (la vraie clé) dans un Keyx séparé (`keyx.bluekeys.ckeys`, sur une clé USB qu'elle garde ailleurs).

### Scénario de coercition

Un adversaire force Alice à ouvrir son Keyx. Alice ouvre `bluekeys.keys`, qui contient `yprivkey`. L'adversaire déchiffre le bundle et obtient le leurre. Il ne peut pas prouver que le canal x existe : le bundle qu'il voit est un blob opaque, et `yprivkey` produit un message crédible.

La clé USB contenant `xprivkey` est physiquement absente. L'adversaire ne sait même pas qu'elle existe.

### Scénario sans déniabilité

Si Alice n'a pas besoin de déniabilité, elle utilise BLUE en mode mono :

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], xmsg="message confidentiel")
```

Elle ne stocke que `xprivkey`, pas de `ckeys`, pas de leurre. BLUE fonctionne alors comme un chiffrement asymétrique classique, mais avec la même structure de bundle indistinguable.

### Pourquoi tout le monde doit utiliser BLUE (et pas BLACK directement)

Si BLACK était exposé comme protocole public, deux populations d'utilisateurs coexisteraient : ceux qui utilisent BLACK (sans déniabilité) et ceux qui utilisent BLUE (avec déniabilité). Un adversaire qui voit un bundle BLUE saurait immédiatement que l'utilisateur a potentiellement quelque chose à cacher — sinon il aurait utilisé BLACK.

En rendant BLACK interne et en forçant tout chiffrement asymétrique à passer par BLUE, tous les bundles ont la même structure. Les utilisateurs qui n'ont pas besoin de déniabilité et ceux qui en ont besoin produisent des bundles identiques. L'adversaire ne peut pas les distinguer.


## Primitives cryptographiques (v2.0)

| Composant | Algorithme |
|---|---|
| Encapsulation de clé | ML-KEM-512 (FIPS 203) via BLACK |
| Chiffrement symétrique | ChaCha20-Poly1305 via BLACK |
| Ordre des slots | Bit aléatoire (`secrets.randbits(1)`) |
| Padding | Buckets à taille fixe (8 tailles jusqu'à 1 Gio) |


## Padding

Pour empêcher la taille du message de trahir le contenu, chaque message est rembourré jusqu'à la taille du plus petit bucket qui peut le contenir.

Buckets disponibles (v2.0) :

| Bucket | Taille |
|---|---|
| 1 | 4 Ko |
| 2 | 16 Ko |
| 3 | 64 Ko |
| 4 | 256 Ko |
| 5 | 1 Mo |
| 6 | 16 Mo |
| 7 | 256 Mo |
| 8 | 1 Gio |

Le format padded est :

```
[4 octets : longueur du message] [message] [octets de padding aléatoires]
```

Si les deux messages (x et y) sont fournis, ils doivent être dans le **même bucket**. Sinon la différence de taille des ciphertexts casserait la déniabilité. Si les deux messages ne tiennent pas dans le même bucket, `encrypt` lève `EncryptionError`.

Plafond strict de taille : chaque message ne doit pas dépasser **1 Gio** (`2³⁰` octets). À des tailles approchant ce plafond, l'usage RAM de pic du chiffrement peut atteindre ~7-9 Gio ; les utilisateurs sur machines à mémoire limitée devraient rester bien en dessous.


## Modes de chiffrement

### Mode dual (x et y)

L'expéditeur fournit les deux messages. Les deux sont chiffrés et assemblés dans le bundle.

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], xmsg="vrai", ymsg="leurre")
```

### Mode mono-x (x uniquement)

L'expéditeur ne fournit que `xmsg`. Le protocole génère une paire de clés ML-KEM-512 **éphémère** pour le canal y, chiffre du bruit aléatoire comme `ymsg`, puis détruit la clé privée éphémère. Le canal y devient alors physiquement indéchiffrable — même par l'expéditeur. Le bundle reste indistinguable d'un bundle dual.

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], xmsg="vrai message")
```

### Mode mono-y (y uniquement)

Identique au mode mono-x mais inversé : le canal x contient du bruit indéchiffrable.

```python
bundle = crx.blue.encrypt("2", keys["gpubkey"], ymsg="vrai message")
```


## Mode asynchrone (v2.0+)

Pour les grands messages (typiquement > 100 Mo), le travail de chiffrement ou déchiffrement peut prendre plusieurs secondes. Pour éviter de bloquer le thread principal et donner à l'appelant une visibilité sur le progrès, BLUE v2.0 fournit un mode asynchrone déclenché par le passage d'un argument `id`.

```python
# Lance le chiffrement en arrière-plan, pas de valeur de retour
crx.blue.encrypt("2", keys["gpubkey"], xmsg="big_data", id="job1")

# Polling du progrès (retourne un float dans [0.0, 1.0])
while crx.blue.show_encryption_progress(id="job1") < 1.0:
    update_ui()
    time.sleep(0.05)

# Récupère le bundle (bloque si pas encore fini ; auto-supprime le job de la registry)
bundle = crx.blue.get_encryption_result(id="job1")
```

API symétrique pour le déchiffrement : `show_decryption_progress(id)` et `get_decryption_result(id)`.

### Reporting du progrès par paliers

Le progrès est reporté comme une séquence de paliers discrets, chacun correspondant à une phase réelle terminée du travail. Le pipeline de chiffrement passe par les paliers suivants :

| Valeur | Signification |
|---|---|
| 0.00 | Job créé, travail pas encore commencé |
| 0.05 | Validation des inputs et décodage gpubkey terminés |
| 0.10 | Bucket choisi et les deux messages rembourrés |
| 0.50 | Chiffrement du slot x terminé |
| 0.85 | Chiffrement du slot y terminé |
| 1.00 | Bundle assemblé, encodé en base64, prêt |

Le déchiffrement utilise une séquence plus courte : `0.10` (en-tête parsé et slot localisé), `0.90` (slot cible déchiffré), `1.00` (unpadded et décodé).

La bibliothèque reporte la vérité : le dernier palier atteint. Aucune interpolation, estimation, ou animation n'est effectuée en interne. C'est un choix de conception délibéré : le lissage d'une barre de progrès est un problème de présentation mieux géré par la couche applicative, où le framework de rendu (Rich, tqdm, Qt, frameworks web, etc.) dispose déjà de ses propres primitives d'animation et peut interpoler entre deux valeurs avec un timing de frame approprié.

Si l'application a besoin d'un rendu lisse, elle peut interpoler entre des polls successifs avec son propre état. Par exemple avec `rich` :

```python
from rich.progress import Progress
import time

with Progress() as p:
    task = p.add_task("Chiffrement...", total=1.0)
    crx.blue.encrypt("2", gpubkey, xmsg=big, id="job1")
    while crx.blue.show_encryption_progress(id="job1") < 1.0:
        p.update(task, completed=crx.blue.show_encryption_progress(id="job1"))
        time.sleep(0.05)
    p.update(task, completed=1.0)
```

Rich interpole la position de la barre entre les mises à jour en interne, produisant une animation fluide à partir des valeurs par paliers.

### Sémantique de l'identifiant

L'argument `id` est **fourni par l'appelant** et doit être unique parmi les jobs actifs. N'importe quelle valeur hashable convient : entiers, chaînes, tuples. Si un `id` est déjà utilisé par un job non consommé, un second `encrypt(..., id=X)` lève `EncryptionError`.

Le job est **automatiquement retiré de la registry** dès que `get_encryption_result(id)` (ou son équivalent de déchiffrement) retourne. Après récupération, le même id peut être réutilisé. Appeler `show_*` ou `get_*` sur un id inexistant, ou sur un id appartenant à un job d'un autre type, lève l'exception appropriée.

### Gestion différée des erreurs

Les exceptions levées dans le travail d'arrière-plan (par exemple mauvaise clé, bundle malformé) sont stockées dans la registry et re-levées quand `get_*_result(id)` est appelé. Les erreurs de validation de types qui surviennent au moment de l'appel (tel qu'un `gpubkey` non-str) sont levées synchroniquement.

### Quand le mode asynchrone n'est pas nécessaire

Pour les petits messages (typiquement moins d'1 Mo), le travail se termine en microsecondes et le surcoût de lancer un thread d'arrière-plan n'est pas justifié. Le mode synchrone (`id=None`, par défaut) est préférable dans ces cas.


## Migration de bundle

Les bundles BLUE v1.0 peuvent être migrés vers v2.0 via `update_bundle`. La fonction déchiffre le bundle source, puis le rechiffre sous la nouvelle version.

```python
new_bundle = crx.blue.update_bundle(
    "1 to 2",            # spec : "<ancien>.<mineur> to <nouveau>.<mineur>" (mineurs optionnels)
    keys["gpubkey"],
    old_bundle,
    xprivkey=keys["xprivkey"],   # au moins une privkey x/y requise
    yprivkey=keys["yprivkey"],   # fournir les deux pour migration sans perte
)
```

Si une seule de `xprivkey` ou `yprivkey` est fournie alors que le bundle source était en mode dual, le slot correspondant à la privkey manquante est remplacé par un decoy aléatoire dans le nouveau bundle — **l'information de ce slot est perdue**. Ce comportement est délibéré ; l'appelant est responsable de s'assurer que la perte est acceptable pour son cas d'usage, ou de fournir les deux privkeys lorsqu'une migration sans perte est requise.

Les downgrades (par exemple `"2 to 1"`) requièrent `downgrade=True` ; sinon `DowngradeError` est levée.

Les specs de même version (`"2 to 2"`, `"2.0 to 2"`) retournent l'input inchangé.


## API

### `crx.blue.encrypt(version, gpubkey, xmsg=None, ymsg=None, *, id=None) -> str | None`

Chiffre un ou deux messages dans un bundle BLUE.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. `"2.0"`, `"2"`, `"1.0"`, ou `"1"`. |
| `gpubkey` | `str` | Clé publique composite (base64url, 1600 octets bruts). |
| `xmsg` | `str \| None` | Message pour le canal x. `None` si inutilisé. |
| `ymsg` | `str \| None` | Message pour le canal y. `None` si inutilisé. |
| `id` | `Any \| None` | Si fourni, le chiffrement tourne en arrière-plan. v2.0+ seulement. |
| **Retour** | `str \| None` | Bundle chiffré (mode sync), ou `None` (mode async). |

Au moins un des deux messages (`xmsg` ou `ymsg`) doit être fourni. Si les deux sont fournis, ils doivent tenir dans le même bucket de padding.

**Exceptions** :
- `ArgumentTypeError` — si un argument n'est pas du bon type.
- `EncryptionError` — si aucun message n'est fourni, si `gpubkey` est invalide, si les messages ne tiennent pas dans le même bucket, si un message dépasse 1 Gio, si un `id` async est déjà en cours d'utilisation, ou si le mode async est demandé sur une version non-v2.0+.
- `VersionNotFoundError` — si la version est inconnue.

### `crx.blue.decrypt(version, privkey, msg, *, slot=..., id=None) -> str | None`

Déchiffre un bundle BLUE avec une clé privée (x ou y).

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version attendue. |
| `privkey` | `str` | `xprivkey` ou `yprivkey`. |
| `msg` | `str` | Bundle chiffré (base64url). |
| `slot` | `str` | **Requis en v2.0+ (keyword-only)**. `"x"` ou `"y"` — identifie quel slot la privkey déchiffre. Non utilisé en v1.0. |
| `id` | `Any \| None` | Si fourni, le déchiffrement tourne en arrière-plan. v2.0+ seulement. |
| **Retour** | `str \| None` | Plaintext (mode sync), ou `None` (mode async). |

En v1.0, le protocole essaie automatiquement les deux canaux (pas d'argument `slot`). En v2.0+, l'argument `slot` est requis : le flag d'ordre dans le bundle localise le ciphertext du slot correspondant, et seul ce slot est déchiffré.

**Exceptions** :
- `ArgumentTypeError` — si un argument n'est pas `str`.
- `DecryptionError` — si la clé ne déchiffre pas le slot demandé, si le bundle est corrompu, ou si le mode async est demandé sur une version non-v2.0+.

### `crx.blue.genkeys(version) -> dict[str, str]`

Génère un trousseau BLUE.

| Paramètre | Type | Description |
|---|---|---|
| `version` | `str` | Version du protocole. |
| **Retour** | `dict` | `{"gpubkey": str, "xprivkey": str, "yprivkey": str}` |

Le `gpubkey` est la concaténation de deux clés publiques ML-KEM-512 (800 + 800 = 1600 octets bruts, encodés en base64url).

### `crx.blue.getversion(msg) -> str`

Extrait la version d'un bundle BLUE sans le déchiffrer.

| Paramètre | Type | Description |
|---|---|---|
| `msg` | `str` | Bundle chiffré (base64url). |
| **Retour** | `str` | Version au format `"M.m"`. |

### `crx.blue.update_bundle(old_to_new, gpubkey, old_msg, xprivkey=None, yprivkey=None, downgrade=False) -> str`

Rechiffre un bundle BLUE d'une version du protocole à une autre.

| Paramètre | Type | Description |
|---|---|---|
| `old_to_new` | `str` | Spécificateur sous la forme `"1 to 2"`, `"1.0 to 2.0"`, ou toute combinaison de versions majeures-seulement et exactes séparées par ` to `. |
| `gpubkey` | `str` | Clé publique composite pour le nouveau bundle. |
| `old_msg` | `str` | Le bundle à migrer. |
| `xprivkey` | `str \| None` | Clé privée côté x. Au moins une privkey x/y requise. |
| `yprivkey` | `str \| None` | Clé privée côté y. Optionnel mais recommandé pour migration dual sans perte. |
| `downgrade` | `bool` | Si `True`, permet la migration vers une version plus ancienne. Par défaut `False`. |
| **Retour** | `str` | Bundle rechiffré. |

**Exceptions** :
- `ArgumentTypeError` — types invalides.
- `VersionNotFoundError` — spec `old_to_new` invalide ou version inconnue.
- `DowngradeError` — ancien > nouveau et `downgrade=False`.
- `DecryptionError` — aucune privkey ne déchiffre le bundle.
- `EncryptionError` — pas de privkey fournie, ou échec de rechiffrement.

### `crx.blue.show_encryption_progress(id) -> float`
### `crx.blue.show_decryption_progress(id) -> float`

Retournent le progrès courant (0.0 à 1.0) d'un job de chiffrement/déchiffrement d'arrière-plan. Lèvent `EncryptionError` / `DecryptionError` si aucun job de ce type n'existe avec cet id.

### `crx.blue.show_encryption_eta(id) -> float | None`
### `crx.blue.show_decryption_eta(id) -> float | None`

Estiment le nombre de secondes restantes pour le job d'arrière-plan avec l'`id` donné. Retournent `None` quand le progrès est en dessous de 1 % (trop faible pour projeter), et `0.0` quand le job est terminé. L'estimation est dérivée du temps écoulé divisé par la valeur du palier courant, projetée sur la fraction restante ; la précision s'améliore à mesure que davantage de paliers sont atteints. Lèvent `EncryptionError` / `DecryptionError` si aucun job de ce type n'existe avec cet id.

### `crx.blue.get_encryption_result(id) -> str`
### `crx.blue.get_decryption_result(id) -> str`

Bloquent jusqu'à ce que le job d'arrière-plan avec l'`id` donné se termine, retournent le bundle (encrypt) ou le plaintext (decrypt), et auto-suppriment le job de la registry. Re-lèvent toute exception qui s'est produite pendant le travail. Lèvent `EncryptionError` / `DecryptionError` si aucun job de ce type n'existe avec cet id.


## Structure du bundle (v2.0)

Le bundle brut (après retrait des 2 octets de version et avant encodage base64) :

```
[1 octet  : order_flag]            → 0 = enc_x en premier, 1 = enc_y en premier
[4 octets : len(enc_first)]        → longueur big-endian du premier slot
[enc_first octets]                 → ciphertext BLACK pour le canal du premier slot
[enc_second octets]                → ciphertext BLACK pour le canal du second slot
```

Chaque `enc_*` est lui-même un ciphertext BLACK v1.0 : encapsulation ML-KEM-512 + ChaCha20-Poly1305 (nonce + ciphertext + tag), base64-encodé. Les deux slots sont rembourrés à la même taille de bucket avant le chiffrement BLACK, garantissant que les deux blobs `enc_*` ont des tailles identiques.

Le `order_flag` est lu en clair par `decrypt` pour identifier quel slot est x et quel slot est y, mais il ne transmet aucune information sur le contenu (c'est un bit uniformément aléatoire).


## Considérations de sécurité

**Crédibilité du leurre** : la déniabilité est inutile si le message leurre n'est pas crédible. Un leurre vide ou absurde ("test", "rien") ne convaincra personne. Le leurre doit ressembler à un vrai message que l'utilisateur aurait raisonnablement envoyé.

**Séparation physique des clés** : la déniabilité suppose que l'adversaire n'a accès qu'à une seule clé privée. Si les deux clés (`xprivkey` et `yprivkey`) sont stockées au même endroit, l'adversaire les trouve toutes les deux et la déniabilité est nulle. Le système keyx fournit deux Keyx séparés (`keys` et `ckeys`) pour exactement cette raison.

**Métadonnées non protégées** : BLUE protège le contenu des messages, pas les métadonnées. L'heure d'envoi, la fréquence des échanges, l'identité de l'expéditeur et du destinataire ne sont pas masqués par BLUE. Pour masquer ces métadonnées, une couche supplémentaire (réseau anonyme, stéganographie via YELLOW) est requise.

**Taille du bundle** : la taille du bundle peut révéler dans quel bucket le message se trouve, donc une plage de taille approximative du message (par exemple 0-4 Ko, 4-16 Ko, 16-256 Mo, etc.). Elle ne révèle pas la taille exacte du message au sein du bucket.

**Sécurité des jobs async** : la registry des `id` stocke les résultats en mémoire jusqu'à récupération. Les plaintexts sensibles de jobs decrypt terminés persistent jusqu'à ce que `get_decryption_result(id)` soit appelé. Les appelants traitant des données sensibles devraient récupérer les résultats rapidement.


## Exemple complet

```python
import pycryptox as crx
import time

# Génération d'un trousseau
keys = crx.blue.genkeys("2")

# --- Usage synchrone (petits messages) ---
bundle = crx.blue.encrypt("2", keys["gpubkey"],
                          xmsg="Coordonnées GPS : 48.8566, 2.3522",
                          ymsg="Pas de nouvelles, tout va bien.")

# Le destinataire déchiffre avec xprivkey → vrai message
real = crx.blue.decrypt("2", keys["xprivkey"], bundle, slot="x")
print(real)  # → "Coordonnées GPS : 48.8566, 2.3522"

# Sous coercition, il livre yprivkey → leurre crédible
decoy = crx.blue.decrypt("2", keys["yprivkey"], bundle, slot="y")
print(decoy)  # → "Pas de nouvelles, tout va bien."

# --- Usage asynchrone (gros messages) ---
big_data = "X" * (10 * 1024 * 1024)   # 10 Mo
crx.blue.encrypt("2", keys["gpubkey"], xmsg=big_data, id="bigjob")

while (p := crx.blue.show_encryption_progress(id="bigjob")) < 1.0:
    print(f"  progrès : {p:.0%}")
    time.sleep(0.1)

big_bundle = crx.blue.get_encryption_result(id="bigjob")

# --- Migration depuis v1.0 ---
old_keys = crx.blue.genkeys("1")
old_bundle = crx.blue.encrypt("1", old_keys["gpubkey"], xmsg="legacy data")
new_bundle = crx.blue.update_bundle("1 to 2", old_keys["gpubkey"],
                                    old_bundle, xprivkey=old_keys["xprivkey"])
print(crx.blue.getversion(new_bundle))   # → "2.0"
```


## Historique des versions

### Version 2.0 (stable, depuis 3.0.0)

Version actuelle. Format wire simplifié `[order_flag][len][enc_x][enc_y]`, plage de buckets étendue (jusqu'à 1 Gio), usage exclusif de l'API publique de BLACK, mode async par job avec reporting du progrès par paliers, et `update_bundle` pour migrer les bundles v1.0. Le flag d'ordre est randomisé à chaque chiffrement (bit aléatoire enregistré en clair), et le déchiffrement utilise un argument `slot` explicite pour identifier le canal correspondant sans fallback try-both.

### Version 1.0 (legacy)

Version stable précédente. Utilisait ML-KEM-512 via BLACK, le padding par buckets (jusqu'à 1 Mo), et le mélange par clés chimiques — les messages chiffrés étaient entrelacés octet par octet avec du bruit aléatoire via deux listes de positions chiffrées (chemkeys). Le mélange n'apportait aucune déniabilité mesurable au-delà de celle déjà fournie par l'indistinguabilité des ciphertexts ML-KEM + ChaCha20-Poly1305, et son placement octet par octet constituait le goulot d'étranglement responsable du plafond à 1 Mo. v2.0 le remplace par une simple concaténation + préfixe de longueur + flag d'ordre aléatoire.

### Version 0.0

Version initiale du protocole. Les fonctions retournent des réponses fixes sans réaliser d'opération cryptographique.

- `encrypt("0.0")` → `"I encrypt nothing now..."`
- `decrypt("0.0")` → `"I decrypt nothing now..."`
- `genkeys("0.0")` → `"I don't want to. I can't be bothered to make a new key."`
