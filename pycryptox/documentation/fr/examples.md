# Exemples

Cette page rassemble des exemples de code couvrant l'ensemble des fonctionnalités de Pycryptox. Chaque exemple est autonome et peut être copié-collé directement.

```python
import pycryptox as crx
```


## PURPLE — Chiffrement par mot de passe

### Chiffrer et déchiffrer un message

```python
ct = crx.purple.encrypt("1", "mon-mot-de-passe", "Message confidentiel")
pt = crx.purple.decrypt("1", "mon-mot-de-passe", ct)
print(pt)  # → "Message confidentiel"
```

### Générer une passphrase sécurisée

```python
passphrase = crx.purple.genkeys("1")
print(passphrase)  # → "abandon ability able about above absent" (exemple)

ct = crx.purple.encrypt("1", passphrase, "Protégé par une passphrase EFF")
pt = crx.purple.decrypt("1", passphrase, ct)
```

### Extraire la version d'un bundle

```python
ct = crx.purple.encrypt("1", "pwd", "hello")
version = crx.purple.getversion(ct)
print(version)  # → "1.0"
```

### Gérer un mauvais mot de passe

```python
ct = crx.purple.encrypt("1", "bon-mot-de-passe", "secret")

try:
    crx.purple.decrypt("1", "mauvais-mot-de-passe", ct)
except crx.DecryptionError:
    print("Mot de passe incorrect ou message corrompu")
```

### Chiffrer plusieurs fois le même message produit des bundles différents

```python
ct1 = crx.purple.encrypt("1", "pwd", "même message")
ct2 = crx.purple.encrypt("1", "pwd", "même message")
print(ct1 == ct2)  # → False (salt et nonce aléatoires)
```


## BLUE — Chiffrement asymétrique déniable

### Générer un trousseau de clés

```python
keys = crx.blue.genkeys("1")
print(keys.keys())  # → dict_keys(['gpubkey', 'xprivkey', 'yprivkey'])
```

### Chiffrement dual (message réel + leurre)

```python
keys = crx.blue.genkeys("1")

bundle = crx.blue.encrypt("1", keys["gpubkey"],
                          xmsg="Rendez-vous à 14h au pont",
                          ymsg="Je t'envoie la recette de gâteau demain")

# Avec xprivkey → message réel
real = crx.blue.decrypt("1", keys["xprivkey"], bundle)
print(real)  # → "Rendez-vous à 14h au pont"

# Avec yprivkey → leurre
decoy = crx.blue.decrypt("1", keys["yprivkey"], bundle)
print(decoy)  # → "Je t'envoie la recette de gâteau demain"
```

### Chiffrement mono (sans déniabilité)

```python
keys = crx.blue.genkeys("1")

# Seul le canal x est utilisé
bundle = crx.blue.encrypt("1", keys["gpubkey"], xmsg="Message simple")
pt = crx.blue.decrypt("1", keys["xprivkey"], bundle)
print(pt)  # → "Message simple"

# Le canal y contient du bruit indéchiffrable
try:
    crx.blue.decrypt("1", keys["yprivkey"], bundle)
except crx.DecryptionError:
    print("Le canal y est indéchiffrable (clé éphémère détruite)")
```

### Mauvaise clé privée

```python
keys_alice = crx.blue.genkeys("1")
keys_bob = crx.blue.genkeys("1")

bundle = crx.blue.encrypt("1", keys_alice["gpubkey"], xmsg="Pour Alice")

try:
    crx.blue.decrypt("1", keys_bob["xprivkey"], bundle)
except crx.DecryptionError:
    print("La clé de Bob ne déchiffre pas le bundle d'Alice")
```

### Messages dans des buckets différents → erreur

```python
keys = crx.blue.genkeys("1")

try:
    crx.blue.encrypt("1", keys["gpubkey"],
                     xmsg="Court",
                     ymsg="x" * 5000)  # 5 Ko → bucket différent de "Court" (< 4 Ko)
except crx.EncryptionError as e:
    print(f"Erreur : {e}")
```


## RED — Chiffrement à seuil

### Chiffrement 2-sur-3

```python
keys = crx.red.genkeys("1", t=2, n=3)

bundle = crx.red.encrypt("1", keys["gpubkey"], "Code du coffre : 7491")

# 2 parts suffisent
pt = crx.red.decrypt("1", keys["privkeys"][:2], bundle)
print(pt)  # → "Code du coffre : 7491"

# N'importe quelle combinaison de 2
pt = crx.red.decrypt("1", [keys["privkeys"][0], keys["privkeys"][2]], bundle)
print(pt)  # → "Code du coffre : 7491"
```

### Une seule part ne suffit pas

```python
keys = crx.red.genkeys("1", t=2, n=3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "secret")

try:
    crx.red.decrypt("1", [keys["privkeys"][0]], bundle)
except crx.DecryptionError:
    print("Impossible avec une seule part (seuil = 2)")
```

### Seuil 1-sur-N (redondance)

```python
keys = crx.red.genkeys("1", t=1, n=5)
bundle = crx.red.encrypt("1", keys["gpubkey"], "Chaque part suffit seule")

# N'importe quelle part seule suffit
for i in range(5):
    pt = crx.red.decrypt("1", [keys["privkeys"][i]], bundle)
    assert pt == "Chaque part suffit seule"
print("Les 5 parts déchiffrent individuellement")
```

### Parts dupliquées → erreur

```python
keys = crx.red.genkeys("1", t=2, n=3)
bundle = crx.red.encrypt("1", keys["gpubkey"], "test")

try:
    crx.red.decrypt("1", [keys["privkeys"][0], keys["privkeys"][0]], bundle)
except crx.DecryptionError:
    print("Parts dupliquées rejetées")
```


## keyx.purplekeys — Stockage de clés

### Créer, ajouter, lire, modifier, supprimer

```python
crx.keyx.purplekeys.createdb("master", "secrets.purple")

with crx.keyx.purplekeys.open("master", "secrets.purple") as s:
    # Ajouter
    s.add("gmail", "G00gleP@ss!")
    s.add("github", "gh-token-abc")
    s.add("aws", "AKIA1234567890")

    # Lire
    print(s.getkey("gmail"))       # → "G00gleP@ss!"
    print(len(s))                  # → 3
    print(s.listallnames())        # → ["aws", "gmail", "github"]

    # Rechercher
    print(s.search("gi"))          # → ["github"]

    # Vérifier l'existence
    print("gmail" in s)            # → True
    print("slack" in s)            # → False

    # Modifier
    s.update("gmail", "NewP@ss2025!")

    # Renommer
    s.rename("aws", "aws-prod")

    # Supprimer
    s.delete("github")

    print(s.listallnames())        # → ["aws-prod", "gmail"]
```

### Vérifier un mot de passe sans ouvrir

```python
print(crx.keyx.purplekeys.verify("master", "secrets.purple"))  # → True
print(crx.keyx.purplekeys.verify("wrong", "secrets.purple"))   # → False
```

### Changer le mot de passe

```python
with crx.keyx.purplekeys.open("master", "secrets.purple") as s:
    s.changepwd("master", "new-master")

# L'ancien mot de passe ne fonctionne plus
try:
    crx.keyx.purplekeys.open("master", "secrets.purple")
except crx.WrongPasswordError:
    print("Ancien mot de passe rejeté")
```

### Backup

```python
with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
    s.backup("secrets.backup.purple")

# Le backup est un keystore valide
with crx.keyx.purplekeys.open("new-master", "secrets.backup.purple") as s:
    print(s.listallnames())
```

### Annulation automatique en cas d'erreur

```python
with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
    print(len(s))  # → 2
    s.add("temporaire", "xyz")
    # len(s) est maintenant 3 en mémoire

try:
    with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
        s.add("poison", "data")
        raise RuntimeError("crash simulé")
except RuntimeError:
    pass

# "poison" n'a PAS été commitée
with crx.keyx.purplekeys.open("new-master", "secrets.purple") as s:
    print("poison" in s)  # → False
```

### Détruire un keystore

```python
crx.keyx.purplekeys.destroy("new-master", "secrets.purple")

# Force destroy (sans vérifier le mot de passe)
crx.keyx.purplekeys.createdb("pwd", "temp.purple")
crx.keyx.purplekeys.destroy("n'importe quoi", "temp.purple", passwordrequired=False)
```


## keyx.bluekeys — Stockage de canaux BLUE

### Stocker et récupérer un canal

```python
my_keys = crx.blue.genkeys("1")
alice_gpubkey = "..."  # reçue d'Alice par un autre canal

crx.keyx.bluekeys.keys.createdb("master", "channels.keys")

with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    s.add("alice", my_keys["gpubkey"], alice_gpubkey, my_keys["xprivkey"])

    entry = s.get("alice")
    print(entry.keys())  # → dict_keys(['mygpubkey', 'hgpubkey', 'privkey'])
```

### Mise à jour partielle d'un canal

```python
new_keys = crx.blue.genkeys("1")

with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    # Ne mettre à jour que la clé privée, sans toucher aux clés publiques
    s.update("alice", privkey=new_keys["xprivkey"])

    entry = s.get("alice")
    print(entry["privkey"] == new_keys["xprivkey"])  # → True
    # mygpubkey et hgpubkey sont inchangés
```

### Utiliser un canal stocké pour chiffrer/déchiffrer

```python
with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    entry = s.get("alice")

    # Chiffrer un message pour Alice
    bundle = crx.blue.encrypt("1", entry["hgpubkey"],
                              xmsg="Message pour Alice",
                              ymsg="Rien de spécial")

    # Déchiffrer un message reçu d'Alice
    received_bundle = "..."  # reçu d'Alice
    pt = crx.blue.decrypt("1", entry["privkey"], received_bundle)
```


## Scénario complet : déniabilité avec keyx

```python
# Bob génère ses clés BLUE
bob_keys = crx.blue.genkeys("1")
alice_gpubkey = "..."  # reçue d'Alice

# Bob crée deux keystores : standard (machine) et critique (USB)
crx.keyx.bluekeys.keys.createdb("master", "channels.keys")
crx.keyx.bluekeys.ckeys.createdb("master", "/usb/critical.ckeys")

# yprivkey (leurre) → keystore standard
with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    s.add("alice", bob_keys["gpubkey"], alice_gpubkey, bob_keys["yprivkey"])

# xprivkey (réel) → keystore critique sur USB
with crx.keyx.bluekeys.ckeys.open("master", "/usb/critical.ckeys") as s:
    s.add("alice", bob_keys["gpubkey"], alice_gpubkey, bob_keys["xprivkey"])

# Alice chiffre un message dual pour Bob
bundle = crx.blue.encrypt("1", bob_keys["gpubkey"],
                          xmsg="Coordonnées : 48.8566, 2.3522",
                          ymsg="Salut, on se voit demain ?")

# Situation normale : Bob déchiffre avec la vraie clé (depuis USB)
with crx.keyx.bluekeys.ckeys.open("master", "/usb/critical.ckeys") as s:
    entry = s.get("alice")
    real = crx.blue.decrypt("1", entry["cprivkey"], bundle)
    print(real)  # → "Coordonnées : 48.8566, 2.3522"

# Sous coercition : Bob ouvre le keystore standard (sur sa machine)
with crx.keyx.bluekeys.keys.open("master", "channels.keys") as s:
    entry = s.get("alice")
    decoy = crx.blue.decrypt("1", entry["privkey"], bundle)
    print(decoy)  # → "Salut, on se voit demain ?"
    # L'adversaire obtient un message crédible. Il ne peut pas prouver
    # que le canal x existe.
```


## Gestion d'erreurs

### Intercepter toutes les erreurs Pycryptox

```python
try:
    crx.purple.decrypt("1", "pwd", "bundle-invalide")
except crx.DecryptionError:
    print("Erreur de déchiffrement spécifique")
except crx.PycryptoxError:
    print("Autre erreur Pycryptox")
```

### Erreurs de type

```python
try:
    crx.purple.encrypt("1", 123, "msg")  # 123 n'est pas un str
except crx.ArgumentTypeError:
    print("Type d'argument invalide")
```

### Erreurs de keystore

```python
try:
    crx.keyx.purplekeys.open("pwd", "inexistant.purple")
except crx.KeystoreError:
    print("Fichier introuvable ou corrompu")

try:
    crx.keyx.purplekeys.createdb("pwd", "fichier.txt")  # mauvaise extension
except crx.KeystoreError:
    print("L'extension doit être .purple")
```

### Erreur de version

```python
try:
    crx.purple.encrypt("99", "pwd", "msg")
except crx.VersionNotFoundError:
    print("Version 99 inconnue")
```


## Discrimination de fichiers keyx

```python
crx.keyx.purplekeys.createdb("pwd", "p.purple")
crx.keyx.bluekeys.keys.createdb("pwd", "k.keys")
crx.keyx.bluekeys.ckeys.createdb("pwd", "c.ckeys")

# Chaque module refuse les fichiers des autres
try:
    crx.keyx.purplekeys.open("pwd", "k.keys")  # extension .keys ≠ .purple
except crx.KeystoreError:
    print("purplekeys refuse un fichier .keys")

try:
    crx.keyx.bluekeys.keys.open("pwd", "c.ckeys")  # extension .ckeys ≠ .keys
except crx.KeystoreError:
    print("bluekeys.keys refuse un fichier .ckeys")

# Même avec une extension renommée, le magic bytes rejette
import shutil
shutil.copy("k.keys", "spoofed.purple")
try:
    crx.keyx.purplekeys.open("pwd", "spoofed.purple")
except crx.KeystoreError:
    print("Magic bytes incompatible — double protection")
```
