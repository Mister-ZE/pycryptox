# Sécurité

Ce document décrit le modèle de menace de Pycryptox, ses garanties, et ses limites connues.


## Ce que Pycryptox garantit

**Confidentialité des données au repos** : les bundles chiffrés et les keystores sont illisibles sans la clé ou le mot de passe correspondant. La confidentialité repose sur ML-KEM-512 (pour BLUE, RED, BLACK) et Argon2id + ChaCha20-Poly1305 (pour PURPLE et les keystores).

**Intégrité et authenticité** : ChaCha20-Poly1305 est un schéma AEAD (Authenticated Encryption with Associated Data). Toute modification d'un bundle ou d'un fichier keystore est détectée au déchiffrement. Un attaquant ne peut pas altérer un ciphertext sans que cela soit détecté.

**Résistance post-quantique** : les opérations asymétriques (BLUE, RED) utilisent ML-KEM-512, standardisé par le NIST sous FIPS 203, conçu pour résister aux attaques par ordinateur quantique (algorithme de Shor). PURPLE, étant purement symétrique (Argon2id + ChaCha20-Poly1305), est également résistant aux attaques quantiques connues (l'algorithme de Grover divise par deux la sécurité effective d'un schéma symétrique, mais 128 bits restent largement suffisants).

**Résistance aux canaux auxiliaires (ML-KEM)** : les opérations ML-KEM-512 sont exécutées via liboqs, une implémentation C compilée avec des optimisations constant-time. Cela protège contre les attaques par analyse de timing, où un adversaire mesure le temps d'exécution des opérations pour en déduire des informations sur les clés.


## Ce que Pycryptox ne garantit pas

### Zéroisation de la mémoire

En Python, les objets `bytes` et `str` sont immuables. Une fois qu'une clé privée ou un message en clair existe en mémoire, il ne peut pas être écrasé de manière fiable. Le ramasse-miettes (garbage collector) de Python peut copier ou déplacer les données en mémoire sans que le programme le contrôle.

Pycryptox effectue une destruction symbolique (`variable = b'\x00' * len(variable)` + `del variable` + `gc.collect()`) dans les chemins critiques (BLUE, RED), mais cela ne garantit pas que les données originales sont effacées de la mémoire physique.

Pour une garantie de zéroisation, un module matériel avec mémoire attestée serait nécessaire. C'est l'un des objectifs du projet Cryptbox — un module matériel compagnon de Pycryptox, actuellement en phase de conception, qui fournirait un environnement d'exécution isolé où les clés sont générées, utilisées et détruites avec attestation matérielle. Cryptbox n'est pas encore disponible.

### Audit indépendant

Pycryptox n'a fait l'objet d'aucun audit de sécurité formel par un tiers. Le code a été écrit avec soin et testé extensivement, mais il n'a pas été validé par un auditeur professionnel. Pour les déploiements à très haute criticité, un audit est recommandé avant mise en production.

### Protection contre un adversaire avec accès root

Si l'attaquant a un accès administrateur (root) à la machine sur laquelle Pycryptox s'exécute, il peut lire la mémoire du processus Python (et voir les clés en clair), intercepter les frappes clavier pour capturer les mots de passe, ou modifier le code de Pycryptox lui-même.

Pycryptox protège les données au repos et en transit, pas les données en cours de traitement sur une machine compromise.

### Forward secrecy

Pycryptox n'implémente pas de forward secrecy (secret de transmission). Si la clé privée ML-KEM-512 d'un utilisateur est compromise, tous les bundles passés chiffrés avec la clé publique correspondante sont déchiffrables. Pycryptox est conçu pour le chiffrement au repos (at-rest), pas pour les sessions de communication interactives comme TLS.


## Limites spécifiques par protocole

### PURPLE

**Brute-force hors-ligne** : un attaquant qui capture un fichier chiffré avec PURPLE peut tenter de le bruteforcer en testant des mots de passe. Argon2id ralentit chaque tentative (~50 ms), mais un attaquant avec du matériel spécialisé (FPGA, ASIC) peut paralléliser. La passphrase générée par `genkeys` a ~77.5 bits d'entropie, ce qui est robuste contre un brute-force en ligne mais peut être insuffisant contre un attaquant étatique avec des ressources massives. Pour les scénarios à haute sécurité, utiliser une passphrase plus longue (8+ mots).

### BLUE

**Déniabilité conditionnelle** : la déniabilité de BLUE est cryptographique (le bundle ne trahit pas l'existence de deux canaux — voir la section dédiée dans la documentation de [BLUE](blue.md)), mais elle dépend du comportement de l'utilisateur. Si les deux clés privées sont stockées au même endroit, la déniabilité est nulle. La séparation physique des clés est nécessaire.

**Oracle de déchiffrement** : le bruit dans le bundle BLUE n'est pas authentifié. Un attaquant qui peut soumettre des bundles modifiés et observer si le déchiffrement réussit ou échoue pourrait cartographier les positions des clés chimiques. Les applications doivent éviter d'exposer le statut succès/échec à des parties non authentifiées.

**Taille maximale** : les messages BLUE sont limités à 1 Mo en v1.0.

### RED

**Trusted dealer** : en v1.0, l'entité qui appelle `genkeys()` voit la clé privée complète avant de la découper en parts. Cette entité doit être de confiance.

**Shares statiques** : les parts RED sont utilisables indéfiniment. Il n'y a pas de mécanisme de révocation. Si une part est compromise, il faut regénérer un nouveau jeu de clés et redistribuer de nouvelles parts.

**Identifiabilité des parts** : chaque part contient un index (1 à n) en clair. Un attaquant qui capture une part sait qu'il s'agit d'une part de partage de secret et connaît son numéro. Pour protéger cette information, les parts peuvent être individuellement chiffrées avec PURPLE avant distribution.


## Dépendances et surface d'attaque

| Dépendance | Rôle | Risque |
|---|---|---|
| `liboqs` (C) | ML-KEM-512 | Implémentation C, maintenue par le projet Open Quantum Safe (Linux Foundation). Constant-time. Pas encore FIPS 140-3 certifié (processus en cours). |
| `cryptography` (Python/C) | ChaCha20-Poly1305 | Bindings Python pour OpenSSL/BoringSSL. Largement audité. |
| `argon2-cffi` (Python/C) | Argon2id | Bindings Python pour l'implémentation de référence Argon2 en C. Vainqueur du Password Hashing Competition (2015). |
| `rapidfuzz` (Python/C) | Recherche floue | Utilisé uniquement pour la recherche dans les keystores. Aucun impact sur la sécurité cryptographique. |


## Recommandations

1. **Utiliser des passphrases fortes** pour PURPLE et les keystores. La passphrase générée par `crx.purple.genkeys("1")` est un minimum acceptable.

2. **Séparer physiquement les clés BLUE** en utilisant les keystores `keys` (sur la machine) et `ckeys` (sur un support externe). Dans un scénario sans déniabilité, seul le keystore `keys` est utilisé ; le keystore `ckeys` n'est pas créé.

3. **Distribuer les parts RED par des canaux séparés**. Ne pas envoyer toutes les parts au même endroit. Chaque participant doit stocker sa part indépendamment.

4. **Ne pas exposer les résultats de déchiffrement** à des tiers non authentifiés, en particulier pour BLUE.

5. **Maintenir Pycryptox à jour**. Les algorithmes post-quantiques sont un domaine actif de recherche. Les mises à jour de Pycryptox intègrent les dernières versions de liboqs et corrigent les vulnérabilités éventuelles.
