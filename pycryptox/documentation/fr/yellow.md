# Protocole YELLOW (placeholder)

YELLOW est le protocole de stéganographie de Pycryptox. Son objectif est de dissimuler des données chiffrées dans des documents d'apparence anodine (images, textes, fichiers audio) pour qu'un observateur ne puisse pas détecter la présence même d'un message chiffré.

**YELLOW n'est pas implémenté dans cette version de Pycryptox.** Le module existe comme placeholder et ses fonctions ne produisent aucun résultat utile.


## API actuelle

### `crx.yellow.stega(version) -> str`

Retourne une chaîne de placeholder. Aucun traitement réel.

### `crx.yellow.unstega(version) -> str`

Retourne une chaîne de placeholder. Aucun traitement réel.

Les deux fonctions acceptent le paramètre `version` pour respecter la convention commune des protocoles Pycryptox, mais ne font rien.


## Objectif futur

YELLOW v1.0 ajoutera :

- `stega(version, msg, cover)` — dissimule `msg` (un bundle PURPLE, BLUE ou RED déjà chiffré) dans un fichier de couverture `cover`.
- `unstega(version, stego)` — extrait le bundle caché d'un fichier stéganographié.

Le protocole sera conçu pour que le fichier stéganographié soit statistiquement indistinguable de l'original pour un observateur qui ne connaît pas la clé.


## Pourquoi YELLOW est séparé des autres protocoles

YELLOW n'est pas un protocole de chiffrement. Il opère sur le résultat d'un chiffrement déjà effectué. Son rôle est la dissimulation, pas la confidentialité. La combinaison typique est : chiffrer avec BLUE, puis dissimuler avec YELLOW avant transmission sur un réseau surveillé.


## Historique des versions

### Version 0.0

Version initiale du protocole. Les fonctions retournent des réponses fixes sans effectuer de traitement.

- `stega("0.0")` → `"Actually... there's nothing I can return."`
- `unstega("0.0")` → `"Actually... there's nothing I can return."`
