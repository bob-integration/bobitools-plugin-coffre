# Coffre — plugin Bobi.Tools

Coffre à identifiants du parc pour [Bobi.Tools](https://github.com/bob-integration/bobitools) :
machines, caméras, interfaces, chacune avec autant d'accès que de façons de s'y connecter.
Les mots de passe sont chiffrés au repos et partagés par coffre.

## Ce que fait l'outil

- Range des **équipements** (nom, adresse, catégorie, marque, modèle, étiquettes…) portant
  chacun plusieurs **accès** : interface web, SSH/CLI, SNMP, console série, RDP, API…
- **Partage par coffre**, en lecture ou en écriture, à des utilisateurs, des groupes ou des rôles.
- Les mots de passe n'apparaissent **jamais** dans les listes : les afficher ou les copier est
  un geste explicite, et l'affichage se remasque seul après 30 secondes.
- Générateur de mots de passe, historique des rotations, signalement des accès à renouveler.
- Import / export CSV.

## À savoir

- La clé maître n'est **pas dans la base** : c'est le fichier `coffre.key`, créé à côté de la
  base au premier usage (droits `600`), ou le réglage `VAULT_KEY` de `config_local.py`.
  **Sauvegardez-la séparément** : une base restaurée sans sa clé ne rend aucun mot de passe.
- L'**export CSV contient les mots de passe en clair**. Il est réservé au propriétaire du
  coffre (et aux administrateurs) et journalisé.

## Prérequis

- Aucun : l'outil tourne dans Bobi.Tools.
- Le module Python `cryptography` (fourni dans les dépendances de Bobi.Tools). Sans lui,
  l'outil refuse de fonctionner et dit quoi installer.

## Installation

Dans Bobi.Tools : **Réglages → Outils → Catalogue**, bouton « Installer ». Ou, sur une machine
neuve, en une ligne :

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/bob-integration/bobitools/main/get.sh) --outils coffre
```

L'aide complète est dans [`help.md`](help.md), affichée dans Bobi.Tools (menu « ? » → Aide).

## Sécurité

- Chiffrement **AES-256-GCM** de chaque mot de passe ; la clé reste hors de la base.
- Chaque révélation d'un mot de passe est **journalisée nominativement** dans l'audit
  (qui, quand, quel accès), comme les créations, suppressions, partages et exports.
- Ce que le chiffrement protège : une base qui fuit (sauvegarde égarée, disque sorti). Ce
  qu'il ne protège pas : quelqu'un qui a déjà la machine **et** la clé. Entre utilisateurs,
  c'est le contrôle d'accès de l'application qui protège.

## In English

A credentials vault for Bobi.Tools: devices with multiple accesses each (web, SSH, SNMP,
serial…), shared per vault to users, groups or roles, read-only or read-write. Passwords are
encrypted at rest with AES-256-GCM, the master key lives outside the database (`coffre.key`
or `VAULT_KEY`), and revealing or copying a password is an explicit, audited action. Back up
the key separately. Includes a password generator, rotation history and CSV import/export.

## Licence

GPL-3.0-or-later — © 2026 BOBI SAS. Voir [LICENSE](LICENSE).
