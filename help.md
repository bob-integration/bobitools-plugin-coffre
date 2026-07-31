# Coffre

Range les **identifiants du parc** : machines, caméras, interfaces, switchs… avec, pour
chacune, **autant d'accès que de façons de s'y connecter**.

## Le modèle : équipement → accès

Une machine a rarement un seul mot de passe. La même caméra se pilote par son **interface
web**, se dépanne en **SSH**, et se supervise en **SNMP** — trois logins différents, trois
mots de passe différents, une seule machine.

D'où deux étages :

- l'**équipement** porte l'identité : nom, adresse IP ou DNS, catégorie, marque, modèle,
  site, étiquettes, notes ;
- l'**accès** porte le couple login / mot de passe **et sa nature** : interface web,
  SSH/CLI, Telnet, FTP, RDP, VNC, SNMP, API, console série, façade, base de données,
  session système. Plus, si besoin, un port et une URL.

Un accès de type *interface web* affiche une flèche **↗** qui ouvre directement
`https://<adresse>` — inutile de retaper l'adresse.

## Les coffres, et le partage

Les équipements sont rangés dans des **coffres** : « Régie A », « Cars », « Infra
réseau »… Le partage se règle **au niveau du coffre**, jamais entrée par entrée :

- **Lecture** — voir les équipements et **révéler** les mots de passe ;
- **Écriture** — en plus : ajouter, modifier, supprimer des équipements.

On partage à des **utilisateurs**, à des **groupes** (Réglages → Utilisateurs → *Groupes
d'utilisateurs*) ou à des **rôles**. Un groupe est le moyen normal de dire « toute l'équipe
régie » sans énumérer huit comptes.

Le **propriétaire** du coffre (celui qui l'a créé) est le seul, avec un administrateur, à
pouvoir repartager, exporter ou supprimer le coffre.

## Les mots de passe

**Ils ne sortent jamais dans les listes.** L'écran affiche `••••••••` ; il faut cliquer
sur **👁** (afficher) ou **⧉** (copier) pour obtenir le mot de passe. Chacun de ces gestes
est **journalisé nominativement** dans l'audit (*qui*, *quand*, *quel accès*) — c'est la
contrepartie d'un coffre partagé. Un mot de passe affiché se **remasque seul au bout de
30 secondes**.

Dans l'écran d'édition, un champ mot de passe **laissé vide ne change rien** : l'interface
ne connaît pas les secrets enregistrés et ne peut donc pas les écraser par mégarde. Le
bouton **⚄** génère un mot de passe solide, en évitant les caractères que les shells et
les consoles série avalent (guillemets, apostrophes, barres obliques, espaces).

À chaque changement, l'ancien mot de passe bascule dans l'**historique** (bouton 🕘) :
précieux le jour où un équipement du parc n'a pas suivi la rotation. Un accès inchangé
depuis le délai réglé (Réglages → Outils, un an par défaut) se signale par
« à renouveler ».

## Le chiffrement, et la clé

Les mots de passe sont chiffrés en base (**AES-256-GCM**). La clé maître **n'est pas dans
la base** : c'est le fichier `coffre.key` posé à côté de `db_bobitools.db` (droits `600`),
ou le réglage `VAULT_KEY` de `config_local.py`.

> **À retenir : sauvegardez la clé séparément.** Une restauration de la base **sans** sa
> clé ne rend aucun mot de passe — les accès s'affichent alors marqués « illisible ».
> L'empreinte affichée en bas du volet gauche (🔑) permet de vérifier d'un coup d'œil que
> deux instances portent bien la même clé.

Ce que le chiffrement protège : une base qui fuite (sauvegarde égarée, disque sorti). Ce
qu'il ne protège pas : quelqu'un qui a déjà la machine **et** la clé. C'est le contrôle
d'accès applicatif qui protège entre utilisateurs.

## Import / export CSV

Colonnes (séparateur `;`) :

```
equipement;adresse;categorie;marque;modele;site;tags;notes;acces;libelle;login;mot_de_passe;port;url;notes_acces
```

Plusieurs lignes portant le **même nom d'équipement** deviennent **plusieurs accès de la
même machine** — c'est ainsi qu'on importe « web + SSH » d'un coup. Un import sur un
équipement existant **ajoute** ses accès plutôt que de les remplacer.

L'**export contient tous les mots de passe en clair** : il est réservé au propriétaire du
coffre, demande une confirmation, et est journalisé. Le fichier obtenu n'est plus protégé
par rien — effacez-le après usage.
