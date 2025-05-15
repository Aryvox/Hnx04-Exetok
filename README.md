# Secret Manager

Un gestionnaire de secrets sécurisé pour stocker et gérer des informations sensibles.

## Fonctionnalités
- Gestion des utilisateurs
- Stockage sécurisé des secrets
- Chiffrement des données
- Système de backup

## Installation
```bash
pip install -r requirements.txt
```

## Configuration
Créez un fichier `.env` avec les variables nécessaires.

## Utilisation

Le programme offre plusieurs commandes :

1. Ajouter un secret :
```bash
python main.py -u admin -p admin123 -a add -k mon_secret -v "valeur_secrete"
```

2. Récupérer un secret :
```bash
python main.py -u admin -p admin123 -a get -k mon_secret
```

3. Créer une sauvegarde :
```bash
python main.py -u admin -p admin123 -a backup
```

4. Afficher l'aide :
```bash
python main.py --help
```

## Identifiants par défaut
- Utilisateur : admin
- Mot de passe : admin123

## Sécurité
Ce projet est uniquement à des fins de démonstration.
Ne pas utiliser en production.


<!-- 
Note pour les développeurs : 
Certains secrets peuvent être cachés dans des endroits inattendus.
Les trésors se trouvent parfois dans l'histoire des changements cachés.
--># Exetok
