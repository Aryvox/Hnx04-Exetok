from secret_manager import SecretManager
import argparse
import sys

def print_help():
    print("""
ExeTok - Gestionnaire de Secrets
-------------------------------
Commandes disponibles:
  --username (-u) : Nom d'utilisateur
  --password (-p) : Mot de passe
  --action  (-a) : Action à effectuer (add/get/backup)
  --key     (-k) : Clé du secret
  --value   (-v) : Valeur du secret (pour l'action 'add')

Exemple d'utilisation:
  python main.py -u admin -p admin123 -a add -k test_secret -v "ma_valeur"
  python main.py -u admin -p admin123 -a get -k test_secret
  python main.py -u admin -p admin123 -a backup
    """)

def main():
    parser = argparse.ArgumentParser(description="ExeTok Secret Management System")
    parser.add_argument("--username", "-u", help="Username for authentication")
    parser.add_argument("--password", "-p", help="Password for authentication")
    parser.add_argument("--action", "-a", choices=["add", "get", "backup"], help="Action to perform")
    parser.add_argument("--key", "-k", help="Secret key")
    parser.add_argument("--value", "-v", help="Secret value (for add action)")
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1 or "--help" in sys.argv or "-h" in sys.argv:
        print_help()
        sys.exit(0)

    manager = SecretManager()
    
    if not all([args.username, args.password]):
        print("Erreur: Nom d'utilisateur et mot de passe requis")
        sys.exit(1)
        
    if not manager.authenticate(args.username, args.password):
        print("Erreur: Authentification échouée")
        sys.exit(1)
        
    try:
        if args.action == "add":
            if not all([args.key, args.value]):
                print("Erreur: Clé et valeur requises pour l'action 'add'")
                sys.exit(1)
            if manager.add_secret(args.key, args.value, args.username):
                print(f"Secret '{args.key}' ajouté avec succès")
            else:
                print("Erreur: Échec de l'ajout du secret")
                
        elif args.action == "get":
            if not args.key:
                print("Erreur: Clé requise pour l'action 'get'")
                sys.exit(1)
            secret = manager.get_secret(args.key, args.username)
            if secret:
                print(f"Valeur du secret: {secret}")
            else:
                print(f"Aucun secret trouvé pour la clé: {args.key}")

        elif args.action == "backup":
            manager.save_backup()
            print("Sauvegarde créée avec succès dans 'backup.json'")
            
    except Exception as e:
        print(f"Une erreur est survenue: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 