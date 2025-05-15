import base64
import hashlib
import json
from typing import Dict, Optional

class SecretManager:
    def __init__(self):
        self._dev_token = self._load_dev_token()
        self._secrets = {}  # Initialize a dictionary to store secrets
        self._users: Dict[str, dict] = {
            "admin": {
                "password": self._hash_password("admin123"),  # Simple password for testing
                "role": "admin"
            }
        }
        # Charger les secrets existants au démarrage
        self._load_backup()

    def _load_dev_token(self):
        # Version test uniquement - à ne pas utiliser en production
        return "ZmxhZ3t0aGlzX2lzX25vdF90aGVfcmVhbF9mbGFnfQ=="

    def _load_backup(self) -> None:
        """
        Charge les secrets depuis le fichier de sauvegarde
        """
        try:
            with open("backup.json", "r") as f:
                backup_data = json.load(f)
                self._secrets = backup_data.get("secrets", {})
        except FileNotFoundError:
            # Si le fichier n'existe pas encore, on continue avec un dictionnaire vide
            pass
        except json.JSONDecodeError:
            # Si le fichier est corrompu, on continue avec un dictionnaire vide
            pass

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate(self, username: str, password: str) -> bool:
        if username not in self._users:
            return False
        return self._users[username]["password"] == self._hash_password(password)

    def add_secret(self, key: str, value: str, user: str) -> bool:
        """
        Ajoute un nouveau secret, en chiffrant la valeur avant de la stocker.
        Args :
            key : La clé pour stocker le secret sous
            value : La valeur secrète à chiffrer et à stocker
            user : Le nom d'utilisateur de l'utilisateur qui ajoute le secret
        Returns :
            bool : True si le secret a été ajouté avec succès, False sinon
        """
        try:
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("Key and value must be strings.")
            encrypted_value = self._encrypt_value(value)
            if not hasattr(self, '_secrets'):
                self._secrets = {}
            if user not in self._secrets:
                self._secrets[user] = {}
            self._secrets[user][key] = encrypted_value
            # Créer automatiquement une sauvegarde après l'ajout d'un secret
            self.save_backup()
            return True
        except Exception as e:
            print(f"Erreur lors de l'ajout du secret: {str(e)}")
            return False

    def get_secret(self, key: str, user: str) -> str:
        """
        Récupère et déchiffre un secret stocké.
        Args:
            key: La clé du secret à récupérer
            user: Le nom d'utilisateur qui demande le secret
        Returns:
            str: La valeur déchiffrée du secret, ou None si non trouvé
        """
        try:
            if not hasattr(self, '_secrets'):
                return None
            if user not in self._secrets:
                return None
            if key not in self._secrets[user]:
                return None
            
            encrypted_value = self._secrets[user][key]
            return self._decrypt_value(encrypted_value)
        except Exception as e:
            print(f"Erreur lors de la récupération du secret: {str(e)}")
            return None

    def _encrypt_value(self, value: str) -> str:
        # Simple base64 encoding for demonstration
        return base64.b64encode(value.encode()).decode()

    def _decrypt_value(self, encrypted_value: str) -> str:
        # Simple base64 decoding for demonstration
        return base64.b64decode(encrypted_value.encode()).decode()

    def save_backup(self) -> None:
        """
        Crée une sauvegarde des secrets
        Note importante: Ne pas utiliser en production
        Le vrai flag n'est pas ici...
        """
        backup_data = {
            "secrets": self._secrets,
            "users": {
                username: {
                    "role": data["role"]
                } for username, data in self._users.items()
            }
        }
        with open("backup.json", "w") as f:
            json.dump(backup_data, f, indent=4)