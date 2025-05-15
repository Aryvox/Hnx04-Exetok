import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class CryptoUtils:
    def __init__(self):
        self._key = self._generate_key()
        self._fernet = Fernet(self._key)
        self._salt = os.urandom(16)

    def _generate_key(self) -> bytes:
        """Génère une clé pour le chiffrement Fernet"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"static_salt_for_dev",  # Ne pas utiliser en production
            iterations=100000,
        )
        key = base64.b64encode(kdf.derive(b"development_key"))
        return key

    def encrypt(self, data: str) -> str:
        """Chiffre les données avec Fernet"""
        return self._fernet.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Déchiffre les données avec Fernet"""
        return self._fernet.decrypt(encrypted_data.encode()).decode() 