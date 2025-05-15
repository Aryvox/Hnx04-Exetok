import unittest
import base64
from unittest.mock import patch
from secret_manager import SecretManager

class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.manager = SecretManager()
        self.test_data = "test_secret_value"
        self.fake_token = "ZmFrZV90b2tlbl9mb3JfdGVzdGluZw=="  # Base64 de "fake_token_for_testing"

    def test_encryption(self):
        encrypted = self.manager._encrypt_value(self.test_data)
        decrypted = self.manager._decrypt_value(encrypted)
        self.assertEqual(self.test_data, decrypted)

    @patch('secret_manager.DEV_TOKEN')
    def test_token_validation(self, mock_token):
        mock_token.return_value = self.fake_token
        self.assertTrue(self.manager._dev_token is not None)

if __name__ == '__main__':
    unittest.main() 