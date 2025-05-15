import hashlib
import secrets
import time

class TokenManager:
    def __init__(self):
        self.tokens = {}
        self.max_age = 3600  # 1 hour

    def generate_token(self, user_id):
        token = secrets.token_hex(16)
        self.tokens[token] = {
            'user_id': user_id,
            'created_at': time.time()
        }
        return token

    def validate_token(self, token):
        if token not in self.tokens:
            return False
        
        token_data = self.tokens[token]
        if time.time() - token_data['created_at'] > self.max_age:
            del self.tokens[token]
            return False
        
        return True

    def execute_command(self, token, command):
        if not self.validate_token(token):
            raise ValueError("Invalid or expired token")
        
        # TODO: Implement secure command execution
        print(f"Executing command: {command}")

if __name__ == "__main__":
    manager = TokenManager()
    token = manager.generate_token("user123")
    print(f"Generated token: {token}")
    print(f"Token valid: {manager.validate_token(token)}") 