from cryptography.fernet import Fernet
import base64
import hashlib

def generate_key_from_password(password: str) -> bytes:
    """Generates a Fernet key from a password using SHA256."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())
