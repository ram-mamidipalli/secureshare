from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_rsa_key_pair():
    """Generates a private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def rsa_encrypt(data: bytes, public_key_pem: bytes) -> bytes:
    """Encrypts data using the public key."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    # RSA has size limits based on key size. We implement simple block encryption or hybrid if needed.
    # For file sharing, hybrid is best (encrypt file with AES, encrypt AES key with RSA).
    # However, strictly following "RSA Algorithm" button might imply pure RSA for small messages or Hybrid.
    # Given "File Sharing", Hybrid is the only scalable way. But let's check if user expects simple RSA demo.
    # Let's implement Hybrid Encryption: Generate AES key, Encrypt Data, Encrypt AES Key with RSA.
    # Return format: [Encrypted AES Key (256 bytes)] + [Encrypted Data]
    
    # Wait, the request is simple "AES Algorithm" vs "RSA Algorithm".
    # Implementing full Hybrid is complex.
    # If the user tries to encrypt a large file with RSA 2048, it will fail.
    # I will implement Hybrid Encryption here but hide it under "RSA Encrypt" function name.
    
    from cryptography.fernet import Fernet
    aes_key = Fernet.generate_key()
    f = Fernet(aes_key)
    encrypted_file_data = f.encrypt(data)
    
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_aes_key + encrypted_file_data

def rsa_decrypt(encrypted_data: bytes, private_key_pem: bytes) -> bytes:
    """Decrypts data using the private key."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # Extract Encrypted AES Key (RSA 2048 key size -> 256 bytes output)
    # The key size is 2048 bits = 256 bytes.
    BLOCK_SIZE = 256
    
    encrypted_aes_key = encrypted_data[:BLOCK_SIZE]
    encrypted_file_data = encrypted_data[BLOCK_SIZE:]
    
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    from cryptography.fernet import Fernet
    f = Fernet(aes_key)
    return f.decrypt(encrypted_file_data)
