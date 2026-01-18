from cryptography.fernet import Fernet

def decrypt_file(encrypted_data, key):
    """
    Decrypts file data using the provided Fernet key.
    
    Args:
        encrypted_data (bytes): Encrypted content.
        key (bytes): The Fernet key.
        
    Returns:
        bytes: Decrypted file data.
    """
    f = Fernet(key)
    return f.decrypt(encrypted_data)
