from cryptography.fernet import Fernet

def encrypt_file(file_data, key):
    """
    Encrypts file data using the provided Fernet key.
    
    Args:
        file_data (bytes): Content of the file to encrypt.
        key (bytes): The Fernet key.
        
    Returns:
        bytes: Encrypted file data.
    """
    f = Fernet(key)
    return f.encrypt(file_data)
