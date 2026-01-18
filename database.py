import mysql.connector
from datetime import datetime

DB_CONFIG = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': 'root',
    'database': 'Secureshare'
}

def get_db_connection():
    """Create a new database connection."""
    conn = mysql.connector.connect(**DB_CONFIG)
    return conn

def init_db():
    """Initialize the database and tables."""
    try:
        # Connect to MySQL server (without DB) to create DB
        conn = mysql.connector.connect(
            host=DB_CONFIG['host'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password']
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
        conn.close()
        
        # Connect to the DB
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Users Table (Already created by user)
        # files Table (Already created by user)
        pass

    except mysql.connector.Error as err:
        print(f"Error checking database: {err}")

def add_user(username, email, password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # User defined table 'Users' with column 'password_hash'
        cursor.execute("INSERT INTO Users (username, email, password_hash) VALUES (%s, %s, %s)", 
                       (username, email, password_hash))
        conn.commit()
        return True
    except mysql.connector.IntegrityError:
        return False
    except mysql.connector.Error as err:
        print(f"Database Error: {err}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_user(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    # User defined table 'Users'
    cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    
    # Adapt to app's expected keys if necessary
    if user:
        user['password'] = user['password_hash'] # Map for compatibility
        
    return user

def save_file_metadata(original_filename, file_path, uploaded_by_id, shared_key, share_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Schema: original_filename, file_path, uploaded_by (int), shared_key (blob), share_id
        cursor.execute(
            "INSERT INTO files (original_filename, file_path, uploaded_by, shared_key, share_id) VALUES (%s, %s, %s, %s, %s)",
            (original_filename, file_path, uploaded_by_id, shared_key, share_id)
        )
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Error saving file: {err}")
    finally:
        cursor.close()
        conn.close()

def get_file_metadata(share_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE share_id = %s", (share_id,))
    file = cursor.fetchone()
    cursor.close()
    conn.close()
    return file

def get_user_files(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM files WHERE uploaded_by = %s ORDER BY uploaded_at DESC", (user_id,))
    files = cursor.fetchall()
    
    # Detect Algorithm based on shared_key content
    for file in files:
        key_data = file.get('shared_key')
        if key_data and isinstance(key_data, bytes) and b'-----BEGIN PUBLIC KEY-----' in key_data:
             file['algorithm'] = 'RSA'
        elif key_data and isinstance(key_data, str) and '-----BEGIN PUBLIC KEY-----' in key_data:
             file['algorithm'] = 'RSA'
        else:
             file['algorithm'] = 'AES'

    cursor.close()
    conn.close()
    return files

def update_file_key(share_id, new_key):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE files SET shared_key = %s WHERE share_id = %s",
            (new_key, share_id)
        )
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Error updating file key: {err}")
    finally:
        cursor.close()
        conn.close()

def delete_file(share_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM files WHERE share_id = %s", (share_id,))
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Error deleting file record: {err}")
    finally:
        cursor.close()
        conn.close()