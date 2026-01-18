from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import io
import zipfile
import secrets
import string
from database import init_db, add_user, get_user, save_file_metadata, get_file_metadata, get_user_files
from encryption.encrypt import encrypt_file
from encryption.decrypt import decrypt_file
from encryption.key_utils import generate_key_from_password
from encryption.rsa_utils import generate_rsa_key_pair, rsa_encrypt, rsa_decrypt

app = Flask(__name__)
app.secret_key = 'supersecretkey_change_this_for_prod'

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


init_db()

def generate_share_id(length=6):
    """Generates a short unique ID for sharing."""
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

@app.route('/', methods=['GET', 'POST'])
def auth():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'register':
            username = request.form['username']
            email = request.form['email']
            password = request.form['password']
           
            hashed_pw = generate_password_hash(password)
            if add_user(username, email, hashed_pw):
                flash('Account created! Please login.', 'success')
                return redirect(url_for('auth', mode='login'))
            else:
                flash('Username already exists or Database Error.', 'error')
                return redirect(url_for('auth', mode='register'))
        
        elif action == 'login':
            username = request.form['username']
            password = request.form['password']
            user = get_user(username)
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials.', 'error')
                
    mode = request.args.get('mode', 'login')
    return render_template('auth.html', mode=mode)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('auth'))
    

    my_files = get_user_files(session['user_id'])
    return render_template('dashboard.html', username=session['username'], files=my_files)



@app.route('/aes')
def aes_options():
    if 'user_id' not in session: return redirect(url_for('auth'))
    return render_template('aes_options.html')

@app.route('/aes/encrypt', methods=['GET', 'POST'])
def aes_encrypt():
    if 'user_id' not in session: return redirect(url_for('auth'))
        
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('password')
        
        if not file or file.filename == '' or not password:
            flash('File and Password required', 'error')
            return redirect(request.url)
            
        try:
            filename = secure_filename(file.filename)
            file_data = file.read()
            
            
            key = generate_key_from_password(password)
            encrypted_data = encrypt_file(file_data, key)
            
            share_id = generate_share_id()
            enc_filename = f"{share_id}_{filename}.enc"
            filepath = os.path.join(UPLOAD_FOLDER, enc_filename)
            
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
                
           
            save_file_metadata(filename, filepath, session['user_id'], key, share_id)
            
            
            flash(f'File Uploaded Successfully!', 'success')
            return render_template('aes_options.html', share_id=share_id, filename=enc_filename)

        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
            return redirect(request.url)
                                   
    return render_template('aes_encrypt.html')

@app.route('/download/<share_id>')
def download_encrypted(share_id):
    if 'user_id' not in session: return redirect(url_for('auth'))
    
    file_record = get_file_metadata(share_id)
    if not file_record:
        abort(404)
        
    try:
        return send_file(
            file_record['file_path'],
            as_attachment=True,
            download_name=os.path.basename(file_record['file_path'])
        )
    except FileNotFoundError:
        abort(404)

@app.route('/aes/decrypt', methods=['GET', 'POST'])
def aes_decrypt():
    if 'user_id' not in session: return redirect(url_for('auth'))

    if request.method == 'POST':
        
        file = request.files.get('file')
        password = request.form.get('password')
        share_id = request.form.get('share_id') 
        
        if share_id:
            
            file_record = get_file_metadata(share_id)
            if not file_record:
                flash('Invalid Share ID', 'error')
                return redirect(request.url)
           
            try:
                with open(file_record['file_path'], 'rb') as f:
                    file_data = f.read()
                filename = file_record['original_filename']
            except FileNotFoundError:
                flash('File not found on server', 'error')
                return redirect(request.url)
        
        elif file and file.filename != '':
            
            filename = secure_filename(file.filename)
            file_data = file.read()
        else:
            flash('Please upload a file OR enter a Share ID', 'error')
            return redirect(request.url)
            
        if not password:
            flash('Password required', 'error')
            return redirect(request.url)

        try:
            key = generate_key_from_password(password)
            decrypted_data = decrypt_file(file_data, key)
            
            download_name = filename.replace('.enc', '') if filename.endswith('.enc') else 'decrypted_' + filename
            
            return send_file(
                io.BytesIO(decrypted_data),
                download_name=download_name,
                as_attachment=True
            )
            
        except Exception as e:
            flash('Decryption Failed: Incorrect Password or Corrupt File.', 'error')
            return redirect(request.url)
            
    return render_template('aes_decrypt.html')



@app.route('/rsa')
def rsa_options():
    if 'user_id' not in session: return redirect(url_for('auth'))
    return render_template('rsa_options.html')

@app.route('/rsa/generate')
def rsa_generate():
    if 'user_id' not in session: return redirect(url_for('auth'))
    
    private_pem, public_pem = generate_rsa_key_pair()
    
    
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w') as zf:
        zf.writestr('private_key.pem', private_pem)
        zf.writestr('public_key.pem', public_pem)
    memory_file.seek(0)
    
    return send_file(
        memory_file,
        download_name='rsa_keys.zip',
        as_attachment=True
    )

@app.route('/rsa/encrypt', methods=['GET', 'POST'])
def rsa_encrypt_view():
    if 'user_id' not in session: return redirect(url_for('auth'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        pub_key_file = request.files.get('public_key')
        
        if not file or not pub_key_file:
            flash('Files required', 'error')
            return redirect(request.url)
            
        try:
            filename = secure_filename(file.filename)
            file_data = file.read()
            public_key_pem = pub_key_file.read()
            
           
            encrypted_data = rsa_encrypt(file_data, public_key_pem)
            
            
            share_id = generate_share_id()
            enc_filename = f"{share_id}_{filename}.rsa.enc"
            filepath = os.path.join(UPLOAD_FOLDER, enc_filename)
            
            with open(filepath, 'wb') as f:
                f.write(encrypted_data)
                
            # For RSA Hybrid, the shared_key blob could store the Encrypted AES Key (first 256 bytes)
            # But currently `rsa_encrypt` returns (EncryptedKey + EncryptedData) as one blob.
            # We'll just store a dummy or valid marker in shared_key, or storing Public Key?
            # Storing the Public Key PEM is useful.


            # Save metadata with .rsa.enc extension so dashboard detects it
            save_file_metadata(filename + '.rsa.enc', filepath, session['user_id'], public_key_pem, share_id)
            
            flash(f'File Encrypted & Saved! Share ID: {share_id}', 'success')
            
            
            return send_file(
                io.BytesIO(encrypted_data),
                as_attachment=True,
                download_name=filename + '.rsa.enc',
                mimetype='application/octet-stream'
            )
        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
            return redirect(request.url)
            
    return render_template('rsa_encrypt.html')

@app.route('/rsa/decrypt', methods=['GET', 'POST'])
def rsa_decrypt_view():
    if 'user_id' not in session: return redirect(url_for('auth'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        priv_key_file = request.files.get('private_key')
        share_id = request.form.get('share_id')
        
        file_data = None
        filename = "decrypted_file"
        
        if share_id:
             
            file_record = get_file_metadata(share_id)
            if not file_record:
                flash('Invalid Share ID', 'error')
                return redirect(request.url)
            try:
                with open(file_record['file_path'], 'rb') as f:
                    file_data = f.read()
                filename = file_record['original_filename']
            except FileNotFoundError:
                flash('File not found', 'error')
                return redirect(request.url)
                
        elif file:
            filename = secure_filename(file.filename)
            file_data = file.read()
        
        if not file_data or not priv_key_file:
             flash('Encrypted File (or ID) and Private Key required', 'error')
             return redirect(request.url)

        try:
            private_key_pem = priv_key_file.read()
            decrypted_data = rsa_decrypt(file_data, private_key_pem)
            
            download_name = filename.replace('.rsa.enc', '') if filename.endswith('.rsa.enc') else 'decrypted_' + filename
            
            return send_file(
                io.BytesIO(decrypted_data),
                download_name=download_name,
                as_attachment=True
            )
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
            return redirect(request.url)
            
    return render_template('rsa_decrypt.html')

@app.route('/reencrypt/<share_id>', methods=['POST'])
def reencrypt_file(share_id):
    if 'user_id' not in session: return redirect(url_for('auth'))

    # Removed global password check to allow RSA key file flow
    file_record = get_file_metadata(share_id)
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Check ownership
    if file_record['uploaded_by'] != session['user_id']:
         flash('Unauthorized', 'error')
         return redirect(url_for('dashboard'))

    try:
        # Check for RSA Re-encryption (File Uploads)
        old_priv_key_file = request.files.get('old_private_key')
        
        # We only check for old_priv_key_file for RSA flow now
        if old_priv_key_file:
            # --- RSA FLOW ---
            with open(file_record['file_path'], 'rb') as f:
                encrypted_data = f.read()

            old_priv_key_pem = old_priv_key_file.read()

            try:
                decrypted_data = rsa_decrypt(encrypted_data, old_priv_key_pem)
            except Exception:
                flash('Incorrect Old Private Key', 'error')
                return redirect(url_for('dashboard'))
                
            # Generate NEW Keys
            new_priv_pem, new_pub_pem = generate_rsa_key_pair()
            
            # Re-encrypt with new Public Key
            new_encrypted_data = rsa_encrypt(decrypted_data, new_pub_pem)
            
            # Save File
            with open(file_record['file_path'], 'wb') as f:
                f.write(new_encrypted_data)
            
            # Update DB
            from database import update_file_key
            update_file_key(share_id, new_pub_pem)

            # Return New Keys as Download
            memory_file = io.BytesIO()
            with zipfile.ZipFile(memory_file, 'w') as zf:
                zf.writestr('new_private_key.pem', new_priv_pem)
                zf.writestr('new_public_key.pem', new_pub_pem)
            memory_file.seek(0)
            
            return send_file(
                memory_file,
                download_name=f'new_keys_{share_id}.zip',
                as_attachment=True
            )

        # --- AES FLOW ---
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        if not old_password or not new_password:
             # If we are here, it means neither RSA files nor Passwords were fully provided
             flash('Credentials required (Password or Keys)', 'error')
             return redirect(url_for('dashboard'))
        
        # 1. Decrypt with Old Password
        with open(file_record['file_path'], 'rb') as f:
            encrypted_data = f.read()

        old_key = generate_key_from_password(old_password)
        try:
            decrypted_data = decrypt_file(encrypted_data, old_key)
        except Exception:
            flash('Incorrect Old Password', 'error')
            return redirect(url_for('dashboard'))

        # 2. Encrypt with New Password
        new_key = generate_key_from_password(new_password)
        new_encrypted_data = encrypt_file(decrypted_data, new_key)

        # 3. Save to Disk
        with open(file_record['file_path'], 'wb') as f:
            f.write(new_encrypted_data)

        # 4. Update Database
        from database import update_file_key
        update_file_key(share_id, new_key)

        flash('File re-encrypted successfully with new key', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f'Re-encryption failed: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/delete/<share_id>', methods=['POST'])
def delete_file_route(share_id):
    if 'user_id' not in session: return redirect(url_for('auth'))
    
    file_record = get_file_metadata(share_id)
    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))
        
    # Check ownership
    if file_record['uploaded_by'] != session['user_id']:
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
        
    try:
        # Delete from Disk
        if os.path.exists(file_record['file_path']):
            os.remove(file_record['file_path'])
            
        # Delete from Database
        from database import delete_file
        delete_file(share_id)
        
        flash('File deleted successfully', 'success')
    except Exception as e:
        flash(f'Delete failed: {str(e)}', 'error')
        
    return redirect(url_for('dashboard'))

@app.route('/view_file/<share_id>', methods=['POST'])
def view_file(share_id):
    if 'user_id' not in session: return redirect(url_for('auth'))

    file_record = get_file_metadata(share_id)

    if not file_record:
        flash('File not found', 'error')
        return redirect(url_for('dashboard'))

    try:
        # Check for RSA Key File
        private_key_file = request.files.get('private_key')
        password = request.form.get('password')

        decrypted_data = None

        with open(file_record['file_path'], 'rb') as f:
            encrypted_data = f.read()

        if private_key_file:
            # RSA Decryption
            private_key_pem = private_key_file.read()
            decrypted_data = rsa_decrypt(encrypted_data, private_key_pem)
        
        elif password:
             # AES Decryption
             key = generate_key_from_password(password)
             decrypted_data = decrypt_file(encrypted_data, key)
        
        else:
             flash('Credentials required', 'error')
             return redirect(url_for('dashboard'))

        # Stream decrypted data to browser
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=file_record['original_filename'],
            as_attachment=False 
        )

    except Exception as e:
        flash(f'Decryption failed: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
