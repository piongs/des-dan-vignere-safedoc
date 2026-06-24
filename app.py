from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
import base64
import os
import io
import json
import hashlib
from datetime import datetime
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
app.secret_key = 'securedoc-secret-2024'

UPLOAD_FOLDER = "/tmp/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ── Simple user store (username: password) ───────────────────────────────────
USERS = {
    'admin': 'admin123',
    'user1': 'password1',
}

# ── In-memory history ────────────────────────────────────────────────────────
history = []

# ── Vigenere Cipher (mod 26, hanya huruf alfabet) ────────────────────────────
def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Enkripsi Vigenere: C = (P + K) mod 26. Hanya huruf alfabet yang digeser."""
    key = key.upper()
    result = []
    ki = 0
    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base  = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)   # non-alpha tidak diubah
    return ''.join(result)

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Dekripsi Vigenere: P = (C - K + 26) mod 26."""
    key = key.upper()
    result = []
    ki = 0
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord('A')
            base  = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift + 26) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return ''.join(result)

# ── DES-CBC ──────────────────────────────────────────────────────────────────
def des_make_key(key_str: str) -> bytes:
    """Ubah kunci string → 8 byte DES key via SHA-256."""
    return hashlib.sha256(key_str.encode()).digest()[:8]

def des_encrypt(data: bytes, key_str: str) -> bytes:
    key    = des_make_key(key_str)
    cipher = DES.new(key, DES.MODE_CBC)
    ct     = cipher.encrypt(pad(data, DES.block_size))
    return cipher.iv + ct       # [IV 8 byte] + [ciphertext]

def des_decrypt(data: bytes, key_str: str) -> bytes:
    key         = des_make_key(key_str)
    iv, ct      = data[:8], data[8:]
    cipher      = DES.new(key, DES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), DES.block_size)

# ── Combined ─────────────────────────────────────────────────────────────────
def combined_encrypt(text: str, vigenere_key: str, des_key: str) -> dict:
    step1 = vigenere_encrypt(text, vigenere_key)
    step2 = des_encrypt(step1.encode('utf-8'), des_key)
    b64   = base64.b64encode(step2).decode('ascii')
    return {'vigenere_result': step1, 'final_cipher': b64}

def combined_decrypt(b64_cipher: str, vigenere_key: str, des_key: str) -> dict:
    raw    = base64.b64decode(b64_cipher)
    step1  = des_decrypt(raw, des_key).decode('utf-8')
    step2  = vigenere_decrypt(step1, vigenere_key)
    return {'des_result': step1, 'plaintext': step2}

# ── Auth helper ───────────────────────────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def add_history(mode, filename):
    history.append({
        'waktu': datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
        'mode': mode,
        'file': filename,
        'user': session.get('username', 'unknown'),
    })

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pwd   = request.form.get('password', '').strip()
        if uname in USERS and USERS[uname] == pwd:
            session['username'] = uname
            return redirect(url_for('dashboard'))
        error = 'Username atau password salah.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    enc = sum(1 for h in history if h['mode'] == 'enkripsi')
    dec = sum(1 for h in history if h['mode'] == 'dekripsi')
    recent = list(reversed(history))[:5]
    return render_template('dashboard.html',
        username=session['username'],
        total=len(history), enc=enc, dec=dec, recent=recent)

@app.route('/enkripsi')
@login_required
def enkripsi():
    return render_template('enkripsi.html', username=session['username'])

@app.route('/dekripsi')
@login_required
def dekripsi():
    return render_template('dekripsi.html', username=session['username'])

@app.route('/riwayat')
@login_required
def riwayat():
    hist = list(reversed(history))
    return render_template('riwayat.html', username=session['username'], history=hist)

@app.route('/tentang')
@login_required
def tentang():
    return render_template('tentang.html', username=session['username'])

# ── API Endpoints ─────────────────────────────────────────────────────────────
@app.route('/api/encrypt', methods=['POST'])
@login_required
def api_encrypt():
    try:
        data         = request.get_json()
        text         = data.get('text', '').strip()
        vigenere_key = data.get('vigenere_key', '').strip()
        des_key      = data.get('des_key', '').strip()

        if not text:
            return jsonify({'error': 'Teks tidak boleh kosong.'}), 400
        if not vigenere_key or not vigenere_key.isalpha():
            return jsonify({'error': 'Kunci Vigenere hanya boleh huruf alfabet (A-Z).'}), 400
        if not des_key:
            return jsonify({'error': 'Kunci DES tidak boleh kosong.'}), 400

        result = combined_encrypt(text, vigenere_key, des_key)
        add_history('enkripsi', 'teks-manual')
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt', methods=['POST'])
@login_required
def api_decrypt():
    try:
        data         = request.get_json()
        cipher       = data.get('cipher', '').strip()
        vigenere_key = data.get('vigenere_key', '').strip()
        des_key      = data.get('des_key', '').strip()

        if not cipher:
            return jsonify({'error': 'Ciphertext tidak boleh kosong.'}), 400
        if not vigenere_key or not vigenere_key.isalpha():
            return jsonify({'error': 'Kunci Vigenere hanya boleh huruf alfabet (A-Z).'}), 400
        if not des_key:
            return jsonify({'error': 'Kunci DES tidak boleh kosong.'}), 400

        result = combined_decrypt(cipher, vigenere_key, des_key)
        add_history('dekripsi', 'teks-manual')
        return jsonify({'success': True, **result})
    except Exception as e:
        return jsonify({'error': 'Dekripsi gagal. Pastikan kunci dan ciphertext benar.'}), 500

@app.route('/api/encrypt_file', methods=['POST'])
@login_required
def api_encrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Tidak ada file yang diunggah.'}), 400

        f            = request.files['file']
        vigenere_key = request.form.get('vigenere_key', '').strip()
        des_key      = request.form.get('des_key', '').strip()
        filename     = f.filename

        if not vigenere_key or not vigenere_key.isalpha():
            return jsonify({'error': 'Kunci Vigenere hanya boleh huruf alfabet (A-Z).'}), 400
        if not des_key:
            return jsonify({'error': 'Kunci DES tidak boleh kosong.'}), 400

        content = f.read()
        try:
            text    = content.decode('utf-8')
            is_text = True
        except UnicodeDecodeError:
            text    = base64.b64encode(content).decode('ascii')
            is_text = False

        result   = combined_encrypt(text, vigenere_key, des_key)
        envelope = json.dumps({
            'filename': filename,
            'is_text':  is_text,
            'cipher':   result['final_cipher'],
        }).encode('utf-8')

        add_history('enkripsi', filename)
        out = io.BytesIO(envelope)
        out.seek(0)
        return send_file(out, mimetype='application/octet-stream',
                         as_attachment=True, download_name=filename + '.enc')
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/decrypt_file', methods=['POST'])
@login_required
def api_decrypt_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Tidak ada file yang diunggah.'}), 400

        f            = request.files['file']
        vigenere_key = request.form.get('vigenere_key', '').strip()
        des_key      = request.form.get('des_key', '').strip()

        if not vigenere_key or not vigenere_key.isalpha():
            return jsonify({'error': 'Kunci Vigenere hanya boleh huruf alfabet (A-Z).'}), 400
        if not des_key:
            return jsonify({'error': 'Kunci DES tidak boleh kosong.'}), 400

        envelope  = json.loads(f.read().decode('utf-8'))
        filename  = envelope['filename']
        is_text   = envelope['is_text']
        cipher    = envelope['cipher']

        result    = combined_decrypt(cipher, vigenere_key, des_key)
        plaintext = result['plaintext']
        raw       = plaintext.encode('utf-8') if is_text else base64.b64decode(plaintext)

        add_history('dekripsi', filename)
        out = io.BytesIO(raw)
        out.seek(0)
        return send_file(out, mimetype='application/octet-stream',
                         as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': 'Dekripsi file gagal. Periksa file dan kunci Anda.'}), 500

@app.route('/api/history/clear', methods=['POST'])
@login_required
def api_clear_history():
    history.clear()
    return redirect(url_for('riwayat'))

if __name__ == '__main__':
    app.run(debug=False, port=5000)
