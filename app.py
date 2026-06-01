import os
import uuid
import hashlib
import base64
import json
import psycopg2
import logging

from flask import (
    Flask, render_template, request, redirect, 
    flash, session, send_from_directory, url_for, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# =========================================
# APP CONFIG
# =========================================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Use absolute paths to prevent 404s on cloud deployments
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
SIGNED_FOLDER = os.path.join(BASE_DIR, "signed")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================================
# DATABASE
# =========================================
DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        encrypted_private_key TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        document_name TEXT,
        stored_file TEXT,
        created_by TEXT,
        current_holder TEXT,
        status TEXT,
        step INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS document_history (
        id SERIAL PRIMARY KEY,
        document_id INTEGER,
        signer TEXT,
        comment TEXT,
        action TEXT,
        step INTEGER DEFAULT 1,
        signed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

# =========================================
# CRYPTO & SIGNING HELPERS
# =========================================
SIGNATURE_MARKER = b"__SIGNATURE_BLOCK__"

def derive_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def get_file_hash(data: bytes):
    return hashlib.sha256(data).digest()

def register_user(username, password):
    conn = get_db()
    cur = conn.cursor()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    public_bytes = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    cipher = Fernet(derive_key(password))
    encrypted_private = cipher.encrypt(private_bytes)
    cur.execute("INSERT INTO users (username, password_hash, public_key, encrypted_private_key) VALUES (%s, %s, %s, %s)", (username, generate_password_hash(password), public_bytes.hex(), encrypted_private.decode()))
    conn.commit()
    conn.close()

def load_private_key(username, password):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT encrypted_private_key FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()
    if not row: raise Exception("User not found")
    cipher = Fernet(derive_key(password))
    return Ed25519PrivateKey.from_private_bytes(cipher.decrypt(row[0].encode()))

def get_public_key(username):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()
    if not row: raise Exception("Public key not found")
    return row[0]

def sign_file(file_path, username, private_key, comment=""):
    with open(file_path, "rb") as f:
        data = f.read()
    existing_signatures = []
    if SIGNATURE_MARKER in data:
        original_data, metadata_bytes = data.split(SIGNATURE_MARKER)
        try:
            metadata = json.loads(metadata_bytes.decode())
            existing_signatures = metadata.get("signatures", [])
        except: pass
    else:
        original_data = data
    file_hash = get_file_hash(original_data)
    signature = private_key.sign(file_hash)
    signature_entry = {"signer": username, "comment": comment, "signature": signature.hex(), "hash": file_hash.hex(), "public_key": get_public_key(username), "algorithm": "Ed25519"}
    existing_signatures.append(signature_entry)
    metadata = {"signatures": existing_signatures}
    metadata_bytes = json.dumps(metadata).encode()
    extension = os.path.splitext(file_path)[1]
    output_name = f"signed_{uuid.uuid4().hex}{extension}"
    output_path = os.path.join(SIGNED_FOLDER, output_name)
    with open(output_path, "wb") as f:
        f.write(original_data)
        f.write(SIGNATURE_MARKER)
        f.write(metadata_bytes)
    app.logger.info(f"Saved signed file: {output_path}")
    return output_name

# =========================================
# ROUTES
# =========================================
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            register_user(request.form["username"], request.form["password"])
            flash("Registration successful")
            return redirect("/login")
        except Exception as e: flash(str(e))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        conn.close()
        if row and check_password_hash(row[0], password):
            session["username"] = username
            session["password"] = password
            return redirect("/dashboard")
        flash("Invalid login")
    return render_template("login.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        return redirect("/login")
    signed_file = None
    if request.method == "POST":
        try:
            if "file" not in request.files or request.files["file"].filename == "":
                flash("Please select a valid file")
                return redirect("/dashboard")
            file = request.files["file"]
            comment = request.form.get("comment", "")
            path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
            file.save(path)
            private_key = load_private_key(session["username"], session["password"])
            signed_file = sign_file(path, session["username"], private_key, comment)
            conn = get_db()
            cur = conn.cursor()
            cur.execute("INSERT INTO documents (document_name, stored_file, created_by, current_holder, status, step) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id", (file.filename, signed_file, session["username"], session["username"], "SIGNED", 1))
            doc_id = cur.fetchone()[0]
            cur.execute("INSERT INTO document_history (document_id, signer, comment, action, step) VALUES (%s, %s, %s, %s, %s)", (doc_id, session["username"], comment, "DOCUMENT CREATED", 1))
            conn.commit()
            conn.close()
            flash("Document signed successfully")
        except Exception as e:
            app.logger.error(f"Sign error: {e}")
            flash(f"Error: {str(e)}")
    return render_template("dashboard.html", signed_file=signed_file)

@app.route("/download/<filename>")
def download(filename):
    """Simple, reliable download route"""
    if "username" not in session:
        return redirect("/login")
    
    file_path = os.path.join(SIGNED_FOLDER, filename)
    if not os.path.exists(file_path):
        app.logger.error(f"Download failed: File not found -> {file_path}")
        abort(404, description="File not found on server.")
    
    return send_from_directory(SIGNED_FOLDER, filename, as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# =========================================
# START
# =========================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
