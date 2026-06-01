import os
import uuid
import hashlib
import base64
import json
import psycopg2
import requests

from requests.auth import HTTPBasicAuth

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    flash,
    session,
    send_from_directory
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)

from cryptography.hazmat.primitives import serialization

from twilio.twiml.messaging_response import MessagingResponse

# =========================================
# APP CONFIG
# =========================================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================================
# DATABASE
# =========================================

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

# =========================================
# INIT DB
# =========================================

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
# HELPERS
# =========================================

SIGNATURE_MARKER = b"__SIGNATURE_BLOCK__"

def derive_key(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

def get_file_hash(data: bytes):
    return hashlib.sha256(data).digest()

# =========================================
# USER KEY MANAGEMENT
# =========================================

def register_user(username, password):

    conn = get_db()
    cur = conn.cursor()

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    cipher = Fernet(derive_key(password))
    encrypted_private = cipher.encrypt(private_bytes)

    cur.execute("""
    INSERT INTO users (username, password_hash, public_key, encrypted_private_key)
    VALUES (%s, %s, %s, %s)
    """, (
        username,
        generate_password_hash(password),
        public_bytes.hex(),
        encrypted_private.decode()
    ))

    conn.commit()
    conn.close()

def load_private_key(username, password):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT encrypted_private_key FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise Exception("User not found")

    cipher = Fernet(derive_key(password))
    private_bytes = cipher.decrypt(row[0].encode())

    return Ed25519PrivateKey.from_private_bytes(private_bytes)

def get_public_key(username):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT public_key FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise Exception("Public key not found")

    return row[0]

# =========================================
# SIGN FILE (COMMENT RESTORED)
# =========================================

def sign_file(file_path, username, private_key, comment=""):

    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER in data:
        original, meta = data.split(SIGNATURE_MARKER)
        try:
            metadata = json.loads(meta.decode())
            signatures = metadata.get("signatures", [])
        except:
            signatures = []
    else:
        original = data
        signatures = []

    file_hash = get_file_hash(original)
    signature = private_key.sign(file_hash)

    entry = {
        "signer": username,
        "comment": comment,   # ✅ RESTORED
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": get_public_key(username)
    }

    signatures.append(entry)

    metadata = json.dumps({"signatures": signatures}).encode()

    output_name = f"signed_{uuid.uuid4().hex}.bin"
    output_path = os.path.join(SIGNED_FOLDER, output_name)

    with open(output_path, "wb") as f:
        f.write(original)
        f.write(SIGNATURE_MARKER)
        f.write(metadata)

    return output_name

# =========================================
# VERIFY FILE
# =========================================

def verify_file(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER not in data:
        return False, "No signatures found"

    try:
        original, meta = data.split(SIGNATURE_MARKER)
        metadata = json.loads(meta.decode())
    except:
        return False, "Corrupted file"

    signatures = metadata.get("signatures", [])
    current_hash = get_file_hash(original)

    results = []

    for sig in signatures:

        signer = sig["signer"]
        comment = sig.get("comment", "")
        signature = bytes.fromhex(sig["signature"])
        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(sig["public_key"])
        )

        try:
            public_key.verify(signature, current_hash)
            results.append(f"{signer}: VALID | {comment}")
        except:
            results.append(f"{signer}: INVALID")

    return True, "\n".join(results)

# =========================================
# ROUTES
# =========================================

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    signed_file = None

    if request.method == "POST":

        file = request.files.get("file")
        comment = request.form.get("comment", "")

        if not file or file.filename == "":
            flash("No file selected")
            return redirect("/dashboard")

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        private_key = load_private_key(session["username"], session["password"])

        signed_file = sign_file(path, session["username"], private_key, comment)

        flash("Document signed successfully")

    return render_template("dashboard.html", signed_file=signed_file)

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        file = request.files.get("file")

        if file and file.filename != "":
            path = os.path.join(UPLOAD_FOLDER, f"verify_{uuid.uuid4().hex}_{file.filename}")
            file.save(path)

            valid, result = verify_file(path)

    return render_template("verify.html", result=result)

@app.route("/incoming")
def incoming():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT id, document_name, created_by, status
    FROM documents
    WHERE current_holder=%s
    ORDER BY id DESC
    """, (session["username"],))

    docs = cur.fetchall()
    conn.close()

    return render_template("incoming.html", docs=docs)

@app.route("/sent")
def sent():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT id, document_name, current_holder, status, step, created_at
    FROM documents
    WHERE created_by=%s
    ORDER BY id DESC
    """, (session["username"],))

    docs = cur.fetchall()
    conn.close()

    return render_template("sent.html", docs=docs)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# =========================================
# RUN
# =========================================

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
