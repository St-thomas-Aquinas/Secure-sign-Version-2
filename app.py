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
    send_from_directory,
    url_for
)

from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization

from twilio.twiml.messaging_response import MessagingResponse


# =========================
# APP CONFIG
# =========================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "CHANGE_THIS_SECRET")

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)


# =========================
# DATABASE
# =========================

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")


# =========================
# INIT DB
# =========================

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


# =========================
# HELPERS
# =========================

SIGNATURE_MARKER = b"__SIGNATURE_BLOCK__"

def derive_key(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

def get_file_hash(data: bytes):
    return hashlib.sha256(data).digest()


# =========================
# USERS
# =========================

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

    return row[0]


def get_users():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT username FROM users")
    users = cur.fetchall()

    conn.close()
    return users


# =========================
# SIGN FILE
# =========================

def sign_file(file_path, username, private_key, comment=""):
    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER in data:
        original_data, meta = data.split(SIGNATURE_MARKER)
    else:
        original_data = data

    file_hash = get_file_hash(original_data)
    signature = private_key.sign(file_hash)

    entry = {
        "signer": username,
        "comment": comment,
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": get_public_key(username)
    }

    metadata = {"signatures": [entry]}
    meta_bytes = json.dumps(metadata).encode()

    output = f"signed_{uuid.uuid4().hex}.bin"
    path = os.path.join(SIGNED_FOLDER, output)

    with open(path, "wb") as f:
        f.write(original_data)
        f.write(SIGNATURE_MARKER)
        f.write(meta_bytes)

    return output


# =========================
# VERIFY
# =========================

def verify_file(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER not in data:
        return False, "No signature found"

    original, meta = data.split(SIGNATURE_MARKER)

    try:
        metadata = json.loads(meta.decode())
    except:
        return False, "Corrupted metadata"

    results = []
    current_hash = get_file_hash(original)

    for sig in metadata.get("signatures", []):

        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"]))
        signature = bytes.fromhex(sig["signature"])

        try:
            pub.verify(signature, current_hash)
            results.append(f"{sig['signer']} ✔ VALID")
        except:
            results.append(f"{sig['signer']} ❌ INVALID")

    return True, "\n".join(results)


# =========================
# ROUTES
# =========================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        register_user(request.form["username"], request.form["password"])
        return redirect("/login")
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


# =========================
# DASHBOARD (FIXED + USERS)
# =========================

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    signed_file = None

    users = get_users()

    if request.method == "POST":

        file = request.files.get("file")

        if not file or file.filename == "":
            flash("No file selected")
            return redirect("/dashboard")

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        private_key = load_private_key(session["username"], session["password"])

        signed_file = sign_file(path, session["username"], private_key)

        flash("Document signed")

    return render_template(
        "dashboard.html",
        signed_file=signed_file,
        users=users
    )


# =========================
# DOWNLOAD
# =========================

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(SIGNED_FOLDER, filename, as_attachment=True)


# =========================
# VERIFY
# =========================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        file = request.files.get("file")

        if file:
            path = os.path.join(UPLOAD_FOLDER, f"verify_{uuid.uuid4().hex}")
            file.save(path)

            _, result = verify_file(path)

    return render_template("verify.html", result=result)


# =========================
# FORWARD (UI ACTION)
# =========================

@app.route("/forward_document", methods=["POST"])
def forward_document():

    if "username" not in session:
        return redirect("/login")

    forward_to = request.form.get("forward_to")
    copy_to = request.form.get("copy_to")

    flash(f"Forwarded to {forward_to}, copied to {copy_to}")

    return redirect("/dashboard")


# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
