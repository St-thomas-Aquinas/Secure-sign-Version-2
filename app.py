import os
import uuid
import hashlib
import base64
import json
import psycopg2

from flask import (
    Flask, render_template, request,
    redirect, flash, session
)

from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

# =========================
# APP SETUP
# =========================

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secret")

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(DATABASE_URL, sslmode="require")

# =========================
# DB INIT
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
        step INTEGER DEFAULT 1
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS document_history (
        id SERIAL PRIMARY KEY,
        document_id INTEGER,
        signer TEXT,
        comment TEXT,
        action TEXT,
        step INTEGER DEFAULT 1
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
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def file_hash(data):
    return hashlib.sha256(data).digest()

# =========================
# USERS
# =========================

def get_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users")
    users = [u[0] for u in cur.fetchall()]
    conn.close()
    return users

def get_public_key(username):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()
    return row[0]

# =========================
# SIGN FILE
# =========================

def sign_file(path, username, private_key, comment=""):

    with open(path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER in data:
        original, meta = data.split(SIGNATURE_MARKER)
        try:
            meta = json.loads(meta.decode())
            sigs = meta.get("signatures", [])
        except:
            sigs = []
    else:
        original = data
        sigs = []

    sig = private_key.sign(file_hash(original))

    sigs.append({
        "signer": username,
        "comment": comment,
        "signature": sig.hex(),
        "hash": file_hash(original).hex(),
        "public_key": get_public_key(username)
    })

    meta = json.dumps({"signatures": sigs}).encode()

    out = f"signed_{uuid.uuid4().hex}.bin"
    out_path = os.path.join(SIGNED_FOLDER, out)

    with open(out_path, "wb") as f:
        f.write(original)
        f.write(SIGNATURE_MARKER)
        f.write(meta)

    return out

# =========================
# VERIFY
# =========================

def verify_file(path):

    with open(path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER not in data:
        return False, "No signature found"

    try:
        original, meta = data.split(SIGNATURE_MARKER)
        meta = json.loads(meta.decode())
    except:
        return False, "Broken file"

    results = []
    for s in meta.get("signatures", []):
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(s["public_key"]))
        sig = bytes.fromhex(s["signature"])

        try:
            pub.verify(sig, file_hash(original))
            results.append(f"{s['signer']} ✔ VALID ({s['comment']})")
        except:
            results.append(f"{s['signer']} ❌ INVALID")

    return True, "\n".join(results)

# =========================
# ROUTES
# =========================

@app.route("/")
def home():
    return render_template("index.html")

# -------------------------
# DASHBOARD (FIXED)
# -------------------------

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    users = get_users()
    signed_file = None

    if request.method == "POST":

        file = request.files.get("file")
        comment = request.form.get("comment", "")
        forward_to = request.form.get("forward_to")
        copy_to = request.form.get("copy_to")

        if not file or file.filename == "":
            flash("Select file")
            return redirect("/dashboard")

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        # dummy key (you already have real one in your full system)
        private_key = Ed25519PrivateKey.generate()

        signed_file = sign_file(path, session["username"], private_key, comment)

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO documents (document_name, stored_file, created_by, current_holder, status)
        VALUES (%s, %s, %s, %s, %s)
        """, (
            file.filename,
            signed_file,
            session["username"],
            session["username"],
            "SIGNED"
        ))

        conn.commit()
        conn.close()

        flash("Document signed")

        # You can later extend forwarding logic here
        flash(f"Forward: {forward_to}, Copy: {copy_to}")

    return render_template("dashboard.html", signed_file=signed_file, users=users)

# -------------------------
# VERIFY
# -------------------------

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":
        file = request.files.get("file")

        if file:
            path = os.path.join(UPLOAD_FOLDER, f"verify_{uuid.uuid4().hex}")
            file.save(path)

            valid, result = verify_file(path)

    return render_template("verify.html", result=result)

# -------------------------
# INCOMING
# -------------------------

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

# -------------------------
# SENT
# -------------------------

@app.route("/sent")
def sent():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT id, document_name, current_holder, status
    FROM documents
    WHERE created_by=%s
    ORDER BY id DESC
    """, (session["username"],))

    docs = cur.fetchall()
    conn.close()

    return render_template("sent.html", docs=docs)

# -------------------------
# LOGOUT
# -------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(debug=True)
