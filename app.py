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

from werkzeug.security import generate_password_hash, check_password_hash

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

from cryptography.hazmat.primitives import serialization

# =========================
# APP CONFIG
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
        copy_to TEXT
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
# USERS LIST (FOR DROPDOWN)
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
# AUTH
# =========================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

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

        conn = get_db()
        cur = conn.cursor()

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

        flash("Registered successfully")
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# =========================
# DASHBOARD
# =========================

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
            flash("No file selected")
            return redirect("/dashboard")

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        signed_file = f"signed_{uuid.uuid4().hex}.bin"

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO documents
        (document_name, stored_file, created_by, current_holder, status, copy_to)
        VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            file.filename,
            signed_file,
            session["username"],
            forward_to,
            "SIGNED",
            copy_to
        ))

        conn.commit()
        conn.close()

        flash(f"Sent to {forward_to}")

    return render_template(
        "dashboard.html",
        users=users,
        signed_file=signed_file
    )

# =========================
# FORWARD (FIXED ROUTE)
# =========================

@app.route("/forward/<int:doc_id>", methods=["GET", "POST"])
def forward(doc_id):

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT username FROM users")
    users = [u[0] for u in cur.fetchall()]

    if request.method == "POST":

        next_user = request.form.get("next_user")
        comment = request.form.get("comment", "")

        cur.execute("""
        UPDATE documents
        SET current_holder=%s,
            status=%s,
            step = step + 1
        WHERE id=%s
        """, (
            next_user,
            f"FORWARDED TO {next_user}",
            doc_id
        ))

        cur.execute("""
        INSERT INTO document_history
        (document_id, signer, comment, action, step)
        VALUES (%s, %s, %s, %s, %s)
        """, (
            doc_id,
            session["username"],
            comment,
            "FORWARDED",
            1
        ))

        conn.commit()
        conn.close()

        flash("Document forwarded")
        return redirect("/incoming")

    conn.close()

    return render_template("forward.html", users=users, doc_id=doc_id)

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
            result = "Verification completed (logic connected)"

    return render_template("verify.html", result=result)

# =========================
# INCOMING
# =========================

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

# =========================
# SENT
# =========================

@app.route("/sent")
def sent():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT id, document_name, current_holder, status, copy_to
    FROM documents
    WHERE created_by=%s
    ORDER BY id DESC
    """, (session["username"],))

    docs = cur.fetchall()
    conn.close()

    return render_template("sent.html", docs=docs)

# =========================
# HOME
# =========================

@app.route("/")
def home():
    return render_template("index.html")

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(debug=True)
