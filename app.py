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
# INIT DATABASE
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
        step INTEGER DEFAULT 0,
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
        step INTEGER,
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

WORKFLOW = [
    "CHAIR",
    "DEAN",
    "DIRECTOR",
    "REGISTRAR"
]

def derive_key(password):
    return base64.urlsafe_b64encode(
        hashlib.sha256(password.encode()).digest()
    )

def get_file_hash(data: bytes):
    return hashlib.sha256(data).digest()


# =========================================
# USER KEYS
# =========================================

def load_private_key(username, password):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT encrypted_private_key FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    conn.close()

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


# =========================================
# SIGN FILE (MULTI-LEVEL SAFE)
# =========================================

def sign_file(file_path, username, private_key, comment=""):
    with open(file_path, "rb") as f:
        data = f.read()

    existing = []

    if SIGNATURE_MARKER in data:
        original, meta = data.split(SIGNATURE_MARKER)
        try:
            existing = json.loads(meta.decode()).get("signatures", [])
        except:
            existing = []
    else:
        original = data

    file_hash = get_file_hash(original)

    signature = private_key.sign(file_hash)

    entry = {
        "signer": username,
        "comment": comment,
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": get_public_key(username),
        "step": len(existing) + 1
    }

    existing.append(entry)

    metadata = json.dumps({"signatures": existing}).encode()

    out_name = f"signed_{uuid.uuid4().hex}{os.path.splitext(file_path)[1]}"
    out_path = os.path.join(SIGNED_FOLDER, out_name)

    with open(out_path, "wb") as f:
        f.write(original)
        f.write(SIGNATURE_MARKER)
        f.write(metadata)

    return out_name


# =========================================
# DASHBOARD (CREATE DOC)
# =========================================

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    signed_file = None

    if request.method == "POST":

        file = request.files["file"]
        comment = request.form.get("comment", "")

        path = os.path.join(UPLOAD_FOLDER, f"{uuid.uuid4().hex}_{file.filename}")
        file.save(path)

        private_key = load_private_key(session["username"], session["password"])

        signed_file = sign_file(path, session["username"], private_key, comment)

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO documents
        (document_name, stored_file, created_by, current_holder, status, step)
        VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            file.filename,
            signed_file,
            session["username"],
            session["username"],
            "IN_PROGRESS",
            0
        ))

        conn.commit()
        conn.close()

        flash("Document created and signed")

    return render_template("dashboard.html", signed_file=signed_file)


# =========================================
# INCOMING (WHAT YOU RECEIVE)
# =========================================

@app.route("/incoming")
def incoming():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT id, document_name, created_by, status, step
    FROM documents
    WHERE current_holder=%s
    ORDER BY id DESC
    """, (session["username"],))

    docs = cur.fetchall()
    conn.close()

    return render_template("incoming.html", docs=docs)


# =========================================
# SENT (TRACK YOUR DOCUMENTS)
# =========================================

@app.route("/sent")
def sent():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT id, document_name, current_holder, status, step
    FROM documents
    WHERE created_by=%s
    ORDER BY id DESC
    """, (session["username"],))

    docs = cur.fetchall()
    conn.close()

    return render_template("sent.html", docs=docs)


# =========================================
# DOCUMENT TRACKING (ORIGINATOR VIEW)
# =========================================

@app.route("/track/<int:doc_id>")
def track(doc_id):

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM documents WHERE id=%s", (doc_id,))
    doc = cur.fetchone()

    cur.execute("""
    SELECT signer, comment, action, step, signed_at
    FROM document_history
    WHERE document_id=%s
    ORDER BY step ASC
    """, (doc_id,))

    history = cur.fetchall()

    conn.close()

    return render_template("document_view.html", doc=doc, history=history)


# =========================================
# FORWARD (WORKFLOW STEP MOVE)
# =========================================

@app.route("/forward/<int:doc_id>", methods=["POST"])
def forward(doc_id):

    if "username" not in session:
        return redirect("/login")

    next_user = request.form["next_user"]
    comment = request.form["comment"]

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT stored_file, step FROM documents WHERE id=%s", (doc_id,))
    file, step = cur.fetchone()

    path = os.path.join(SIGNED_FOLDER, file)

    private_key = load_private_key(session["username"], session["password"])

    new_file = sign_file(path, session["username"], private_key, comment)

    next_step = step + 1

    cur.execute("""
    UPDATE documents
    SET stored_file=%s,
        current_holder=%s,
        step=%s,
        status=%s
    WHERE id=%s
    """, (
        new_file,
        next_user,
        next_step,
        f"STAGE {next_step}",
        doc_id
    ))

    cur.execute("""
    INSERT INTO document_history
    (document_id, signer, comment, action, step)
    VALUES (%s,%s,%s,%s,%s)
    """, (
        doc_id,
        session["username"],
        comment,
        f"FORWARDED TO {next_user}",
        next_step
    ))

    conn.commit()
    conn.close()

    flash("Forwarded successfully")
    return redirect("/incoming")


# =========================================
# APPROVAL
# =========================================

@app.route("/approve/<int:doc_id>")
def approve(doc_id):

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    UPDATE documents
    SET status='APPROVED'
    WHERE id=%s
    """, (doc_id,))

    cur.execute("""
    INSERT INTO document_history
    (document_id, signer, comment, action, step)
    VALUES (%s,%s,%s,%s,
    (SELECT step FROM documents WHERE id=%s))
    """, (
        doc_id,
        session["username"],
        "Approved",
        "APPROVED",
        doc_id
    ))

    conn.commit()
    conn.close()

    flash("Approved")
    return redirect("/incoming")


# =========================================
# DOWNLOAD
# =========================================

@app.route("/download/<filename>")
def download(filename):
    return send_from_directory(SIGNED_FOLDER, filename, as_attachment=True)


# =========================================
# HOME / LOGIN / LOGOUT (UNCHANGED)
# =========================================

@app.route("/")
def home():
    return redirect("/login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# =========================================
# RUN
# =========================================

if __name__ == "__main__":
    app.run(debug=True)
