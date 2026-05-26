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

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "CHANGE_THIS_SECRET"
)

UPLOAD_FOLDER = "uploads"
SIGNED_FOLDER = "signed"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_FOLDER, exist_ok=True)

# =========================================
# TWILIO CONFIG
# =========================================

TWILIO_ACCOUNT_SID = os.environ.get(
    "TWILIO_ACCOUNT_SID"
)

TWILIO_AUTH_TOKEN = os.environ.get(
    "TWILIO_AUTH_TOKEN"
)

# =========================================
# DATABASE
# =========================================

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():

    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require"
    )

# =========================================
# INIT DATABASE
# =========================================

def init_db():

    conn = get_db()
    cur = conn.cursor()

    # USERS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        encrypted_private_key TEXT
    )
    """)

    # DOCUMENTS
    cur.execute("""
    CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        document_name TEXT,
        stored_file TEXT,
        created_by TEXT,
        current_holder TEXT,
        status TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # HISTORY
    cur.execute("""
    CREATE TABLE IF NOT EXISTS document_history (
        id SERIAL PRIMARY KEY,
        document_id INTEGER,
        signer TEXT,
        comment TEXT,
        action TEXT,
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
# REGISTER USER
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

    cipher = Fernet(
        derive_key(password)
    )

    encrypted_private = cipher.encrypt(
        private_bytes
    )

    cur.execute("""
    INSERT INTO users (
        username,
        password_hash,
        public_key,
        encrypted_private_key
    )
    VALUES (%s, %s, %s, %s)
    """, (
        username,
        generate_password_hash(password),
        public_bytes.hex(),
        encrypted_private.decode()
    ))

    conn.commit()
    conn.close()

# =========================================
# LOAD PRIVATE KEY
# =========================================

def load_private_key(username, password):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT encrypted_private_key
    FROM users
    WHERE username=%s
    """, (username,))

    row = cur.fetchone()

    conn.close()

    cipher = Fernet(
        derive_key(password)
    )

    private_bytes = cipher.decrypt(
        row[0].encode()
    )

    return Ed25519PrivateKey.from_private_bytes(
        private_bytes
    )

# =========================================
# GET PUBLIC KEY
# =========================================

def get_public_key(username):

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT public_key
    FROM users
    WHERE username=%s
    """, (username,))

    row = cur.fetchone()

    conn.close()

    return row[0]

# =========================================
# SIGN FILE
# =========================================

def sign_file(
    file_path,
    username,
    private_key,
    comment=""
):

    with open(file_path, "rb") as f:
        data = f.read()

    existing_signatures = []

    if SIGNATURE_MARKER in data:

        original_data, metadata_bytes = data.split(
            SIGNATURE_MARKER
        )

        try:

            metadata = json.loads(
                metadata_bytes.decode()
            )

            existing_signatures = metadata.get(
                "signatures",
                []
            )

        except:

            existing_signatures = []

    else:

        original_data = data

    file_hash = get_file_hash(
        original_data
    )

    signature = private_key.sign(
        file_hash
    )

    public_key = get_public_key(
        username
    )

    signature_entry = {
        "signer": username,
        "comment": comment,
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": public_key,
        "algorithm": "Ed25519"
    }

    existing_signatures.append(
        signature_entry
    )

    metadata = {
        "signatures": existing_signatures
    }

    metadata_bytes = json.dumps(
        metadata
    ).encode()

    extension = os.path.splitext(
        file_path
    )[1]

    output_name = (
        f"signed_{uuid.uuid4().hex}{extension}"
    )

    output_path = os.path.join(
        SIGNED_FOLDER,
        output_name
    )

    with open(output_path, "wb") as f:

        f.write(original_data)

        f.write(SIGNATURE_MARKER)

        f.write(metadata_bytes)

    return output_name

# =========================================
# VERIFY FILE
# =========================================

def verify_file(file_path):

    with open(file_path, "rb") as f:
        data = f.read()

    if SIGNATURE_MARKER not in data:

        return False, "No embedded signatures found"

    try:

        original_data, metadata_bytes = data.split(
            SIGNATURE_MARKER
        )

        metadata = json.loads(
            metadata_bytes.decode()
        )

    except:

        return False, "Corrupted metadata"

    signatures = metadata.get(
        "signatures",
        []
    )

    current_hash = get_file_hash(
        original_data
    )

    results = []

    for sig in signatures:

        signer = sig["signer"]

        signature = bytes.fromhex(
            sig["signature"]
        )

        stored_hash = bytes.fromhex(
            sig["hash"]
        )

        public_key_hex = sig["public_key"]

        comment = sig.get(
            "comment",
            ""
        )

        if current_hash != stored_hash:

            results.append(
                f"{signer}: DOCUMENT MODIFIED"
            )

            continue

        public_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(public_key_hex)
        )

        try:

            public_key.verify(
                signature,
                stored_hash
            )

            results.append(
                f"{signer}: VALID SIGNATURE | Comment: {comment}"
            )

        except:

            results.append(
                f"{signer}: INVALID SIGNATURE"
            )

    return True, "\n".join(results)

# =========================================
# HOME
# =========================================

@app.route("/")
def home():

    return render_template("index.html")

# =========================================
# REGISTER
# =========================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        try:

            register_user(
                request.form["username"],
                request.form["password"]
            )

            flash("Registration successful")

            return redirect("/login")

        except Exception as e:

            flash(str(e))

    return render_template("register.html")

# =========================================
# LOGIN
# =========================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        SELECT password_hash
        FROM users
        WHERE username=%s
        """, (username,))

        row = cur.fetchone()

        conn.close()

        if row and check_password_hash(
            row[0],
            password
        ):

            session["username"] = username
            session["password"] = password

            return redirect("/dashboard")

        flash("Invalid login")

    return render_template("login.html")

# =========================================
# DASHBOARD
# =========================================

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:

        return redirect("/login")

    signed_file = None

    if request.method == "POST":

        file = request.files["file"]

        comment = request.form.get(
            "comment",
            ""
        )

        path = os.path.join(
            UPLOAD_FOLDER,
            f"{uuid.uuid4().hex}_{file.filename}"
        )

        file.save(path)

        private_key = load_private_key(
            session["username"],
            session["password"]
        )

        signed_file = sign_file(
            path,
            session["username"],
            private_key,
            comment
        )

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO documents
        (
            document_name,
            stored_file,
            created_by,
            current_holder,
            status
        )
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

        flash("Document signed successfully")

    return render_template(
        "dashboard.html",
        signed_file=signed_file
    )

# =========================================
# INCOMING
# =========================================

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

    return render_template(
        "incoming.html",
        docs=docs
    )

# =========================================
# FORWARD
# =========================================

@app.route("/forward/<int:doc_id>", methods=["GET", "POST"])
def forward(doc_id):

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":

        next_user = request.form["next_user"]
        comment = request.form["comment"]

        cur.execute("""
        SELECT stored_file
        FROM documents
        WHERE id=%s
        """, (doc_id,))

        row = cur.fetchone()

        stored_file = row[0]

        file_path = os.path.join(
            SIGNED_FOLDER,
            stored_file
        )

        private_key = load_private_key(
            session["username"],
            session["password"]
        )

        new_file = sign_file(
            file_path,
            session["username"],
            private_key,
            comment
        )

        cur.execute("""
        UPDATE documents
        SET stored_file=%s,
            current_holder=%s,
            status=%s
        WHERE id=%s
        """, (
            new_file,
            next_user,
            "FORWARDED",
            doc_id
        ))

        cur.execute("""
        INSERT INTO document_history
        (
            document_id,
            signer,
            comment,
            action
        )
        VALUES (%s, %s, %s, %s)
        """, (
            doc_id,
            session["username"],
            comment,
            "FORWARDED"
        ))

        conn.commit()
        conn.close()

        flash("Document forwarded successfully")

        return redirect("/incoming")

    conn.close()

    return render_template(
        "forward.html",
        doc_id=doc_id
    )

# =========================================
# VERIFY
# =========================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        file = request.files["file"]

        path = os.path.join(
            UPLOAD_FOLDER,
            f"verify_{uuid.uuid4().hex}_{file.filename}"
        )

        file.save(path)

        valid, result = verify_file(path)

    return render_template(
        "verify.html",
        result=result
    )

# =========================================
# WHATSAPP BOT
# =========================================

@app.route("/whatsapp", methods=["POST"])
def whatsapp():

    resp = MessagingResponse()

    try:

        media_url = request.form.get(
            "MediaUrl0"
        )

        if not media_url:

            resp.message(
                "Send a signed document."
            )

            return str(resp)

        file_response = requests.get(
            media_url,
            auth=HTTPBasicAuth(
                TWILIO_ACCOUNT_SID,
                TWILIO_AUTH_TOKEN
            )
        )

        path = os.path.join(
            UPLOAD_FOLDER,
            f"wa_{uuid.uuid4().hex}"
        )

        with open(path, "wb") as f:
            f.write(file_response.content)

        valid, result = verify_file(path)

        resp.message(result)

    except Exception as e:

        resp.message(str(e))

    return str(resp)

# =========================================
# DOWNLOAD
# =========================================

@app.route("/download/<filename>")
def download(filename):

    return send_from_directory(
        SIGNED_FOLDER,
        filename,
        as_attachment=True
    )

# =========================================
# LOGOUT
# =========================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

# =========================================
# START
# =========================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )
