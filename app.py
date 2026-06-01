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

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")

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

    # USERS TABLE
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        public_key TEXT,
        encrypted_private_key TEXT
    )
    """)

    # DOCUMENTS TABLE
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

    # DOCUMENT HISTORY TABLE
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

# =========================================
# AUTO MIGRATION
# =========================================

def migrate_db():

    conn = get_db()
    cur = conn.cursor()

    # ADD STEP COLUMN TO DOCUMENTS
    cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name='documents'
            AND column_name='step'
        ) THEN
            ALTER TABLE documents
            ADD COLUMN step INTEGER DEFAULT 1;
        END IF;
    END $$;
    """)

    # ADD STEP COLUMN TO HISTORY
    cur.execute("""
    DO $$
    BEGIN
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_name='document_history'
            AND column_name='step'
        ) THEN
            ALTER TABLE document_history
            ADD COLUMN step INTEGER DEFAULT 1;
        END IF;
    END $$;
    """)

    conn.commit()
    conn.close()

with app.app_context():
    init_db()
    migrate_db()

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

    if not row:
        raise Exception("User not found")

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

    if not row:
        raise Exception("Public key not found")

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

    signature_entry = {
        "signer": username,
        "comment": comment,
        "signature": signature.hex(),
        "hash": file_hash.hex(),
        "public_key": get_public_key(username),
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
# DASHBOARD (UPDATED)
# =========================================

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():

    if "username" not in session:
        return redirect("/login")

    signed_file = None

    # Fetch users for dropdowns (exclude currently logged-in user)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username != %s", (session["username"],))
    users = cur.fetchall()
    conn.close()

    if request.method == "POST":

        try:

            if "file" not in request.files:
                flash("Please select a file")
                return redirect("/dashboard")

            file = request.files["file"]

            if file.filename == "":
                flash("No selected file")
                return redirect("/dashboard")

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
                status,
                step
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """, (
                file.filename,
                signed_file,
                session["username"],
                session["username"],
                "SIGNED",
                1
            ))

            document_id = cur.fetchone()[0]

            cur.execute("""
            INSERT INTO document_history
            (
                document_id,
                signer,
                comment,
                action,
                step
            )
            VALUES (%s, %s, %s, %s, %s)
            """, (
                document_id,
                session["username"],
                comment,
                "DOCUMENT CREATED",
                1
            ))

            conn.commit()
            conn.close()

            flash("Document signed successfully")

        except Exception as e:

            flash(f"Error: {str(e)}")

    # Pass both signed_file and users to the template
    return render_template(
        "dashboard.html",
        signed_file=signed_file,
        users=users
    )

# =========================================
# FORWARD DOCUMENT (NEW ROUTE)
# =========================================

@app.route("/forward_document", methods=["POST"])
def forward_document():

    if "username" not in session:
        return redirect("/login")

    signed_file = request.form.get("file")
    forward_to = request.form.get("forward_to")
    copy_to = request.form.get("copy_to", "")
    comment = request.form.get("comment", "")

    if not forward_to:
        flash("Please select a user to forward to.")
        return redirect("/dashboard")

    conn = get_db()
    cur = conn.cursor()
    try:
        # Find the document record
        cur.execute("""
            SELECT id, step FROM documents
            WHERE stored_file = %s AND created_by = %s
            ORDER BY id DESC LIMIT 1
        """, (signed_file, session["username"]))
        doc_row = cur.fetchone()

        if not doc_row:
            flash("Document not found or already processed.")
            return redirect("/dashboard")

        doc_id, current_step = doc_row
        new_step = current_step + 1

        # 1. Update ownership & status for "Forward To"
        cur.execute("""
            UPDATE documents
            SET current_holder = %s, status = %s, step = %s
            WHERE id = %s
        """, (forward_to, f"FORWARDED TO {forward_to}", new_step, doc_id))

        # 2. Log Forward action in history
        cur.execute("""
            INSERT INTO document_history (document_id, signer, comment, action, step)
            VALUES (%s, %s, %s, %s, %s)
        """, (doc_id, session["username"], comment, f"FORWARDED TO {forward_to}", new_step))

        # 3. Handle "Copy To" separately (CC entry in history)
        if copy_to and copy_to != "":
            cur.execute("""
                INSERT INTO document_history (document_id, signer, comment, action, step)
                VALUES (%s, %s, %s, %s, %s)
            """, (doc_id, session["username"], comment, f"CC TO {copy_to}", new_step))

        conn.commit()
        flash("Document forwarded successfully!")
    except Exception as e:
        conn.rollback()
        flash(f"Error forwarding document: {str(e)}")
    finally:
        conn.close()

    return redirect("/dashboard")

# =========================================
# INCOMING DOCUMENTS
# =========================================

@app.route("/incoming")
def incoming():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT
        id,
        document_name,
        created_by,
        status
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
# SENT DOCUMENTS
# =========================================

@app.route("/sent")
def sent():

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT
        id,
        document_name,
        current_holder,
        status,
        step,
        created_at
    FROM documents
    WHERE created_by=%s
    ORDER BY id DESC
    """, (session["username"],))

    docs = cur.fetchall()

    conn.close()

    return render_template(
        "sent.html",
        docs=docs
    )

# =========================================
# DOCUMENT DETAILS
# =========================================

@app.route("/document/<int:doc_id>")
def document_details(doc_id):

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT
        id,
        document_name,
        created_by,
        current_holder,
        status,
        step,
        stored_file,
        created_at
    FROM documents
    WHERE id=%s
    """, (doc_id,))

    document = cur.fetchone()

    cur.execute("""
    SELECT
        signer,
        comment,
        action,
        step,
        signed_at
    FROM document_history
    WHERE document_id=%s
    ORDER BY id ASC
    """, (doc_id,))

    history = cur.fetchall()

    conn.close()

    return render_template(
        "document_details.html",
        document=document,
        history=history
    )

# =========================================
# FORWARD DOCUMENT (EXISTING ROUTE FOR /forward/<doc_id>)
# =========================================

@app.route("/forward/<int:doc_id>", methods=["GET", "POST"])
def forward(doc_id):

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":

        try:

            next_user = request.form["next_user"]
            comment = request.form["comment"]

            cur.execute("""
            SELECT stored_file, step
            FROM documents
            WHERE id=%s
            """, (doc_id,))

            row = cur.fetchone()

            if not row:
                flash("Document not found")
                return redirect("/incoming")

            stored_file = row[0]
            current_step = row[1]

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

            new_step = current_step + 1

            cur.execute("""
            UPDATE documents
            SET stored_file=%s,
                current_holder=%s,
                status=%s,
                step=%s
            WHERE id=%s
            """, (
                new_file,
                next_user,
                f"FORWARDED TO {next_user}",
                new_step,
                doc_id
            ))

            cur.execute("""
            INSERT INTO document_history
            (
                document_id,
                signer,
                comment,
                action,
                step
            )
            VALUES (%s, %s, %s, %s, %s)
            """, (
                doc_id,
                session["username"],
                comment,
                f"FORWARDED TO {next_user}",
                new_step
            ))

            conn.commit()
            conn.close()

            flash("Document forwarded successfully")

            return redirect("/incoming")

        except Exception as e:

            flash(f"Forward error: {str(e)}")

    conn.close()

    return render_template(
        "forward.html",
        doc_id=doc_id
    )

# =========================================
# APPROVE DOCUMENT
# =========================================

@app.route("/approve/<int:doc_id>")
def approve_document(doc_id):

    if "username" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    SELECT step
    FROM documents
    WHERE id=%s
    """, (doc_id,))

    row = cur.fetchone()

    current_step = row[0]

    cur.execute("""
    UPDATE documents
    SET status=%s
    WHERE id=%s
    """, (
        "APPROVED",
        doc_id
    ))

    cur.execute("""
    INSERT INTO document_history
    (
        document_id,
        signer,
        comment,
        action,
        step
    )
    VALUES (%s, %s, %s, %s, %s)
    """, (
        doc_id,
        session["username"],
        "Document Approved",
        "APPROVED",
        current_step
    ))

    conn.commit()
    conn.close()

    flash("Document approved successfully")

    return redirect("/incoming")

# =========================================
# VERIFY WEB
# =========================================

@app.route("/verify", methods=["GET", "POST"])
def verify():

    result = None

    if request.method == "POST":

        try:
            if "file" not in request.files:
                flash("No file uploaded")
                return redirect("/verify")

            file = request.files["file"]

            if file.filename == "":
                flash("No file selected")
                return redirect("/verify")

            path = os.path.join(
                UPLOAD_FOLDER,
                f"verify_{uuid.uuid4().hex}_{file.filename}"
            )

            file.save(path)

            valid, result = verify_file(path)

        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template("verify.html", result=result)

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
