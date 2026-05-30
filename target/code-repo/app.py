import os
import subprocess

import paramiko
import requests
import yaml
from PIL import Image
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for, jsonify)

import db
import utils

app = Flask(__name__)

# B105: hardcoded secret key
app.secret_key = "supersecretkey123"

# B105: hardcoded API credentials
INTERNAL_API_KEY = "sk-internal-abc123xyz"
ADMIN_PASSWORD = "admin"


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path="config.yaml"):
    if os.path.exists(path):
        with open(path) as f:
            # B506: yaml.load without Loader= argument
            return yaml.load(f)
    return {}


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = db.find_user(username)
        if user and utils.verify_password(password, user[2]):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["is_admin"] = bool(user[4])
            return redirect(url_for("index"))
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form.get("email", "")
        pw_hash = utils.hash_password(password)
        try:
            db.create_user(username, pw_hash, email)
            flash("Account created. Please log in.")
            return redirect(url_for("login"))
        except Exception as e:
            error = str(e)
    return render_template("register.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("index.html", username=session.get("username"))


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

@app.route("/users")
def users():
    if "user_id" not in session:
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    results = []
    if q:
        # passes user input directly — SQL injection via db.find_user
        row = db.find_user(q)
        if row:
            results = [row]
    email_results = []
    eq = request.args.get("email", "")
    if eq:
        row = db.find_user_by_email(eq)
        if row:
            email_results = [row]
    return render_template("users.html", results=results, email_results=email_results, q=q, eq=eq)


# ---------------------------------------------------------------------------
# File manager
# ---------------------------------------------------------------------------

@app.route("/files")
def files():
    if "user_id" not in session:
        return redirect(url_for("login"))
    os.makedirs("uploads", exist_ok=True)
    file_list = os.listdir("uploads")
    return render_template("files.html", files=file_list)


@app.route("/files/download")
def files_download():
    if "user_id" not in session:
        return redirect(url_for("login"))
    filename = request.args.get("file", "")
    # Path traversal + B602: shell=True with unsanitized user input
    filepath = os.path.join("uploads", filename)
    result = subprocess.call(["sh", "-c", "cat " + filepath], shell=True)
    return f"Exit code: {result}"


@app.route("/files/upload", methods=["POST"])
def files_upload():
    if "user_id" not in session:
        return redirect(url_for("login"))
    f = request.files.get("file")
    if f:
        os.makedirs("uploads", exist_ok=True)
        # No filename sanitization — client-supplied name used directly
        save_path = os.path.join("uploads", f.filename)
        f.save(save_path)
        try:
            img = Image.open(save_path)
            img.thumbnail((128, 128))
        except Exception:
            pass
        flash(f"Uploaded {f.filename}")
    return redirect(url_for("files"))


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------

@app.route("/diag")
def diag():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("diag.html")


@app.route("/diag/ssh", methods=["GET", "POST"])
def diag_ssh():
    if "user_id" not in session:
        return redirect(url_for("login"))
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=username, password=password, timeout=5)
            _, stdout, _ = client.exec_command("whoami")
            output = stdout.read().decode()
            client.close()
        except Exception as e:
            output = f"Error: {e}"
    return render_template("diag.html", ssh_output=output)


@app.route("/diag/ping", methods=["GET", "POST"])
def diag_ping():
    if "user_id" not in session:
        return redirect(url_for("login"))
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        # B602: subprocess with shell=True and unsanitized user input — command injection
        output = subprocess.check_output("ping -c 1 " + host, shell=True,
                                         stderr=subprocess.STDOUT).decode()
    return render_template("diag.html", output=output)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.route("/api/token")
def api_token():
    if "user_id" not in session:
        return jsonify({"error": "unauthenticated"}), 401
    token = utils.generate_token()
    db.store_token(session["user_id"], token)
    return jsonify({"token": token})


# ---------------------------------------------------------------------------
# Health proxy (justifies requests + yaml dependencies)
# ---------------------------------------------------------------------------

@app.route("/health")
def health_proxy():
    """Proxy to an upstream health endpoint (justifies requests dependency)."""
    cfg = load_config()
    upstream = cfg.get("upstream_health_url", "http://localhost:5001/health")
    try:
        resp = requests.get(upstream, timeout=3)
        return jsonify({"status": resp.status_code, "body": resp.text[:200]})
    except Exception as e:
        return jsonify({"error": str(e)}), 502


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    db.init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
