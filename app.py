import os
import csv
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from io import BytesIO
from io import StringIO
from cryptography.fernet import InvalidToken
from flask import Flask, render_template, request, redirect, session, send_file, flash, jsonify
from flask_bcrypt import Bcrypt
from sqlite3 import IntegrityError
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from models.db import (
    init_db,
    create_user,
    get_user_by_username,
    create_file_record,
    get_files_by_user_id,
    get_file_for_user,
    increment_file_downloads,
    delete_file_record,
    rename_file_record,
    set_user_login_security_state,
    reset_user_login_security_state,
    log_audit_event,
    get_recent_audit_logs,
)
from services.security_services import get_cipher
from services.file_services import (
    ensure_storage_dir,
    encrypt_and_store_file,
    load_and_decrypt_file,
    delete_encrypted_file,
)

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "dev-only-change-me")
bcrypt = Bcrypt(app)
MAX_FILENAME_LENGTH = 120
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
LOGIN_RATE_LIMIT_ATTEMPTS = 10
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "docx"}
LOGIN_BUCKETS = defaultdict(deque)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("FLASK_ENV") == "production"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Create encrypted folder if missing
os.makedirs("encrypted_files", exist_ok=True)
ensure_storage_dir()
cipher = get_cipher()

init_db()


def _format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def _parse_db_timestamp(value):
    if not value:
        return None

    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _is_allowed_file(filename):
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS


def _is_rate_limited(ip_address):
    now = time.time()
    bucket = LOGIN_BUCKETS[ip_address]
    while bucket and now - bucket[0] > LOGIN_RATE_LIMIT_WINDOW_SECONDS:
        bucket.popleft()

    if len(bucket) >= LOGIN_RATE_LIMIT_ATTEMPTS:
        return True

    bucket.append(now)
    return False


def _log_event(event, status, username=None, user_id=None, details=None):
    log_audit_event(
        user_id=user_id,
        username=username,
        event=event,
        status=status,
        ip_address=request.remote_addr,
        details=details,
    )


def _generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = _generate_csrf_token


@app.before_request
def protect_post_routes_with_csrf():
    if request.method != "POST":
        return None

    session_token = session.get("_csrf_token")
    form_token = request.form.get("csrf_token")

    if not session_token or not form_token or not secrets.compare_digest(session_token, form_token):
        flash("Security validation failed. Please try again.", "error")
        return redirect(request.referrer or "/login")

    return None


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; img-src 'self' data:"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(_error):
    flash("Upload blocked: file exceeds 10 MB size limit.", "error")
    return redirect("/dashboard")

# -----------------------------
# ROUTES
# -----------------------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.", "error")
            _log_event("register", "failed", username=username, details="missing_fields")
            return redirect("/register")
        if len(password) < 10:
            flash("Password must be at least 10 characters.", "error")
            _log_event("register", "failed", username=username, details="weak_password")
            return redirect("/register")

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        try:
            create_user(username, hashed_password)
            flash("Account created. Please log in.", "success")
            _log_event("register", "success", username=username)
            return redirect("/login")
        except IntegrityError:
            flash("Username already exists.", "error")
            _log_event("register", "failed", username=username, details="username_exists")
            return redirect("/register")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr or "unknown"

        if _is_rate_limited(client_ip):
            flash("Too many login attempts. Please wait and try again.", "error")
            _log_event("login", "blocked", username=username, details="rate_limited")
            return redirect("/login")

        if not username or not password:
            flash("Username and password are required.", "error")
            _log_event("login", "failed", username=username, details="missing_fields")
            return redirect("/login")

        user = get_user_by_username(username)
        now = datetime.utcnow()

        if user and user[4]:
            locked_until = _parse_db_timestamp(user[4])
            if locked_until and now < locked_until:
                flash("Account is temporarily locked. Try again later.", "error")
                _log_event("login", "blocked", username=username, user_id=user[0], details="account_locked")
                return redirect("/login")

        if user and bcrypt.check_password_hash(user[2], password):
            reset_user_login_security_state(user[0])
            session.permanent = True
            session["user_id"] = user[0]
            session["username"] = user[1]
            flash("Logged in successfully.", "success")
            _log_event("login", "success", username=username, user_id=user[0])
            return redirect("/dashboard")

        if user:
            failed_attempts = (user[3] or 0) + 1
            locked_until_value = None
            if failed_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
                lock_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                locked_until_value = lock_until.strftime("%Y-%m-%d %H:%M:%S")
                failed_attempts = 0

            set_user_login_security_state(user[0], failed_attempts, locked_until_value)

        flash("Invalid credentials.", "error")
        _log_event("login", "failed", username=username, user_id=user[0] if user else None, details="invalid_credentials")
        return redirect("/login")

    return render_template("login.html")


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            safe_filename = secure_filename(file.filename)
            if not safe_filename:
                flash("Invalid filename.", "error")
                _log_event("upload", "failed", user_id=session["user_id"], username=session["username"], details="invalid_filename")
                return redirect("/dashboard")
            if len(safe_filename) > MAX_FILENAME_LENGTH:
                flash("Filename is too long.", "error")
                _log_event("upload", "failed", user_id=session["user_id"], username=session["username"], details="filename_too_long")
                return redirect("/dashboard")
            if not _is_allowed_file(safe_filename):
                flash("Blocked file type.", "error")
                _log_event("upload", "blocked", user_id=session["user_id"], username=session["username"], details="disallowed_extension")
                return redirect("/dashboard")

            file_id, size_bytes = encrypt_and_store_file(file, cipher)
            create_file_record(file_id, session["user_id"], safe_filename, size_bytes)
            flash("File uploaded successfully.", "success")
            _log_event("upload", "success", user_id=session["user_id"], username=session["username"], details=safe_filename)
            return redirect("/dashboard")

        flash("Please choose a file to upload.", "error")
        _log_event("upload", "failed", user_id=session["user_id"], username=session["username"], details="missing_file")
        return redirect("/dashboard")

    search_term = request.args.get("q", "").strip()
    user_files = get_files_by_user_id(session["user_id"], search_term)

    return render_template(
        "dashboard.html",
        username=session["username"],
        files=user_files,
        search_term=search_term,
        format_size=_format_size,
    )


@app.route("/download/<file_id>")
def download(file_id):
    if "user_id" not in session:
        return redirect("/login")

    file = get_file_for_user(file_id, session["user_id"])

    if not file:
        flash("You are not authorized to access that file.", "error")
        _log_event("download", "blocked", user_id=session["user_id"], username=session["username"], details=file_id)
        return redirect("/dashboard")

    try:
        decrypted_data = load_and_decrypt_file(file_id, cipher)
    except FileNotFoundError:
        flash("File not found on server.", "error")
        _log_event("download", "failed", user_id=session["user_id"], username=session["username"], details=f"{file_id}:missing_on_disk")
        return redirect("/dashboard")
    except (InvalidToken, ValueError):
        flash("Stored file is corrupted and cannot be downloaded.", "error")
        _log_event("download", "failed", user_id=session["user_id"], username=session["username"], details=f"{file_id}:corrupted")
        return redirect("/dashboard")

    increment_file_downloads(file_id)
    _log_event("download", "success", user_id=session["user_id"], username=session["username"], details=file[2])
    return send_file(
        BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file[2]
    )


@app.route("/delete/<file_id>", methods=["POST"])
def delete(file_id):
    if "user_id" not in session:
        return redirect("/login")

    file_record = get_file_for_user(file_id, session["user_id"])
    if not file_record:
        flash("File not found or not owned by you.", "error")
        _log_event("delete", "blocked", user_id=session["user_id"], username=session["username"], details=file_id)
        return redirect("/dashboard")

    delete_file_record(file_id, session["user_id"])
    delete_encrypted_file(file_id)
    flash("File deleted successfully.", "success")
    _log_event("delete", "success", user_id=session["user_id"], username=session["username"], details=file_id)

    return redirect("/dashboard")


@app.route("/rename/<file_id>", methods=["POST"])
def rename(file_id):
    if "user_id" not in session:
        return redirect("/login")

    new_name = request.form.get("new_name", "").strip()
    if not new_name:
        flash("New filename cannot be empty.", "error")
        _log_event("rename", "failed", user_id=session["user_id"], username=session["username"], details="empty_filename")
        return redirect("/dashboard")

    safe_name = secure_filename(new_name)
    if not safe_name:
        flash("Invalid filename.", "error")
        _log_event("rename", "failed", user_id=session["user_id"], username=session["username"], details="invalid_filename")
        return redirect("/dashboard")

    if len(safe_name) > MAX_FILENAME_LENGTH:
        flash("Filename is too long.", "error")
        _log_event("rename", "failed", user_id=session["user_id"], username=session["username"], details="filename_too_long")
        return redirect("/dashboard")

    if not _is_allowed_file(safe_name):
        flash("Blocked file type.", "error")
        _log_event("rename", "blocked", user_id=session["user_id"], username=session["username"], details="disallowed_extension")
        return redirect("/dashboard")

    was_updated = rename_file_record(file_id, session["user_id"], safe_name)
    if not was_updated:
        flash("Could not rename file.", "error")
        _log_event("rename", "failed", user_id=session["user_id"], username=session["username"], details=file_id)
        return redirect("/dashboard")

    flash("Filename updated.", "success")
    _log_event("rename", "success", user_id=session["user_id"], username=session["username"], details=safe_name)
    return redirect("/dashboard")


@app.route("/security")
def security():
    if "user_id" not in session:
        return redirect("/login")

    logs = get_recent_audit_logs(session["user_id"], limit=100)
    return render_template("security.html", logs=logs)


def _get_export_limit():
    raw_limit = request.args.get("limit", "100")
    try:
        limit = int(raw_limit)
    except ValueError:
        limit = 100
    return max(1, min(limit, 5000))


@app.route("/security/export/json")
def export_security_json():
    if "user_id" not in session:
        return redirect("/login")

    limit = _get_export_limit()
    logs = get_recent_audit_logs(session["user_id"], limit=limit)
    payload = [
        {
            "event": row[0],
            "status": row[1],
            "ip_address": row[2],
            "details": row[3],
            "created_at": row[4],
        }
        for row in logs
    ]

    _log_event("security_export_json", "success", user_id=session["user_id"], username=session["username"], details=f"limit={limit}")
    return jsonify(payload)


@app.route("/security/export/csv")
def export_security_csv():
    if "user_id" not in session:
        return redirect("/login")

    limit = _get_export_limit()
    logs = get_recent_audit_logs(session["user_id"], limit=limit)

    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["event", "status", "ip_address", "details", "created_at"])
    for row in logs:
        writer.writerow([row[0], row[1], row[2], row[3], row[4]])

    data = csv_buffer.getvalue().encode("utf-8")
    filename = f"security_logs_{session['user_id']}.csv"
    _log_event("security_export_csv", "success", user_id=session["user_id"], username=session["username"], details=f"limit={limit}")
    return send_file(
        BytesIO(data),
        as_attachment=True,
        download_name=filename,
        mimetype="text/csv",
    )


@app.route("/logout", methods=["POST"])
def logout():
    _log_event("logout", "success", user_id=session.get("user_id"), username=session.get("username"))
    session.clear()
    flash("You have been logged out.", "success")
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
