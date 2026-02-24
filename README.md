# SecureDrive Pro - Encrypted Cloud Storage

SecureDrive Pro is a Flask web app for secure cloud-style file storage.  
Users can register, log in, upload files, and download them later with encryption at rest and strong access controls.

## What It Does

- Auth system with registration/login
- Password hashing using Flask-Bcrypt
- Per-user private file storage
- File upload, download, rename, and delete
- Encrypted storage using Fernet (cryptography)
- File type and size restrictions
- CSRF protection for form actions
- Login rate limiting and temporary lockout
- Security audit logs with JSON/CSV export

## Tech Stack

- Python
- Flask
- SQLite
- Flask-Bcrypt
- cryptography (Fernet)
- HTML/CSS templates

## Quick Start

```bash
pip install -r requirements.txt
python app.py
app.py
models/db.py
services/
  auth_services.py
  file_services.py
  security_services.py
templates/
static/
encrypted_files/
database.db
secret.key
