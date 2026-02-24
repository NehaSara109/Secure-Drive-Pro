import sqlite3

DATABASE = "database.db"


def get_connection():
    return sqlite3.connect(DATABASE, timeout=10)


def init_db():
    conn = get_connection()
    try:
        cursor = conn.cursor()

        # WAL reduces writer/reader lock contention for sqlite in web apps.
        cursor.execute("PRAGMA journal_mode=WAL")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                locked_until TEXT
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                user_id INTEGER,
                original_name TEXT,
                downloads INTEGER DEFAULT 0,
                size_bytes INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                event TEXT NOT NULL,
                status TEXT NOT NULL,
                ip_address TEXT,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Lightweight migration for older databases.
        cursor.execute("PRAGMA table_info(users)")
        user_columns = {row[1] for row in cursor.fetchall()}
        if "failed_attempts" not in user_columns:
            cursor.execute(
                "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0"
            )
        if "locked_until" not in user_columns:
            cursor.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")

        cursor.execute("PRAGMA table_info(files)")
        columns = {row[1] for row in cursor.fetchall()}
        if "size_bytes" not in columns:
            cursor.execute("ALTER TABLE files ADD COLUMN size_bytes INTEGER DEFAULT 0")
        if "created_at" not in columns:
            cursor.execute("ALTER TABLE files ADD COLUMN created_at TEXT")
            cursor.execute(
                "UPDATE files SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"
            )

        conn.commit()
    finally:
        conn.close()


def create_user(username, hashed_password):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password),
        )
        conn.commit()
    finally:
        conn.close()


def get_user_by_username(username):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, username, password, failed_attempts, locked_until
            FROM users
            WHERE username = ?
            """,
            (username,),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def set_user_login_security_state(user_id, failed_attempts, locked_until):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE users
            SET failed_attempts = ?, locked_until = ?
            WHERE id = ?
            """,
            (failed_attempts, locked_until, user_id),
        )
        conn.commit()
    finally:
        conn.close()


def reset_user_login_security_state(user_id):
    set_user_login_security_state(user_id, 0, None)


def create_file_record(file_id, user_id, original_name, size_bytes):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO files (id, user_id, original_name, size_bytes, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
            """,
            (file_id, user_id, original_name, size_bytes),
        )
        conn.commit()
    finally:
        conn.close()


def get_files_by_user_id(user_id, search_term=None):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        if search_term:
            cursor.execute(
                """
                SELECT *
                FROM files
                WHERE user_id = ? AND original_name LIKE ?
                ORDER BY COALESCE(created_at, '') DESC, id DESC
                """,
                (user_id, f"%{search_term}%"),
            )
        else:
            cursor.execute(
                """
                SELECT *
                FROM files
                WHERE user_id = ?
                ORDER BY COALESCE(created_at, '') DESC, id DESC
                """,
                (user_id,),
            )
        return cursor.fetchall()
    finally:
        conn.close()


def get_file_for_user(file_id, user_id):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?",
            (file_id, user_id),
        )
        return cursor.fetchone()
    finally:
        conn.close()


def increment_file_downloads(file_id):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE files SET downloads = downloads + 1 WHERE id = ?", (file_id,))
        conn.commit()
    finally:
        conn.close()


def delete_file_record(file_id, user_id):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, user_id))
        conn.commit()
    finally:
        conn.close()


def rename_file_record(file_id, user_id, new_name):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE files SET original_name = ? WHERE id = ? AND user_id = ?",
            (new_name, file_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def log_audit_event(user_id, username, event, status, ip_address, details):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_logs (user_id, username, event, status, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, username, event, status, ip_address, details),
        )
        conn.commit()
    finally:
        conn.close()


def get_recent_audit_logs(user_id, limit=50):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT event, status, ip_address, details, created_at
            FROM audit_logs
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (user_id, limit),
        )
        return cursor.fetchall()
    finally:
        conn.close()
