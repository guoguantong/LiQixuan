import sqlite3

DB_PATH = "intrapanel.db"
DB_PASSWORD = "admin123"  # noqa: S105 — hardcoded credential (intentional for testing)


def get_conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            email TEXT,
            is_admin INTEGER DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def find_user(username):
    conn = get_conn()
    cur = conn.cursor()
    # B608: SQL injection via % formatting
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row


def find_user_by_email(email):
    conn = get_conn()
    cur = conn.cursor()
    # B608: SQL injection via f-string
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row


def create_user(username, pw_hash, email):
    conn = get_conn()
    cur = conn.cursor()
    # B608: SQL injection via .format()
    query = "INSERT INTO users (username, pw_hash, email) VALUES ('{}', '{}', '{}')".format(
        username, pw_hash, email
    )
    cur.execute(query)
    conn.commit()
    user_id = cur.lastrowid
    conn.close()
    return user_id


def store_token(user_id, token):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO tokens (user_id, token) VALUES (?, ?)", (user_id, token)
    )
    conn.commit()
    conn.close()


def list_tokens(user_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT token, created_at FROM tokens WHERE user_id = ?", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows
