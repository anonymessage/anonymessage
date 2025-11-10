# migrate.py
import sqlite3
from pathlib import Path
from datetime import datetime
import re

BASE = Path.cwd()
DB = BASE / "anonymessage.db"
SECRETS = BASE / ".streamlit" / "secrets.toml"

def read_secrets():
    # Very small parser for the expected admin section in secrets.toml
    if not SECRETS.exists():
        print(f"ERROR: secrets.toml not found at {SECRETS}")
        return None
    text = SECRETS.read_text(encoding="utf-8")
    # naive parsing, expecting lines like: email = "..." and password_hash = "..."
    email_match = re.search(r'email\s*=\s*"([^"]+)"', text)
    ph_match = re.search(r'password_hash\s*=\s*"([0-9a-fA-F]+)"', text)
    if not email_match or not ph_match:
        print("ERROR: Could not parse admin email or password_hash from secrets.toml.")
        return None
    return {"email": email_match.group(1).strip(), "password_hash": ph_match.group(1).strip()}

def ensure_columns(conn):
    cur = conn.cursor()
    # Get existing columns
    cur.execute("PRAGMA table_info(users)")
    cols = {row[1] for row in cur.fetchall()}  # row[1] is column name
    # Desired columns and SQL to add them
    to_add = []
    if "password_hash" not in cols:
        to_add.append("ALTER TABLE users ADD COLUMN password_hash TEXT")
    if "blocked" not in cols:
        to_add.append("ALTER TABLE users ADD COLUMN blocked INTEGER DEFAULT 0")
    if "verified" not in cols:
        # if verified already exists skip; otherwise add
        if "verified" not in cols:
            to_add.append("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 1")
    # Run adds
    for sql in to_add:
        print("Executing:", sql)
        cur.execute(sql)
    # ensure settings table exists and anon_counter exists
    cur.execute("""CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
    cur.execute("SELECT value FROM settings WHERE key='anon_counter'")
    if not cur.fetchone():
        cur.execute("INSERT INTO settings(key,value) VALUES('anon_counter','99')")
    conn.commit()

def ensure_admin(conn, admin_email, password_hash):
    cur = conn.cursor()
    # Check if admin user exists by email
    cur.execute("SELECT * FROM users WHERE email=?", (admin_email,))
    r = cur.fetchone()
    if r:
        print("Admin user already exists in DB. Updating password_hash and nickname to Adminous_1.")
        cur.execute("UPDATE users SET password_hash=?, nickname=? WHERE email=?",
                    (password_hash, "Adminous_1", admin_email))
    else:
        print("Creating admin user row in users table.")
        now = datetime.utcnow().isoformat()
        # Try to insert with email and given password hash
        try:
            cur.execute("""INSERT INTO users(nickname,email,phone,password_hash,verified,blocked,created_at)
                           VALUES(?,?,?,?,1,0,?)""", ("Adminous_1", admin_email, None, password_hash, now))
        except sqlite3.IntegrityError as e:
            print("Insert failed (IntegrityError):", e)
            # fallback: update if record exists but with null email or similar
    conn.commit()

def main():
    if not DB.exists():
        print("Database not found at", DB, "- creating new DB and schema.")
        conn = sqlite3.connect(DB)
        # create minimal schema (same as app expects)
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT UNIQUE,
            email TEXT UNIQUE,
            phone TEXT,
            password_hash TEXT,
            verified INTEGER DEFAULT 1,
            blocked INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS posts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT,
            title TEXT,
            content TEXT,
            created_at TEXT,
            upvotes INTEGER DEFAULT 0,
            downvotes INTEGER DEFAULT 0,
            user_id TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS comments(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            user_id TEXT,
            nickname TEXT,
            content TEXT,
            created_at TEXT,
            upvotes INTEGER DEFAULT 0,
            downvotes INTEGER DEFAULT 0
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS chat(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            user_id TEXT,
            nickname TEXT,
            message TEXT,
            created_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS news(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            created_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS reports(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT,
            target_id INTEGER,
            reporter_user_id TEXT,
            reason TEXT,
            created_at TEXT,
            status TEXT DEFAULT 'open'
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS polls(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT,
            options_json TEXT,
            created_at TEXT
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS poll_votes(
            poll_id INTEGER,
            user_id TEXT,
            choice_index INTEGER,
            created_at TEXT,
            PRIMARY KEY (poll_id, user_id)
        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
        cur.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('anon_counter','99')")
        conn.commit()
    else:
        conn = sqlite3.connect(DB)
    print("DB opened:", DB)
    ensure_columns(conn)

    secrets = read_secrets()
    if not secrets:
        print("No valid admin secrets found; create .streamlit/secrets.toml with [admin] email & password_hash and re-run.")
        conn.close()
        return
    ensure_admin(conn, secrets["email"], secrets["password_hash"])
    conn.close()
    print("Migration completed. Now restart your Streamlit app.")

if __name__ == "__main__":
    main()
