import sqlite3
from werkzeug.security import generate_password_hash
import os

# Path to your existing database
DB_FOLDER = 'db'
DB_NAME = os.path.join(DB_FOLDER, 'users.db')

# Admin credentials
username = 'admin'
email = 'admin@example.com'
password = 'admin123'
role = 'admin'


# Initialize the database (create table if it doesn't exist)
def init_db():
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)

    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        ''')
        conn.commit()
        conn.close()
    print(f"✅ Database initialized at {DB_NAME}")


# Initialize the database before attempting to insert admin user
init_db()

# Hash the password
hashed_password = generate_password_hash(password)

# Insert the admin user into the database
conn = sqlite3.connect(DB_NAME)
cursor = conn.cursor()

try:
    cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                   (username, email, hashed_password, role))
    conn.commit()
    print(f"✅ Admin user '{username}' created successfully.")
except sqlite3.IntegrityError as e:
    print(f"⚠️ Error: {e}")

conn.close()
