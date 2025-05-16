# import secure modules and libraries
from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3
import os
import re
import html
from werkzeug.security import generate_password_hash, check_password_hash
from spades_cryptosystem import encrypt_dataset, search_and_decrypt, get_memory_usage
from datetime import datetime
import time

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))  # Secret key not hardcoded

# Secure cookie flags
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # Prevents client-side script access to cookies
    SESSION_COOKIE_SECURE=True,         # Works only over HTTPS
    SESSION_COOKIE_SAMESITE='Lax'       # Helps prevent CSRF
)

DB_FOLDER = 'db'
DB_NAME = os.path.join(DB_FOLDER, 'users.db')

# Safe DB creation and folder handling
def init_db():
    if not os.path.exists(DB_FOLDER):
        os.makedirs(DB_FOLDER)
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute('''  # Table with UNIQUE constraint
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        ''')
        conn.commit()
        conn.close()


@app.route('/')
def index():
    return render_template('login.html')  # Entry point


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = html.escape(request.form['username'])  # Input sanitization
        password = request.form['password']

        # Parameterized query to prevent SQL injection
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT username, password, role FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        # Passwords stored as hashes, compared securely
        if user and check_password_hash(user[1], password):
            session['username'] = user[0]
            session['role'] = user[2]

            # Access control based on roles
            if user[2] == 'analyst':
                return redirect(url_for('analyst_dashboard', username=user[0]))
            elif user[2] == 'admin':
                return redirect(url_for('admin_panel'))
            else:
                return render_template('user_dashboard.html', username=user[0])
        else:
            error = "Invalid username or password."

    return render_template('login.html', error=error)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    success = None
    if request.method == 'POST':
        username = html.escape(request.form['username'])  #  Sanitize input
        email = html.escape(request.form['email'])
        password = request.form['password']

        # Regex used to validate user inputs
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            error = "Username must be 3–20 characters, only letters, numbers, or underscores."
        elif not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            error = "Invalid email address."
        elif len(password) < 6:  # Enforce strong password policy
            error = "Password must be at least 6 characters long."

        if not error:
            hashed_password = generate_password_hash(password)  # Hash password
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            try:
                # Use safe insertion to avoid SQLi
                cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                               (username, email, hashed_password))
                conn.commit()
                conn.close()
                success = "Account created successfully! You can now log in."
            except sqlite3.IntegrityError as e:
                conn.close()
                # Handle DB errors securely
                if 'username' in str(e):
                    error = "Username already exists."
                elif 'email' in str(e):
                    error = "Email already in use."
                else:
                    error = "Database error. Please try again."

    return render_template('signup.html', error=error, success=success)


@app.route('/admin', methods=['GET', 'POST'])
def admin_panel():
    # Access control check
    if 'username' not in session or session.get('role') != 'admin':
        return "Unauthorized access", 403

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    if request.method == 'POST':
        username = request.form['username']
        action = request.form.get('action')
        # Role-based privilege escalation handling
        if action == 'add':
            cursor.execute("UPDATE users SET role = 'analyst' WHERE username = ?", (username,))
        elif action == 'remove':
            cursor.execute("UPDATE users SET role = 'user' WHERE username = ?", (username,))
        conn.commit()

    cursor.execute("SELECT username, email, role FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template('admin.html', users=users)


@app.route('/analyst/<username>', methods=['GET', 'POST'])
def analyst_dashboard(username):
    # Ensure correct user and role access
    if 'username' not in session or session['username'] != username or session.get('role') != 'analyst':
        return "Unauthorized access", 403

    result = None
    if request.method == 'POST':
        option = request.form['option']
        max_vec_length = int(request.form['max_vec_length'])
        search_value = request.form['search_value']

        try:
            # Encrypt and process data securely (see spades_cryptosystem)
            encrypt_start_time = time.time()
            db_path, data, encrypted_data, sks, reg_key = encrypt_dataset(option, max_vec_length)
            encrypt_end_time = time.time()
            encryption_time = round(encrypt_end_time - encrypt_start_time, 4)

            decrypt_start_time = time.time()
            decrypted_data = search_and_decrypt(search_value, option, encrypted_data, sks, reg_key)
            decrypt_end_time = time.time()
            decryption_time = round(decrypt_end_time - decrypt_start_time, 4)

            result = {
                'data': data,
                'encrypted_data': encrypted_data,
                'decrypted_data': decrypted_data,
                'encryption_time': encryption_time,
                'decryption_time': decryption_time,
                'total_processing_time': round(encryption_time + decryption_time, 4),
                'memory_usage': get_memory_usage()
            }

        except Exception as e:
            result = {"error": str(e)}  # Fail securely on unexpected input

    return render_template('analyst_dashboard.html', result=result, username=username)


@app.route('/logout')
def logout():
    session.clear()  # Clear session to prevent fixation/reuse
    return redirect(url_for('index'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
