import pyodbc
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import bcrypt
import os
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize the Diffie-Hellman parameters (large prime and base for DH)
parameters = dh.generate_parameters(generator=2, key_size=2048)

# MSSQL Database connection settings
def get_db_connection():
    conn = pyodbc.connect(
        'DRIVER={ODBC Driver 17 for SQL Server};'
        'SERVER=.\\SQLEXPRESS;'
        'DATABASE=Diffie-Hellman;'
        'UID=sa;'
        'PWD=query'
    )
    return conn

# Initialize the database
def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='users' AND xtype='U')
        BEGIN
            CREATE TABLE users (
                user_id INT PRIMARY KEY IDENTITY(1,1),
                username NVARCHAR(255) NOT NULL UNIQUE,
                email NVARCHAR(255),
                hashed_password NVARCHAR(255),
                salt NVARCHAR(255),
                dh_public_key NVARCHAR(MAX),
                created_at DATETIME,
                updated_at DATETIME,
                is_active BIT,
                last_login DATETIME,
                is_locked BIT
            );
        END;
        """)
        conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Hash the password and generate salt
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        # Generate a Diffie-Hellman key pair for the user
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()

        # Serialize public key
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Insert user data into the database
        created_at = datetime.now()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO users (username, email, hashed_password, salt, dh_public_key, created_at, updated_at, is_active, is_locked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (username, email, hashed_password.decode('utf-8'), salt.decode('utf-8'), serialized_public_key, created_at, created_at, 1, 0))
            conn.commit()

        flash('Account successfully created!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch the user from the database
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

        if user:
            # Retrieve the salt and compare passwords
            stored_salt = user.salt.encode('utf-8')  # Ensure salt is in bytes format
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
                session['user_id'] = user.user_id
                session['username'] = user.username
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password!', 'danger')

        else:
            flash('Invalid username or password!', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
