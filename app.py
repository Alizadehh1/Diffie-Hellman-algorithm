import pyodbc
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import bcrypt
import os
import uuid
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
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
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Users' AND xtype='U')
        BEGIN
            CREATE TABLE Users (
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
            INSERT INTO Users (username, email, hashed_password, salt, dh_public_key, created_at, updated_at, is_active, is_locked)
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
            cursor.execute('SELECT * FROM Users WHERE username = ?', (username,))
            user = cursor.fetchone()

        if user:
            # Retrieve the salt and compare passwords
            stored_salt = user.salt.encode('utf-8')  # Ensure salt is in bytes format
            stored_password = user.hashed_password.encode('utf-8')  # Ensure hashed password is in bytes format
            
            # Check if the provided password matches the stored hash
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Login successful
                session['user_id'] = user.user_id
                session['username'] = user.username
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password. Please try again.', 'danger')
        else:
            flash('Username does not exist. Please try again.', 'danger')

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

# Initialize the serializer (used to sign the reset token)
s = URLSafeTimedSerializer(app.secret_key)

@app.route('/request_reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form['email']

        # Fetch the user from the database based on the email
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM Users WHERE email = ?', (email,))
            user = cursor.fetchone()

        if user:
            # Generate a password reset token
            reset_token = s.dumps(user.email, salt='password-reset')

            # Create a password reset URL
            reset_url = url_for('reset_password', token=reset_token, _external=True)

            # Send the reset URL to the user's email (you'll need to configure email functionality here)
            send_reset_email(user.email, reset_url)  # You'll implement the email sending function

            flash('Password reset link sent to your email.', 'success')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.', 'danger')

    return render_template('request_reset.html')

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'testsmtp541@gmail.com'
app.config['MAIL_PASSWORD'] = 'qlxjvxdpyjiuliec'
app.config['MAIL_DEFAULT_SENDER'] = 'ali.alizadehh541@gmail.com'

mail = Mail(app)

def send_reset_email(to, reset_url):
    msg = Message('Password Reset Request', recipients=[to])
    msg.body = f'Click the following link to reset your password: {reset_url}'
    mail.send(msg)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify the token, it will raise an exception if the token is invalid or expired
        email = s.loads(token, salt='password-reset', max_age=3600)  # token expires in 1 hour
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        
        # Hash the new password and update in the database
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE Users 
                SET hashed_password = ?, salt = ?, updated_at = ? 
                WHERE email = ?
            """, (hashed_password.decode('utf-8'), salt.decode('utf-8'), datetime.now(), email))
            conn.commit()

        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
