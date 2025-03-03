import os
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import uuid
from werkzeug.security import generate_password_hash

DATABASE = 'users.db'

app = Flask(__name__)
app.secret_key = 'Jacques'


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row 
    return conn


def init_db():
    # Ensure the database exists and table is created
    if not os.path.exists(DATABASE):
        print(f"Database {DATABASE} does not exist. Creating it...")

    with app.app_context():
        conn = get_db_connection()
        cursor = conn.cursor()

        # Create the 'users' table if it doesn't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        conn.commit()
        print("Database initialized with 'users' table.")  # Debugging print
        conn.close()


def signup_user(username, email, password, confirm_password, first_name, last_name):
    if password != confirm_password:
        return 'Passwords do not match!'  # Return error message if passwords do not match

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if username or email already exists
    cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return 'Username or email already exists!'

    user_id = str(uuid.uuid4())
    salted_password = password + user_id
    hashed_password = generate_password_hash(salted_password)

    cursor.execute('''
        INSERT INTO users (id, username, email, first_name, last_name, password_hash)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, username, email, first_name, last_name, hashed_password))

    conn.commit()
    conn.close()

    return 'Signup successful! Please log in.'

@app.route('/')
def index():
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm_password']  # Capture confirm password
    first_name = request.form['first_name']
    last_name = request.form['last_name']

    message = signup_user(username, email, password, confirm_password, first_name, last_name)
    flash(message)

    if 'Signup successful!' in message:
        return redirect(url_for('homepage'))
    
    return redirect(url_for('index'))


@app.route('/homepage')
def homepage():
    return render_template('homepage.html')


if __name__ == '__main__':
    init_db()  # Initialize the database and create the table if it doesn't exist
    app.run(debug=True)
