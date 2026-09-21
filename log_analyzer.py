import os
import ssl
from urllib.parse import urlparse, unquote

import flask
import bcrypt
import pg8000.dbapi
from dotenv import load_dotenv

load_dotenv()

total_logs = None

def get_db_connection():
    url = urlparse(os.environ["DATABASE_URL"])

    return pg8000.dbapi.connect(
        user=unquote(url.username),
        password=unquote(url.password),
        host=url.hostname,
        port=url.port or 5432,
        database=unquote(url.path.lstrip("/")),
        ssl_context=ssl.create_default_context(),
    )

app = flask.Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    if flask.request.method == 'POST':
        username = flask.request.form.get('username')
        password = flask.request.form.get('password')

        conn = get_db_connection()

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
        finally:
            conn.close()
        
        if result:
            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                print("PASS")
            else:
                print("FAIL - wrong password")
        else:
            print("FAIL - user not found")

    return flask.render_template('index.html')   

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if flask.request.method == 'POST':
        email = flask.request.form.get('email')
        username = flask.request.form.get('username')
        password = flask.request.form.get('password')

        if not email or not username or not password:
            return "Please fill in all fields.", 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()

        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users(email, username, password_hash) VALUES (%s, %s, %s)", (email, username, hashed_password))
            conn.commit()
        finally:
            conn.close()
        print(f"Email: {email}, Username: {username}, Password: {hashed_password}")
    return flask.render_template('registration.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if flask.request.method == 'POST':
        username = flask.request.form.get('admin')
        password = flask.request.form.get('password')

        conn = get_db_connection()

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM admins WHERE username = %s", (username,))
            result = cursor.fetchone()
        finally:
            conn.close()
        
        if result:
            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                print("PASS")
                return dashboard()
            else:
                print("FAIL - wrong password")
        else:
            print("FAIL - user not found")
    return flask.render_template('admin.html')

def dashboard():
    return flask.render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
