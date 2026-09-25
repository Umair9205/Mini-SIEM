import os
import ssl
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone

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
app.secret_key = os.environ["SECRET_KEY"]

ADMIN_TIMEOUT = 15 * 60

@app.route('/', methods=['GET', 'POST'])
def home():
    if flask.request.method == 'POST':
        username = flask.request.form.get('username')
        password = flask.request.form.get('password')
        ipaddr = flask.request.remote_addr

        if not username or not password:
            writelog(
                "WARNING",
                ipaddr,
                "Login Attempt without missingusername or password"
            )
            flask.flash("Please enter your username and password.", "error")
            return flask.redirect(flask.url_for('home'))

        conn = get_db_connection()

        try:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()
        except Exception as e:
            print(f"Database error: {e}")
            writelog(
                "ERROR",
                ipaddr,
                "Error occurred while accessing the database"
            )
            error_context(
                "ERROR",
                ipaddr,
                str(e)
            )
            return "Internal Server Error", 500
        finally:
            conn.close()
        
        if result:
            if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
                print("PASS")
                writelog(
                    "INFO",
                    ipaddr,
                    f"Login Successfully with username: {username}"
                )
                flask.flash("Login successful.", "success")
            else:
                print("FAIL - wrong password")
                writelog(
                    "WARNING",
                    ipaddr,
                    f"Failed Login Attempt with username: {username} - Incorrect Password"
                )
                flask.flash("Incorrect password.", "error")
        else:
            print("FAIL - user not found")
            writelog(
                "WARNING",
                ipaddr,
                "Failed Login Attempt - Incorrect Username"
            )
            flask.flash("Username not found.", "error")
    return flask.render_template('index.html')   

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if flask.request.method == 'POST':
        email = flask.request.form.get('email')
        username = flask.request.form.get('username')
        password = flask.request.form.get('password')

        if not email or not username or not password:
            flask.flash("Please fill in all fields.", "error")
            return flask.redirect(flask.url_for('registration'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        conn = get_db_connection()

        try:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users(email, username, password_hash) VALUES (%s, %s, %s)", (email, username, hashed_password))
            conn.commit()
            flask.flash("Account created. You can now sign in.", "success")
            return flask.redirect(flask.url_for('home'))
        finally:
            conn.close()
        print(f"Email: {email}, Username: {username}, Password: {hashed_password}")
    return flask.render_template('registration.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if flask.request.method == 'POST':
        username = flask.request.form.get('admin')
        password = flask.request.form.get('password')
        if not username or not username.strip() or not password:
            flask.flash("Please enter your admin username and password.", "error")
            return flask.redirect(flask.url_for('admin'))

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

                flask.session.clear()
                flask.session['admin'] = True
                flask.session['last_activity'] = datetime.now(timezone.utc).timestamp()

                return flask.redirect(flask.url_for('dashboard'))
            else:
                print("FAIL - wrong password")
                flask.flash("Incorrect password.", "error")
        else:
            print("FAIL - user not found")
            flask.flash("Username not found.", "error")
    return flask.render_template('admin.html')


def admin_session_valid(update_activity=True):
    if not flask.session.get('admin'):
        return False

    last_activity = flask.session.get('last_activity')

    if last_activity is None:
        flask.session.clear()
        return False

    current_time = datetime.now(timezone.utc).timestamp()

    if current_time - last_activity > ADMIN_TIMEOUT:
        flask.session.clear()
        return False

    if update_activity:
        flask.session['last_activity'] = current_time

    return True


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if not admin_session_valid():
        return flask.redirect(flask.url_for('admin'))

    total = total_logs()
    error = error_count()
    warning = warning_count()

    return flask.render_template('dashboard.html', total_logs=total, error_count=error, warning_count=warning)

def writelog(level, ipaddr, message):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logs(level, ip_address, message) VALUES(%s, %s, %s)", (level, ipaddr, message))
        conn.commit()
    finally:
        conn.close()

def error_context(level, ipaddr, message):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO error_context(level, ip_address, message) VALUES(%s, %s, %s)", (level, ipaddr, message))
        conn.commit()
    finally:
        conn.close()

def total_logs():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        result = cursor.fetchone()
        return result[0]
    finally:
        conn.close()

def error_count():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs WHERE level = 'ERROR'")
        result = cursor.fetchone()
        return result[0]
    finally:
        conn.close()

def warning_count():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs WHERE level = 'WARNING'")
        result = cursor.fetchone()
        return result[0]
    finally:
        conn.close()

@app.route('/api/logs', methods=['GET'])
def api_logs():
    if not admin_session_valid(update_activity=False):
        return flask.jsonify({"error": "Unauthorized"}), 401

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, level, ip_address, message FROM logs ORDER BY id DESC")
        rows = cursor.fetchall()
    finally:
        conn.close()

    logs = []

    for row in rows:
        logs.append({
            "id": row[0],
            "timestamp": row[1],
            "level": row[2],
            "ip_address": row[3],
            "message": row[4]
        })

    return flask.jsonify(logs)

if __name__ == '__main__':
    app.run()