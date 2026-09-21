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
# import os, time, bcrypt
# from colorama import Fore, Style


# def analyze_log_file():
#     pass

# def input_username_password():
#     username = input("Enter Username: ") 
#     while True:  
#         if username.isdigit(): 
#             print("Username cannot be a number. Please enter a valid username.")
#             print("")
#             time.sleep(2)
#             print("\33[2A\33[2K", end="")
#             print("\33[1A\33[2K", end="")
#             username = input("Enter Username: ")
#         elif len(username) <= 5:
#             print("Username must be at least 5 characters long. Please enter a valid username.")
#             print("")
#             time.sleep(2)
#             print("\33[2A\33[2K", end="")
#             print("\33[1A\33[2K", end="")
#             username = input("Enter Username: ")
#         elif len(username) > 20:
#             print("Username cannot exceed 20 characters. Please enter a valid username.")
#             print("")
#             time.sleep(2)
#             print("\33[2A\33[2K", end="")
#             print("\33[1A\33[2K", end="")
#             username = input("Enter Username: ")
#         elif any(char in username for char in "!@#$%^&*()-+={/}\\,[]?><.|~`;:"):
#             print("Username cannot only contain alphanumeric characters and underscores. Please enter a valid username.")
#             print("")
#             time.sleep(2)
#             print("\33[2A\33[2K", end="")
#             print("\33[1A\33[2K", end="")
#             username = input("Enter Username: ")
#         else:
#             break

#     password = input("Enter Password: ") 
#     with open("password.txt", "rb") as f:
#         for lines in f:
#             stored_hash = lines.rstrip(b"\r\n")
#             if not stored_hash:
#                 print("No password hash found in the file.")
#                 return
#             if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
#                 print("Password correct")
#                 break
#         else:
#             print("Password incorrect")

# def start():
#     print("Welcome to the Log Analyzer!")
#     print("Please select an option:")
#     print(Fore.YELLOW + "[1] " + Style.RESET_ALL + "Analyze a log file")
#     print(Fore.YELLOW + "[2] " + Style.RESET_ALL + "Exit")
#     choice = input("Enter your choice: ")
#     if choice == "1":
#         input_username_password()
#     elif choice == "2":
#         print("Exiting the program.")
#         exit()
#     else:
#         print("Invalid choice. Please try again.")
#         start()



# start()

# # final_password = "Um@123"
# # hashed_password = bcrypt.hashpw(final_password.encode('utf-8'), bcrypt.gensalt())
# # with open("password.txt", "ab") as f:
# #     f.write(hashed_password + b"\n")