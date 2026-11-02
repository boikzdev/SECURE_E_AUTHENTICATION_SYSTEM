"""
SECURE E-AUTHENTICATION SYSTEM
Class XII Computer Science Investigatory Project (CBSE, Session 2026-27)

A menu-driven, command-line authentication system built with Python 3 and
MySQL. The program demonstrates salted SHA-256 password hashing, fully
parameterised SQL queries, an intrusion-detection style account-lockout
mechanism, and a CSV-based security audit trail, alongside a relational
database of registered users and their login history.
"""

import os
import csv
import secrets
import hashlib
import getpass
from datetime import datetime

import mysql.connector
from mysql.connector import Error


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
# Values are read from environment variables so that no credentials are
# stored in the source code. The fallbacks below are used if a variable is
# not set (host "localhost", user "root", password "root").
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", "root")
}

DATABASE_NAME = "secure_auth_system"
AUDIT_FILE = "security_audit.csv"
MAX_FAILED_ATTEMPTS = 3


# ---------------------------------------------------------------------------
# DATABASE INITIALISATION
# ---------------------------------------------------------------------------
def get_server_connection():
    """Opens a connection to the MySQL server without selecting a database."""
    try:
        connection = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"]
        )
        return connection
    except Error as error:
        print("Could not connect to the MySQL server:", error)
        return None


def get_database_connection():
    """Opens a connection to the MySQL server with the project database selected."""
    try:
        connection = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            database=DATABASE_NAME
        )
        return connection
    except Error as error:
        print("Could not connect to the database:", error)
        return None


def initialize_database():
    """
    Ensures the project database and both required tables exist, creating
    them automatically if they are missing. This lets the program run
    seamlessly the very first time it is executed on the examiner's system.
    """
    server_connection = get_server_connection()
    if server_connection is None:
        return None

    try:
        server_cursor = server_connection.cursor()
        server_cursor.execute("CREATE DATABASE IF NOT EXISTS " + DATABASE_NAME)
        server_connection.commit()
        server_cursor.close()
    except Error as error:
        print("Error while creating the database:", error)
        server_connection.close()
        return None

    server_connection.close()

    connection = get_database_connection()
    if connection is None:
        return None

    try:
        cursor = connection.cursor()

        create_users_table = """
            CREATE TABLE IF NOT EXISTS users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                hashed_password VARCHAR(64) NOT NULL,
                salt VARCHAR(32) NOT NULL,
                security_question VARCHAR(255) NOT NULL,
                failed_attempts INT DEFAULT 0,
                status VARCHAR(20) DEFAULT 'ACTIVE'
            ) ENGINE=InnoDB
        """
        cursor.execute(create_users_table)

        create_login_logs_table = """
            CREATE TABLE IF NOT EXISTS login_logs (
                log_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                login_time DATETIME,
                access_status VARCHAR(20),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            ) ENGINE=InnoDB
        """
        cursor.execute(create_login_logs_table)

        connection.commit()
        cursor.close()
    except Error as error:
        print("Error while creating tables:", error)
        connection.close()
        return None

    return connection


def initialize_audit_file():
    """Creates security_audit.csv with a header row if it does not already exist."""
    file_exists = os.path.isfile(AUDIT_FILE)
    if not file_exists:
        with open(AUDIT_FILE, mode="w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Timestamp", "Username", "Event_Type", "Details"])


# ---------------------------------------------------------------------------
# FILE HANDLING - SECURITY AUDIT LOG (CSV)
# ---------------------------------------------------------------------------
def log_security_event(username, event_type, details):
    """Appends one security event to the CSV audit trail with a timestamp."""
    initialize_audit_file()
    with open(AUDIT_FILE, mode="a", newline="") as csv_file:
        writer = csv.writer(csv_file)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([timestamp, username, event_type, details])


def view_security_audit_log():
    """Reads and neatly displays every row stored in the CSV audit trail."""
    print("\n--- Security Audit Log (security_audit.csv) ---")
    initialize_audit_file()

    with open(AUDIT_FILE, mode="r", newline="") as csv_file:
        reader = csv.reader(csv_file)
        rows = list(reader)

    if len(rows) <= 1:
        print("No security events have been recorded yet.")
        return

    header = rows[0]
    print("{:<21}{:<16}{:<32}{:<50}".format(header[0], header[1], header[2], header[3]))
    print("-" * 119)
    for row in rows[1:]:
        print("{:<21}{:<16}{:<32}{:<50}".format(row[0], row[1], row[2], row[3]))


# ---------------------------------------------------------------------------
# CRYPTOGRAPHY - SALTED SHA-256 HASHING
# ---------------------------------------------------------------------------
def generate_salt():
    """Generates a cryptographically strong random salt as a 32-character hex string."""
    return secrets.token_hex(16)


def hash_password(password, salt):
    """Combines a password with its unique salt and returns the SHA-256 hex digest."""
    salted_password = password + salt
    hash_object = hashlib.sha256(salted_password.encode("utf-8"))
    return hash_object.hexdigest()


# ---------------------------------------------------------------------------
# USER REGISTRATION
# ---------------------------------------------------------------------------
def username_exists(connection, username):
    """Checks whether a username is already present in the users table."""
    cursor = connection.cursor()
    cursor.execute("SELECT user_id FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    cursor.close()
    return result is not None


def register_user(connection):
    """Registers a new user after validating input and hashing the password with a fresh salt."""
    print("\n--- New User Registration ---")
    username = input("Enter a new username: ").strip()

    if username == "":
        print("Username cannot be empty.")
        return

    if username_exists(connection, username):
        print("This username is already taken. Please choose another one.")
        return

    password = getpass.getpass("Enter a new password: ")
    confirm_password = getpass.getpass("Confirm your password: ")

    if password != confirm_password:
        print("Passwords do not match. Registration cancelled.")
        return

    if len(password) < 6:
        print("Password must be at least 6 characters long.")
        return

    question_text = input("Set a security question (e.g., What is your favourite colour?): ").strip()
    answer_text = input("Enter the answer to your security question: ").strip()
    combined_security_data = question_text + "::" + answer_text

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    try:
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO users
            (username, hashed_password, salt, security_question, failed_attempts, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        values = (username, hashed_password, salt, combined_security_data, 0, "ACTIVE")
        cursor.execute(insert_query, values)
        connection.commit()
        cursor.close()
    except Error as error:
        print("Registration failed due to a database error:", error)
        return

    print("Registration successful! You may now log in.")
    log_security_event(username, "REGISTRATION", "New user account created successfully")


# ---------------------------------------------------------------------------
# LOGIN AND INTRUSION DETECTION
# ---------------------------------------------------------------------------
def fetch_user_record(connection, username):
    """Retrieves the full row for a given username, or None if it does not exist."""
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user_record = cursor.fetchone()
    cursor.close()
    return user_record


def record_login_log(connection, user_id, access_status):
    """Inserts one row into login_logs recording the outcome of a login attempt."""
    cursor = connection.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    insert_query = """
        INSERT INTO login_logs (user_id, login_time, access_status)
        VALUES (%s, %s, %s)
    """
    cursor.execute(insert_query, (user_id, timestamp, access_status))
    connection.commit()
    cursor.close()


def update_failed_attempts(connection, username, new_count):
    """Updates the failed_attempts counter for a given username."""
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE users SET failed_attempts = %s WHERE username = %s",
        (new_count, username)
    )
    connection.commit()
    cursor.close()


def lock_account(connection, username):
    """Sets a user's status to LOCKED, blocking further login attempts until recovery."""
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE users SET status = %s WHERE username = %s",
        ("LOCKED", username)
    )
    connection.commit()
    cursor.close()


def login_user(connection):
    """
    Authenticates a user against their stored salted hash. Implements
    intrusion detection: three consecutive incorrect passwords locks the
    account and raises an emergency alert in the CSV audit log.
    """
    print("\n--- User Login ---")
    username = input("Enter your username: ").strip()

    user_record = fetch_user_record(connection, username)

    if user_record is None:
        print("No account found with this username.")
        log_security_event(
            username, "UNAUTHORIZED_ACCESS_ATTEMPT",
            "Login attempted with a non-existent username"
        )
        return

    if user_record["status"] == "LOCKED":
        print("This account has been locked due to multiple failed login attempts.")
        print("Please use 'Forgot Password / Unlock Account' to restore access.")
        log_security_event(
            username, "LOCKED_ACCOUNT_ACCESS_ATTEMPT",
            "Login attempted on a locked account"
        )
        return

    password = getpass.getpass("Enter your password: ")
    hashed_input_password = hash_password(password, user_record["salt"])

    if hashed_input_password == user_record["hashed_password"]:
        print("Login successful! Welcome, " + username + ".")
        update_failed_attempts(connection, username, 0)
        record_login_log(connection, user_record["user_id"], "SUCCESS")
        log_security_event(username, "LOGIN_SUCCESS", "User logged in successfully")
    else:
        new_failed_count = user_record["failed_attempts"] + 1
        print(
            "Incorrect password. Attempt " + str(new_failed_count) +
            " of " + str(MAX_FAILED_ATTEMPTS) + "."
        )

        if new_failed_count >= MAX_FAILED_ATTEMPTS:
            lock_account(connection, username)
            record_login_log(connection, user_record["user_id"], "LOCKED")
            log_security_event(
                username, "ACCOUNT_LOCKED",
                "Account locked after " + str(MAX_FAILED_ATTEMPTS) +
                " consecutive failed attempts"
            )
            print("Your account has been locked due to too many failed attempts.")
        else:
            update_failed_attempts(connection, username, new_failed_count)
            record_login_log(connection, user_record["user_id"], "FAILURE")
            log_security_event(
                username, "LOGIN_FAILURE",
                "Incorrect password attempt " + str(new_failed_count) +
                " of " + str(MAX_FAILED_ATTEMPTS)
            )


# ---------------------------------------------------------------------------
# ACCOUNT RECOVERY
# ---------------------------------------------------------------------------
def unlock_account(connection):
    """Restores a locked account and resets its password after verifying the security answer."""
    print("\n--- Forgot Password / Account Recovery ---")
    username = input("Enter your username: ").strip()
    user_record = fetch_user_record(connection, username)

    if user_record is None:
        print("No account found with this username.")
        return

    stored_question, stored_answer = user_record["security_question"].split("::", 1)
    print("Security Question:", stored_question)
    answer = input("Enter your answer: ").strip()

    if answer == stored_answer:
        new_password = getpass.getpass("Enter a new password: ")
        confirm_password = getpass.getpass("Confirm your new password: ")

        if new_password != confirm_password:
            print("Passwords do not match. Please try again.")
            return

        new_salt = generate_salt()
        new_hashed_password = hash_password(new_password, new_salt)

        cursor = connection.cursor()
        update_query = """
            UPDATE users
            SET hashed_password = %s, salt = %s, failed_attempts = %s, status = %s
            WHERE username = %s
        """
        cursor.execute(
            update_query,
            (new_hashed_password, new_salt, 0, "ACTIVE", username)
        )
        connection.commit()
        cursor.close()

        print("Password reset successful. Your account has been unlocked.")
        log_security_event(
            username, "ACCOUNT_RECOVERY",
            "Account unlocked and password reset via security question"
        )
    else:
        print("Incorrect answer to the security question. Account recovery failed.")
        log_security_event(
            username, "FAILED_RECOVERY_ATTEMPT",
            "Incorrect security question answer provided"
        )


# ---------------------------------------------------------------------------
# ADMINISTRATIVE REPORTS
# ---------------------------------------------------------------------------
def view_login_history(connection):
    """Displays every row of login_logs joined with the corresponding username."""
    print("\n--- Login History (login_logs table) ---")
    cursor = connection.cursor(dictionary=True)
    query = """
        SELECT login_logs.log_id, users.username,
               login_logs.login_time, login_logs.access_status
        FROM login_logs
        INNER JOIN users ON login_logs.user_id = users.user_id
        ORDER BY login_logs.login_time DESC
    """
    cursor.execute(query)
    records = cursor.fetchall()
    cursor.close()

    if not records:
        print("No login history found.")
        return

    print("{:<8}{:<18}{:<22}{:<12}".format("Log ID", "Username", "Login Time", "Status"))
    print("-" * 62)
    for record in records:
        print("{:<8}{:<18}{:<22}{:<12}".format(
            record["log_id"], record["username"],
            str(record["login_time"]), record["access_status"]
        ))


def view_all_users(connection):
    """Displays the users table, proving that passwords are stored only as salted hashes."""
    print("\n--- Registered Users (users table) ---")
    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        "SELECT user_id, username, hashed_password, salt, failed_attempts, status FROM users"
    )
    records = cursor.fetchall()
    cursor.close()

    if not records:
        print("No users found in the database.")
        return

    print("{:<5}{:<14}{:<66}{:<34}{:<10}{:<8}".format(
        "ID", "Username", "Hashed Password (SHA-256)", "Salt", "Attempts", "Status"
    ))
    print("-" * 140)
    for record in records:
        print("{:<5}{:<14}{:<66}{:<34}{:<10}{:<8}".format(
            record["user_id"], record["username"], record["hashed_password"],
            record["salt"], record["failed_attempts"], record["status"]
        ))


# ---------------------------------------------------------------------------
# MENU-DRIVEN INTERFACE
# ---------------------------------------------------------------------------
def display_menu():
    """Prints the main menu of the Secure E-Authentication System."""
    print("\n===================================================")
    print("        SECURE E-AUTHENTICATION SYSTEM")
    print("===================================================")
    print("1. Register New User")
    print("2. Login")
    print("3. Forgot Password / Unlock Account")
    print("4. View Login History (Admin)")
    print("5. View All Registered Users (Admin)")
    print("6. View Security Audit Log (Admin)")
    print("7. Exit")
    print("===================================================")


def main():
    """Program entry point: initialises storage and runs the interactive menu loop."""
    print("Initialising Secure E-Authentication System...")
    connection = initialize_database()
    initialize_audit_file()

    if connection is None:
        print("The program could not start because the database is unavailable.")
        print("Please verify that MySQL is running and that DB_CONFIG is correct.")
        return

    print("Database and tables verified successfully.")
    print("Security audit file (" + AUDIT_FILE + ") is ready.")

    while True:
        display_menu()
        choice = input("Enter your choice (1-7): ").strip()

        if choice == "1":
            register_user(connection)
        elif choice == "2":
            login_user(connection)
        elif choice == "3":
            unlock_account(connection)
        elif choice == "4":
            view_login_history(connection)
        elif choice == "5":
            view_all_users(connection)
        elif choice == "6":
            view_security_audit_log()
        elif choice == "7":
            print("Thank you for using the Secure E-Authentication System. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 7.")

    connection.close()


if __name__ == "__main__":
    main()
