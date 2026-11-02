# Secure E-Authentication System

A menu-driven, command-line user authentication system written in Python 3 with a MySQL back end. It handles user registration, login, account lockout after repeated failed logins, password recovery through a security question, and keeps two separate records of activity: a MySQL table and a CSV audit file.

This was written as a CBSE Class XII Computer Science (083) investigatory project for the 2026-27 session. The full project report is in [`docs/Secure-E-CS_Project.pdf`](docs/Secure-E-CS_Project.pdf).

It is a learning project. See [Known limitations](#known-limitations) before reusing any of it for something real.

## Contents

- [Features](#features)
- [Repository layout](#repository-layout)
- [Requirements](#requirements)
- [Setup](#setup)
- [Configuration](#configuration)
- [Running the program](#running-the-program)
- [Menu options](#menu-options)
- [How it works](#how-it-works)
- [Database schema](#database-schema)
- [Audit log format](#audit-log-format)
- [Sample session](#sample-session)
- [Known limitations](#known-limitations)
- [Pushing this repository to GitHub](#pushing-this-repository-to-github)
- [License](#license)

## Features

- **Salted password hashing.** Each password is combined with a random 16-byte salt and hashed with SHA-256 (`hashlib`). Only the hash and the salt are stored.
- **Parameterised SQL.** Every query uses `%s` placeholders. User input is never concatenated into SQL text.
- **Account lockout.** Three consecutive wrong passwords set the account status to `LOCKED`. The limit is the `MAX_FAILED_ATTEMPTS` constant.
- **Account recovery.** A locked (or any) account can be reset by answering the security question set at registration.
- **Hidden password entry.** Passwords are read with `getpass`, so they are not echoed to the terminal.
- **Two activity records.**
  - `login_logs` (MySQL): login outcomes tied to existing users, linked by a foreign key.
  - `security_audit.csv`: a wider set of events, including ones with no valid user (for example, a login attempt with a username that does not exist).
- **Self-initialising.** On first run the program creates the database, both tables, and the CSV file if they do not exist.
- **Admin views.** Menu options show the login history, the users table (including hashes and salts), and the audit log.

## Repository layout

```
secure-e-authentication-system/
├── secure_e_authentication_system.py   # the entire program
├── requirements.txt                    # Python dependency
├── docs/
│   ├── Secure-E-CS_Project.pdf         # project report
│   └── schema.sql                      # reference copy of the table definitions
├── .gitignore
├── LICENSE
└── README.md
```

`security_audit.csv` is created in the directory you run the program from. It is listed in `.gitignore` and is not part of the repository.

## Requirements

| Item | Version |
|---|---|
| Python | 3.10 or later |
| MySQL Server | 8.0 or later |
| Python package | `mysql-connector-python` |
| OS | Windows, Linux, or macOS |

Standard-library modules used: `os`, `csv`, `secrets`, `hashlib`, `getpass`, `datetime`.

## Setup

1. Install and start MySQL Server 8.0 or later. Confirm you can log in with the `mysql` client.

2. Clone the repository:

   ```bash
   git clone https://github.com/<your-username>/secure-e-authentication-system.git
   cd secure-e-authentication-system
   ```

3. (Recommended) Create a virtual environment:

   ```bash
   python -m venv .venv
   # Linux / macOS
   source .venv/bin/activate
   # Windows (PowerShell)
   .venv\Scripts\Activate.ps1
   ```

4. Install the dependency:

   ```bash
   pip install -r requirements.txt
   ```

5. Set the MySQL credentials (next section), then run the program.

You do not need to create the database or tables by hand.

## Configuration

Connection settings are read from environment variables. If a variable is not set, the default in the second column is used.

| Variable | Default | Meaning |
|---|---|---|
| `DB_HOST` | `localhost` | MySQL server host |
| `DB_USER` | `root` | MySQL user |
| `DB_PASSWORD` | `root` | MySQL password |

Set them for the current terminal session:

```bash
# Linux / macOS
export DB_PASSWORD="your_mysql_password"

# Windows Command Prompt
set DB_PASSWORD=your_mysql_password

# Windows PowerShell
$env:DB_PASSWORD = "your_mysql_password"
```

Other constants at the top of `secure_e_authentication_system.py`:

| Constant | Default | Meaning |
|---|---|---|
| `DATABASE_NAME` | `secure_auth_system` | Database created and used by the program |
| `AUDIT_FILE` | `security_audit.csv` | CSV audit file, relative to the working directory |
| `MAX_FAILED_ATTEMPTS` | `3` | Wrong passwords allowed before lockout |

## Running the program

```bash
python secure_e_authentication_system.py
```

If the database connection fails, the program prints a message and exits. Check that MySQL is running and that the credentials are correct.

`getpass` does not work in some IDE consoles (it may hang or show a warning). Run the program from a real terminal.

## Menu options

| Option | Action |
|---|---|
| 1 | Register a new user |
| 2 | Log in |
| 3 | Forgot password / unlock account |
| 4 | View login history (`login_logs` joined with `users`) |
| 5 | View all registered users, including hashes and salts |
| 6 | View the CSV security audit log |
| 7 | Exit |

Options 4, 5 and 6 are labelled "Admin" but there is no admin login. Anyone running the program can use them.

## How it works

### Registration

1. Username is stripped of whitespace and must be non-empty and not already in use.
2. Password is entered twice. The two entries must match and the password must be at least 6 characters.
3. The user supplies a security question and its answer. They are stored together in one column as `question::answer`.
4. A new salt is generated with `secrets.token_hex(16)` (32 hex characters).
5. The hash is `SHA-256(password + salt)`, stored as a 64-character hex string.
6. The row is inserted with `failed_attempts = 0` and `status = 'ACTIVE'`, and a `REGISTRATION` event is written to the CSV.

### Login

1. Look up the username. If it does not exist, print a message and log `UNAUTHORIZED_ACCESS_ATTEMPT` to the CSV only (there is no user row to attach a `login_logs` entry to).
2. If the account status is `LOCKED`, refuse and log `LOCKED_ACCOUNT_ACCESS_ATTEMPT`.
3. Otherwise read the password, hash it with the stored salt, and compare to the stored hash.
4. **Match:** reset `failed_attempts` to 0, insert a `SUCCESS` row in `login_logs`, log `LOGIN_SUCCESS`.
5. **No match:** increment the counter.
   - If it reaches `MAX_FAILED_ATTEMPTS`: set status to `LOCKED`, insert a `LOCKED` row, log `ACCOUNT_LOCKED`.
   - Otherwise: save the new count, insert a `FAILURE` row, log `LOGIN_FAILURE`.

A successful login only prints a welcome message. The program has no session or protected area after login.

### Recovery

1. Enter the username. The stored security question is shown.
2. If the answer matches exactly (case-sensitive), the user sets a new password. A new salt is generated, `failed_attempts` is reset to 0 and status is set to `ACTIVE`. `ACCOUNT_RECOVERY` is logged.
3. If the answer is wrong, `FAILED_RECOVERY_ATTEMPT` is logged.

### Function map

| Area | Functions |
|---|---|
| Database setup | `get_server_connection`, `get_database_connection`, `initialize_database` |
| CSV audit | `initialize_audit_file`, `log_security_event`, `view_security_audit_log` |
| Hashing | `generate_salt`, `hash_password` |
| Registration | `username_exists`, `register_user` |
| Login | `fetch_user_record`, `record_login_log`, `update_failed_attempts`, `lock_account`, `login_user` |
| Recovery | `unlock_account` |
| Reports | `view_login_history`, `view_all_users` |
| Interface | `display_menu`, `main` |

## Database schema

Database: `secure_auth_system`. A copy of the definitions is in [`docs/schema.sql`](docs/schema.sql).

**`users`**

| Column | Type | Notes |
|---|---|---|
| `user_id` | `INT` | Primary key, auto-increment |
| `username` | `VARCHAR(50)` | Unique, not null |
| `hashed_password` | `VARCHAR(64)` | SHA-256 hex digest |
| `salt` | `VARCHAR(32)` | Hex-encoded random salt |
| `security_question` | `VARCHAR(255)` | Stored as `question::answer` |
| `failed_attempts` | `INT` | Default 0 |
| `status` | `VARCHAR(20)` | `ACTIVE` or `LOCKED`, default `ACTIVE` |

**`login_logs`**

| Column | Type | Notes |
|---|---|---|
| `log_id` | `INT` | Primary key, auto-increment |
| `user_id` | `INT` | Foreign key to `users(user_id)` |
| `login_time` | `DATETIME` | |
| `access_status` | `VARCHAR(20)` | `SUCCESS`, `FAILURE` or `LOCKED` |

Both tables use the InnoDB engine.

## Audit log format

`security_audit.csv` has a header row and four columns: `Timestamp`, `Username`, `Event_Type`, `Details`. Rows are appended; the file is never rewritten.

| Event type | Written when |
|---|---|
| `REGISTRATION` | A user account is created |
| `LOGIN_SUCCESS` | Correct password |
| `LOGIN_FAILURE` | Wrong password, below the lockout limit |
| `ACCOUNT_LOCKED` | Wrong password that reaches the limit |
| `LOCKED_ACCOUNT_ACCESS_ATTEMPT` | Login attempted on a locked account |
| `UNAUTHORIZED_ACCESS_ATTEMPT` | Login attempted with an unknown username |
| `ACCOUNT_RECOVERY` | Password reset through the security question |
| `FAILED_RECOVERY_ATTEMPT` | Wrong security answer |

## Sample session

Three wrong passwords, then lockout, then a refused login:

```
--- User Login ---
Enter your username: priya_bora
Incorrect password. Attempt 1 of 3.
...
Incorrect password. Attempt 3 of 3.
Your account has been locked due to too many failed attempts.

--- User Login ---
Enter your username: priya_bora
This account has been locked due to multiple failed login attempts.
Please use 'Forgot Password / Unlock Account' to restore access.
```

More screens (registration, recovery, admin views, SQL output) are in section 8 and 9 of the [report](docs/Secure-E-CS_Project.pdf).

## Known limitations

These are real weaknesses in the current code. They are listed so nobody mistakes this for production-ready authentication.

1. **SHA-256 is the wrong tool for passwords.** It is fast, which makes offline guessing cheap if the database leaks. A salt prevents precomputed-table attacks but does not slow guessing. Use a deliberately slow function: `hashlib.pbkdf2_hmac`, `bcrypt`, `scrypt` or Argon2.
2. **Security answers are stored in plain text** in the `security_question` column, and compared case-sensitively.
3. **Recovery bypasses the lockout.** The security-question flow has no attempt limit and works on any account, not only locked ones. Someone who guesses or knows the answer can reset the password.
4. **No admin authentication.** Options 4 to 6 are open to anyone at the menu. Option 5 prints every hash and salt.
5. **Username enumeration.** "No account found with this username" confirms which usernames do not exist.
6. **Non-constant-time comparison.** Hashes are compared with `==`. `hmac.compare_digest` is the safer choice.
7. **Permanent lockout counter.** Lockout does not expire with time and the failed-attempt count is not time-windowed.
8. **Parsing of `question::answer`.** The value is split on the first `::`. A question that itself contains `::` would be parsed incorrectly.
9. **No session handling.** A successful login does nothing beyond printing a message.
10. **Weak password policy.** Only a 6-character minimum is enforced.
11. **Database account.** The program is designed around the MySQL `root` user. A real deployment should use a dedicated account with only the privileges it needs.
12. **Audit file is not tamper-evident.** It is an ordinary CSV that anyone with file access can edit.


## License

MIT. See [`LICENSE`](LICENSE).
