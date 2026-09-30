# Private Notes App

A small web development and security learning project: create an account, sign in, and keep notes visible only to your own account.

Built with Python, Flask, SQLite, HTML and CSS. It is not an original university submission.

## Features

- Register with a username and password.
- Sign in and sign out.
- Create, view and delete your own notes.
- Store notes in a local SQLite database.
- Responsive layouts for phones and computers.

## Start on a Mac

1. Install Python 3.9 or newer.
2. Extract the download, keeping all files and folders together.
3. Open Terminal in the `private-notes-app` folder.
4. Run each line:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
```

5. Open **http://127.0.0.1:5000** in your browser.
6. Select **Create an account**, choose a username and a password of at least 12 characters, then sign in.
7. Press Control+C in Terminal when you want to stop the app.

Next time, activate the environment and start `app.py` again. Your accounts and notes remain in the local database.

If port 5000 is busy, run:

```bash
python3 -m flask --app 'app:create_app()' run --port 5001
```

Then open http://127.0.0.1:5001.

## Windows

In a terminal opened in this folder:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

If your terminal does not permit activation, run `.venv\Scripts\python.exe -m pip install -r requirements.txt`, followed by `.venv\Scripts\python.exe app.py`.

## Files

| File or folder | Purpose |
|---|---|
| `app.py` | Routes, authentication, database and input checks |
| `templates/` | HTML pages rendered on the server |
| `static/style.css` | Responsive styling |
| `requirements.txt` | Python dependencies |
| `test_app.py` | Main-flow and security tests |
| `.gitignore` | Keeps local database and secrets out of Git |
| `instance/` | Created locally on first run; contains database and session key |

## Security controls demonstrated

- **Password hashing:** salted scrypt hashes through Werkzeug; passwords are not stored directly.
- **Parameterized SQL:** user input is passed as query parameters.
- **Per-user access:** note lists and deletions use the authenticated user ID. Changing a note ID does not grant access.
- **Server-side login records:** a random token maps to a user and one-hour expiry. Only its SHA-256 hash is stored in the database. The token is carried inside Flask's signed session cookie.
- **Logout revocation:** the login record is deleted so the old token cannot be reused.
- **CSRF checks:** every POST form requires a token tied to the signed browser session.
- **Escaped output:** Jinja renders note content as text, including script-like input.
- **Login throttling:** five failed attempts per directly observed IP in a five-minute window block further attempts temporarily.
- **Response headers:** a restrictive Content Security Policy, no-store caching, nosniff and a referrer policy.
- **Cookies:** HttpOnly and SameSite=Lax. Secure is deliberately off for localhost HTTP; enable it when configuring HTTPS hosting.

Flask session cookies are signed, not encrypted. Do not put passwords or note bodies in them. The session signing secret is generated locally or can be supplied via the `NOTES_SECRET_KEY` environment variable; it is excluded from the download and Git.

The database is not encrypted. Local administrators and anyone with access to the database file can read notes. This is a local teaching app, not a guarantee of encrypted or production-grade storage.

## Run tests

With the environment activated:

```bash
python3 -m unittest -v
```

The tests use a temporary database and cover registration, password hashing, CSRF rejection, per-user visibility, unauthorised deletion, output escaping, expired sessions, logout revocation, failed-login throttling and input handling.

## Learn by trying

1. Create two accounts and add a different note to each.
2. Confirm each account sees only its own notes.
3. Review the delete query and explain why it checks both note ID and user ID.
4. Save `<script>alert(1)</script>` as a note. It should display as text.
5. Trace registration, login and note creation from HTML form to route to database.

## Limits and future work

The Flask development server binds only to your computer. This project has not been deployed. Before internet hosting, add a production server, HTTPS and Secure cookies, deployment-specific trusted-host and proxy configuration, secrets management, backups and operational monitoring. The simple IP limit is for teaching, may affect shared networks and is not a complete defence against distributed attacks. Password reset, MFA, email verification and note editing are not included.


## References

- [Flask security guidance](https://flask.palletsprojects.com/en/stable/web-security/)
- [Werkzeug password hashing](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security)
