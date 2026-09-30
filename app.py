"""Small Flask/SQLite learning app with login and per-user private notes."""
import hashlib
import os
import re
import secrets
import sqlite3
import time
from functools import wraps
from pathlib import Path
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    secret = os.environ.get('NOTES_SECRET_KEY')
    if not secret and not test_config:
        key_path = Path(app.instance_path) / 'session.key'
        try:
            with key_path.open('x') as file:
                os.chmod(key_path, 0o600)
                file.write(secrets.token_hex(32))
        except FileExistsError:
            pass
        secret = key_path.read_text().strip()
    app.config.update(SECRET_KEY=secret, DATABASE=str(Path(app.instance_path) / 'notes.sqlite3'),
                      MAX_CONTENT_LENGTH=32768, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=False)
    if test_config:
        app.config.update(test_config)

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'])
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys = ON')
        return g.db

    @app.teardown_appcontext
    def close_db(error=None):
        connection = g.pop('db', None)
        if connection is not None:
            connection.close()

    with app.app_context():
        db().executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                title TEXT NOT NULL, body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS logins (
                token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
                expires_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts (ip TEXT NOT NULL, happened_at INTEGER NOT NULL);
        ''')
        db().commit()

    def token_hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def csrf_token():
        if 'csrf' not in session:
            session['csrf'] = secrets.token_urlsafe(32)
        return session['csrf']

    app.jinja_env.globals['csrf_token'] = csrf_token

    @app.before_request
    def protect_request():
        g.user = None
        token = session.get('auth_token')
        if isinstance(token, str):
            g.user = db().execute('''SELECT users.id, users.username FROM logins JOIN users
                ON users.id=logins.user_id WHERE token_hash=? AND expires_at>?''',
                (token_hash(token), int(time.time()))).fetchone()
        if request.method == 'POST':
            expected, provided = session.get('csrf'), request.form.get('csrf_token')
            if not isinstance(expected, str) or not isinstance(provided, str) or not secrets.compare_digest(expected, provided):
                abort(400, description='The form expired. Reload the page and try again.')

    @app.after_request
    def response_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; img-src 'self'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['Cache-Control'] = 'no-store'
        return response

    def login_required(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for('login'))
            return function(*args, **kwargs)
        return wrapped

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if g.user is not None:
            return redirect(url_for('index'))
        if request.method == 'POST':
            username = request.form.get('username', '').strip().lower()
            password = request.form.get('password', '')
            if not re.fullmatch(r'[a-z0-9_]{3,30}', username):
                flash('Use 3–30 letters, numbers or underscores for your username.', 'error')
            elif not 12 <= len(password) <= 128:
                flash('Choose a password between 12 and 128 characters.', 'error')
            else:
                try:
                    db().execute('INSERT INTO users(username, password_hash) VALUES (?, ?)',
                                 (username, generate_password_hash(password, method='scrypt')))
                    db().commit()
                except sqlite3.IntegrityError:
                    flash('That username is unavailable. Choose another.', 'error')
                else:
                    flash('Account created. You can now sign in.', 'success')
                    return redirect(url_for('login'))
        return render_template('auth.html', mode='register')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if g.user is not None:
            return redirect(url_for('index'))
        if request.method == 'POST':
            now, ip = int(time.time()), request.remote_addr or 'unknown'
            db().execute('DELETE FROM attempts WHERE happened_at <= ?', (now - 300,))
            count = db().execute('SELECT COUNT(*) FROM attempts WHERE ip=?', (ip,)).fetchone()[0]
            if count >= 5:
                db().commit()
                flash('Too many attempts. Wait five minutes before trying again.', 'error')
                return render_template('auth.html', mode='login'), 429
            username = request.form.get('username', '').strip().lower()
            password = request.form.get('password', '')
            user = db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            if not user or not check_password_hash(user['password_hash'], password):
                db().execute('INSERT INTO attempts VALUES (?, ?)', (ip, now))
                db().commit()
                flash('Username or password is incorrect.', 'error')
            else:
                old_token = session.get('auth_token')
                if isinstance(old_token, str):
                    db().execute('DELETE FROM logins WHERE token_hash=?', (token_hash(old_token),))
                db().execute('DELETE FROM logins WHERE expires_at <= ?', (now,))
                session.clear()
                token = secrets.token_urlsafe(32)
                db().execute('INSERT INTO logins VALUES (?, ?, ?)', (token_hash(token), user['id'], now + 3600))
                db().commit()
                session['auth_token'] = token
                csrf_token()
                return redirect(url_for('index'))
        return render_template('auth.html', mode='login')

    @app.post('/logout')
    @login_required
    def logout():
        db().execute('DELETE FROM logins WHERE token_hash=?', (token_hash(session['auth_token']),))
        db().commit()
        session.clear()
        return redirect(url_for('login'))

    @app.route('/', methods=['GET', 'POST'])
    @login_required
    def index():
        if request.method == 'POST':
            title, body = request.form.get('title', '').strip(), request.form.get('body', '').strip()
            if not 1 <= len(title) <= 80 or not 1 <= len(body) <= 5000:
                flash('Add a title of 1–80 characters and a note of 1–5000 characters.', 'error')
            else:
                db().execute('INSERT INTO notes(user_id,title,body) VALUES (?,?,?)', (g.user['id'],title,body))
                db().commit()
                flash('Note saved.', 'success')
                return redirect(url_for('index'))
        notes = db().execute('SELECT * FROM notes WHERE user_id=? ORDER BY id DESC', (g.user['id'],)).fetchall()
        return render_template('notes.html', notes=notes)

    @app.post('/notes/<int:note_id>/delete')
    @login_required
    def delete_note(note_id):
        result = db().execute('DELETE FROM notes WHERE id=? AND user_id=?', (note_id,g.user['id']))
        if result.rowcount == 0:
            db().rollback()
            abort(404)
        db().commit()
        flash('Note deleted.', 'success')
        return redirect(url_for('index'))

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    def friendly_error(error):
        message = {400:'Reload the page and try submitting the form again.',
                   404:'This page or note is unavailable.',413:'Your submission is too large.'}.get(error.code)
        return render_template('error.html', message=message), error.code

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5000, debug=False)
