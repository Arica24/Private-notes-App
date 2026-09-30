"""Security and main-flow checks using temporary data, not real user accounts."""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from app import create_app


class NotesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = str(Path(self.directory.name) / 'test.sqlite3')
        self.app = create_app({'TESTING': True, 'SECRET_KEY': 'testing-only-key', 'DATABASE': self.path})
        self.alice = self.app.test_client()
        self.bob = self.app.test_client()

    def tearDown(self):
        self.directory.cleanup()

    def post(self, client, path, data=None):
        client.get('/login')
        with client.session_transaction() as state:
            csrf = state['csrf']
        return client.post(path, data={**(data or {}), 'csrf_token': csrf})

    def account(self, client, username):
        self.post(client, '/register', {'username': username, 'password': 'a memorable password'})
        return self.post(client, '/login', {'username': username, 'password': 'a memorable password'})

    def test_registration_login_and_hash(self):
        self.assertEqual(self.account(self.alice, 'alice').status_code, 302)
        with sqlite3.connect(self.path) as connection:
            stored = connection.execute('SELECT password_hash FROM users').fetchone()[0]
        self.assertNotEqual(stored, 'a memorable password')
        self.assertTrue(stored.startswith('scrypt:'))
        self.assertIn(b'Room for your ideas', self.alice.get('/').data)

    def test_csrf_required(self):
        self.assertEqual(self.alice.post('/register', data={'username':'alice'}).status_code, 400)

    def test_private_notes_and_delete_ownership(self):
        self.account(self.alice, 'alice')
        self.post(self.alice, '/', {'title':'Alice secret', 'body':'Only Alice should see this'})
        self.account(self.bob, 'bob')
        self.assertNotIn(b'Alice secret', self.bob.get('/').data)
        self.assertEqual(self.post(self.bob, '/notes/1/delete').status_code, 404)
        self.assertIn(b'Alice secret', self.alice.get('/').data)
        self.assertEqual(self.post(self.alice, '/notes/1/delete').status_code, 302)
        self.assertNotIn(b'Alice secret', self.alice.get('/').data)

    def test_script_text_is_escaped(self):
        self.account(self.alice, 'alice')
        self.post(self.alice, '/', {'title':'Test', 'body':'<script>alert(1)</script>'})
        html = self.alice.get('/').data
        self.assertIn(b'&lt;script&gt;', html)
        self.assertNotIn(b'<script>', html)

    def test_logout_revokes_server_session(self):
        self.account(self.alice, 'alice')
        with self.alice.session_transaction() as state:
            original = state['auth_token']
        self.post(self.alice, '/logout')
        with self.alice.session_transaction() as state:
            state['auth_token'] = original
        self.assertEqual(self.alice.get('/').status_code, 302)
        with sqlite3.connect(self.path) as connection:
            count = connection.execute('SELECT COUNT(*) FROM logins WHERE token_hash=?',
                                       (hashlib.sha256(original.encode()).hexdigest(),)).fetchone()[0]
        self.assertEqual(count, 0)

    def test_expired_session(self):
        self.account(self.alice, 'alice')
        with sqlite3.connect(self.path) as connection:
            connection.execute('UPDATE logins SET expires_at=0')
        self.assertEqual(self.alice.get('/').status_code, 302)

    def test_login_throttling(self):
        for _ in range(5):
            self.post(self.alice, '/login', {'username':'nobody', 'password':'wrong'})
        self.assertEqual(self.post(self.alice, '/login', {'username':'nobody','password':'wrong'}).status_code,429)

    def test_parameterised_query_and_validation(self):
        self.assertEqual(self.account(self.alice, 'alice').status_code,302)
        self.post(self.alice, '/', {'title':'', 'body':'empty title'})
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM notes').fetchone()[0],0)
        self.post(self.alice, '/logout')
        response = self.post(self.alice, '/login', {'username':"' OR 1=1 --",'password':'anything'})
        self.assertIn(b'Username or password is incorrect',response.data)
        self.assertEqual(self.alice.get('/').status_code,302)


if __name__ == '__main__':
    unittest.main()
