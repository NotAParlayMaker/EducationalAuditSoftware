"""Local accounts, hashed expiring sessions, and audit authorization."""
import hashlib
import hmac
import json
import re
import secrets
import time

from security import RequestError

ROLES = ('administrator', 'auditor', 'remediation_owner', 'reviewer')
ITERATIONS = 600_000
SESSION_SECONDS = 3600


def initialize(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS account_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, role TEXT NOT NULL,
            salt TEXT NOT NULL, password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS login_budget (id INTEGER PRIMARY KEY CHECK(id=1), start REAL NOT NULL, attempts INTEGER NOT NULL);
    ''')


def enabled(db):
    return db.execute("SELECT 1 FROM account_settings WHERE key='accounts_enabled'").fetchone() is not None


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITERATIONS).hex()


def create_user(db, username, role, password):
    if not isinstance(username, str) or not re.fullmatch(r'[a-z][a-z0-9_.-]{2,49}', username):
        raise ValueError('Username must be 3–50 lowercase ASCII letters, digits, dots, underscores, or hyphens.')
    if role not in ROLES or not isinstance(password, str) or not 14 <= len(password) <= 256:
        raise ValueError('Use a valid role and a password of 14–256 characters.')
    if not enabled(db) and role != 'administrator':
        raise ValueError('Create an administrator first.')
    salt = secrets.token_hex(16)
    db.execute('INSERT INTO users(username,role,salt,password_hash) VALUES(?,?,?,?)',
               (username, role, salt, password_hash(password, salt)))
    db.execute("INSERT OR IGNORE INTO account_settings VALUES('accounts_enabled','1')")


def login(db, data, now=None):
    now = time.time() if now is None else now
    if not enabled(db):
        raise RequestError(409, 'Accounts are not configured. Use the local setup command.')
    if not isinstance(data, dict) or set(data) != {'username', 'password'}:
        raise RequestError(400, 'Supply username and password.')
    username, password = data['username'], data['password']
    if not isinstance(username, str) or not isinstance(password, str) or len(username) > 50 or len(password) > 256:
        raise RequestError(400, 'Invalid credentials format.')
    # Global bounded budget blocks username/IP rotation on this loopback-only service.
    db.execute('BEGIN IMMEDIATE')
    row = db.execute('SELECT * FROM login_budget WHERE id=1').fetchone()
    start, count = (row['start'], row['attempts']) if row and now - row['start'] < 60 else (now, 0)
    if count >= 10:
        db.commit()
        raise RequestError(429, 'Too many login attempts. Try again after one minute.')
    db.execute('INSERT OR REPLACE INTO login_budget VALUES(1,?,?)', (start, count + 1))
    db.commit()  # Keep failed attempts even if authentication fails.
    row = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    salt = row['salt'] if row else '00' * 16
    candidate = password_hash(password, salt)
    expected = row['password_hash'] if row else '00' * 32
    if not hmac.compare_digest(candidate, expected) or not row or not row['active']:
        raise RequestError(401, 'Invalid username or password.')
    token = secrets.token_urlsafe(32)
    db.execute('DELETE FROM sessions WHERE expires<=?', (now,))
    db.execute('INSERT INTO sessions VALUES(?,?,?)', (digest(token), username, now + SESSION_SECONDS))
    return {'token': token, 'expires_in': SESSION_SECONDS, 'user': {'username': username, 'role': row['role']}}


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def principal(db, authorization, now=None):
    if not enabled(db):
        return None
    token = authorization.removeprefix('Bearer ') if authorization.startswith('Bearer ') else ''
    if not 20 <= len(token) <= 256:
        raise RequestError(401, 'Sign in to continue.')
    row = db.execute('''SELECT users.username, users.role FROM sessions JOIN users USING(username)
        WHERE token_hash=? AND expires>? AND active=1''', (digest(token), time.time() if now is None else now)).fetchone()
    if not row:
        raise RequestError(401, 'Session expired or invalid. Sign in again.')
    return dict(row)


def authorize_resource(user, resource, write=False):
    if user is None:
        return
    if resource in ('students', 'attendance', 'grades') and user['role'] != 'administrator':
        raise RequestError(403, 'This role cannot access student records.')
    if write and resource in ('assets', 'tickets') and user['role'] != 'administrator':
        raise RequestError(403, 'Only administrators can change this resource.')


def authorize_audit(db, user, data, audit_id=None):
    if user is None:
        return data
    if not isinstance(data, dict):
        raise RequestError(400, 'Invalid audit object.')
    data = dict(data)
    data['actor'] = user['username']  # Browser-supplied actor never establishes identity.
    previous = None
    if audit_id is not None:
        row = db.execute('SELECT * FROM audits WHERE id=?', (audit_id,)).fetchone()
        if row is None:
            raise LookupError()
        previous = dict(row)
    role, name = user['role'], user['username']
    if previous is None and role not in ('administrator', 'auditor'):
        raise RequestError(403, 'Only auditors and administrators can create findings.')
    if previous and role not in ('administrator', 'auditor'):
        if role == 'remediation_owner' and previous['owner'] == name:
            allowed = {'remediation', 'evidence', 'status'}
            next_states = {'Open', 'In progress', 'Awaiting verification'}
        elif role == 'reviewer' and previous['reviewer'] == name and previous['status'] == 'Awaiting verification':
            allowed = {'verification', 'closure_reason', 'status'}
            next_states = {'Awaiting verification', 'Closed', 'In progress'}
        else:
            raise RequestError(403, 'This finding is not assigned to your role.')
        for key, value in data.items():
            if key not in allowed | {'actor', 'revision'} and value != previous.get(key):
                raise RequestError(403, 'This role cannot change assignment or finding details.')
        if data.get('status', previous['status']) not in next_states:
            raise RequestError(403, 'This role cannot perform this transition.')
    status = data.get('status', previous['status'] if previous else 'Draft')
    for field, roles in [('owner', ('administrator', 'remediation_owner')), ('reviewer', ('administrator', 'reviewer'))]:
        value = data.get(field, previous[field] if previous else '')
        if value:
            if not isinstance(value, str):
                raise RequestError(400, 'Invalid assignment.')
            row = db.execute('SELECT role,active FROM users WHERE username=?', (value,)).fetchone()
            if not row or not row['active'] or row['role'] not in roles:
                raise RequestError(400, 'Assignments must name active accounts with the appropriate role.')
    if status == 'Closed':
        reviewer = data.get('reviewer', previous['reviewer'] if previous else '')
        owner = data.get('owner', previous['owner'] if previous else '')
        if role not in ('administrator', 'reviewer') or name != reviewer or name == owner:
            raise RequestError(403, 'Only the assigned independent reviewer can close a finding.')
        if not previous or previous['reviewer'] != name or previous['owner'] == name:
            raise RequestError(403, 'Reviewer assignment must be saved before closure.')
    return data
