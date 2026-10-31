"""Local accounts, hashed expiring sessions, and audit authorization."""
import hashlib
import hmac
import json
import re
import secrets
import time
import security_events as events

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
    events.initialize(db)
    db.execute('''CREATE TABLE IF NOT EXISTS password_budget (
        username TEXT PRIMARY KEY, start REAL NOT NULL, attempts INTEGER NOT NULL)''')
    columns={row[1] for row in db.execute('PRAGMA table_info(sessions)')}
    if 'public_id' not in columns:
        db.execute("ALTER TABLE sessions ADD COLUMN public_id TEXT NOT NULL DEFAULT ''")
    if 'created_at' not in columns:
        db.execute('ALTER TABLE sessions ADD COLUMN created_at REAL NOT NULL DEFAULT 0')
    for row in db.execute("SELECT token_hash,expires FROM sessions WHERE public_id='' ").fetchall():
        db.execute('UPDATE sessions SET public_id=?,created_at=? WHERE token_hash=?',
                   (secrets.token_urlsafe(18),row['expires']-SESSION_SECONDS,row['token_hash']))
    db.execute('CREATE UNIQUE INDEX IF NOT EXISTS session_public_id ON sessions(public_id)')


def enabled(db):
    return db.execute("SELECT 1 FROM account_settings WHERE key='accounts_enabled'").fetchone() is not None


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITERATIONS).hex()


def create_user(db, username, role, password):
    if username=='local-maintenance' or not isinstance(username, str) or not re.fullmatch(r'[a-z][a-z0-9_.-]{2,49}', username):
        raise ValueError('Username must be 3–50 lowercase ASCII letters, digits, dots, underscores, or hyphens.')
    if role not in ROLES or not isinstance(password, str) or not 14 <= len(password) <= 256:
        raise ValueError('Use a valid role and a password of 14–256 characters.')
    if not enabled(db) and role != 'administrator':
        raise ValueError('Create an administrator first.')
    salt = secrets.token_hex(16)
    db.execute('INSERT INTO users(username,role,salt,password_hash) VALUES(?,?,?,?)',
               (username, role, salt, password_hash(password, salt)))
    db.execute("INSERT OR IGNORE INTO account_settings VALUES('accounts_enabled','1')")
    events.append(db,'account_created',actor='local-maintenance',target=username)


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
        if count==10:
            db.execute('UPDATE login_budget SET attempts=11 WHERE id=1')
            events.append(db,'login_throttled')
        db.commit()
        raise RequestError(429, 'Too many login attempts. Try again after one minute.')
    db.execute('INSERT OR REPLACE INTO login_budget VALUES(1,?,?)', (start, count + 1))
    db.commit()  # Keep failed attempts even if authentication fails.
    row = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    salt = row['salt'] if row else '00' * 16
    candidate = password_hash(password, salt)
    expected = row['password_hash'] if row else '00' * 32
    if not hmac.compare_digest(candidate, expected) or not row or not row['active']:
        events.append(db,'login_failed')
        db.commit()
        raise RequestError(401, 'Invalid username or password.')
    # Recheck after password hashing so a concurrent reset/disable cannot issue a
    # fresh session from credentials that have just been revoked.
    db.execute('BEGIN IMMEDIATE')
    fresh=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    if not fresh or not fresh['active'] or fresh['password_hash']!=expected:
        events.append(db,'login_failed')
        db.commit()
        raise RequestError(401,'Invalid username or password.')
    row=fresh
    token = secrets.token_urlsafe(32)
    db.execute('DELETE FROM sessions WHERE expires<=?', (now,))
    db.execute('INSERT INTO sessions(token_hash,username,expires,public_id,created_at) VALUES(?,?,?,?,?)',
               (digest(token),username,now+SESSION_SECONDS,secrets.token_urlsafe(18),now))
    removed=db.execute('''DELETE FROM sessions WHERE username=? AND token_hash NOT IN
        (SELECT token_hash FROM sessions WHERE username=? ORDER BY created_at DESC,token_hash DESC LIMIT 10)''',(username,username)).rowcount
    if removed:events.append(db,'session_evicted',actor=username)
    events.append(db,'login_succeeded',actor=username)
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


def session_list(db,user,authorization,now=None):
    if not user:raise RequestError(403,'Individual account sign-in is required.')
    current=digest(authorization.removeprefix('Bearer '))
    now=time.time() if now is None else now
    return [{'id':row['public_id'],'created_at':row['created_at'],'expires_at':row['expires'],
             'current':row['token_hash']==current} for row in db.execute(
        'SELECT * FROM sessions WHERE username=? AND expires>? ORDER BY created_at DESC,token_hash DESC LIMIT 10',
        (user['username'],now))]


def revoke_sessions(db,user,session_id=None):
    if not user:raise RequestError(403,'Individual account sign-in is required.')
    if session_id is not None:
        if not isinstance(session_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{24}',session_id):
            raise RequestError(400,'Invalid session identifier.')
        removed=db.execute('DELETE FROM sessions WHERE public_id=? AND username=?',(session_id,user['username'])).rowcount
        if not removed:raise RequestError(404,'Session not found.')
        events.append(db,'session_revoked',actor=user['username'])
    else:
        db.execute('DELETE FROM sessions WHERE username=?',(user['username'],))
        events.append(db,'sessions_revoked',actor=user['username'])


def change_password(db,user,data,now=None):
    if not user:raise RequestError(403,'Individual account sign-in is required.')
    if not isinstance(data,dict) or set(data)!={'current_password','new_password'}:
        raise RequestError(400,'Supply current and new passwords.')
    current,new=data['current_password'],data['new_password']
    if not isinstance(current,str) or len(current)>256 or not isinstance(new,str) or not 14<=len(new)<=256 or current==new:
        raise RequestError(400,'Use a different new password of 14–256 characters.')
    now=time.time() if now is None else now
    username=user['username']
    db.execute('BEGIN IMMEDIATE')
    budget=db.execute('SELECT start,attempts FROM password_budget WHERE username=?',(username,)).fetchone()
    start,count=(budget['start'],budget['attempts']) if budget and now-budget['start']<900 else (now,0)
    if count>=5:
        if count==5:
            db.execute('UPDATE password_budget SET attempts=6 WHERE username=?',(username,))
            events.append(db,'password_change_throttled',actor=username)
        db.commit()
        raise RequestError(429,'Too many password changes attempted. Wait fifteen minutes.')
    db.execute('INSERT OR REPLACE INTO password_budget VALUES(?,?,?)',(username,start,count+1))
    db.commit()
    row=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
    verified=bool(row and row['active'] and hmac.compare_digest(password_hash(current,row['salt']),row['password_hash']))
    if not verified:
        events.append(db,'password_change_failed',actor=username)
        db.commit()
        raise RequestError(401,'Current password is incorrect.')
    salt=secrets.token_hex(16)
    hashed=password_hash(new,salt)
    db.execute('BEGIN IMMEDIATE')
    fresh=db.execute('SELECT password_hash,active FROM users WHERE username=?',(username,)).fetchone()
    if not fresh or not fresh['active'] or fresh['password_hash']!=row['password_hash']:
        raise RequestError(409,'Account changed. Sign in again before changing the password.')
    db.execute('UPDATE users SET salt=?,password_hash=? WHERE username=?',(salt,hashed,username))
    db.execute('DELETE FROM sessions WHERE username=?',(username,))
    events.append(db,'password_changed',actor=username)
