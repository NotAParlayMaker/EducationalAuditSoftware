"""TOTP, single-use recovery codes, and encrypted enrollment state."""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time
from urllib.parse import quote

import secret_config
import security_events as events
from security import RequestError, auth_throttled


def initialize(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS mfa_accounts(username TEXT PRIMARY KEY, secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0, expires REAL NOT NULL, last_counter INTEGER NOT NULL DEFAULT -1);
        CREATE TABLE IF NOT EXISTS mfa_login_budget(username TEXT PRIMARY KEY,start REAL NOT NULL,attempts INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS mfa_backoff_budget(identity TEXT PRIMARY KEY,start REAL NOT NULL,attempts INTEGER NOT NULL,updated_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS mfa_budget(username TEXT PRIMARY KEY,start REAL NOT NULL,attempts INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS mfa_recovery(username TEXT NOT NULL, code_hash TEXT NOT NULL,
            PRIMARY KEY(username,code_hash));
    ''')
    columns={row[1] for row in db.execute('PRAGMA table_info(sessions)')}
    for name,kind in [('auth_time','REAL'),('mfa_verified','INTEGER')]:
        if name not in columns:db.execute('ALTER TABLE sessions ADD COLUMN '+name+' '+kind+' NOT NULL DEFAULT 0')


def required(user,db=None):
    stored=db.execute("SELECT value FROM account_settings WHERE key='mfa_required'").fetchone() if db is not None else None
    policy=stored[0] if stored else ''
    return policy=='all' or os.environ.get('SCHOOL_PROFILE')=='cloud' or ((policy=='privileged' or os.environ.get('SCHOOL_REQUIRE_MFA')=='1') and user['role'] in ('administrator','registrar','teacher','reviewer'))


def active(db,username):
    row=db.execute('SELECT enabled FROM mfa_accounts WHERE username=?',(username,)).fetchone()
    return bool(row and row['enabled'])


def crypt():
    try:return secret_config.fernet('SCHOOL_MFA_KEY')
    except (ValueError,ImportError):raise RequestError(503,'MFA encryption is not configured or unavailable.') from None


def totp(secret,counter):
    raw=base64.b32decode(secret,casefold=False)
    value=hmac.new(raw,struct.pack('>Q',counter),hashlib.sha1).digest();offset=value[-1]&15
    return str((struct.unpack('>I',value[offset:offset+4])[0]&0x7fffffff)%1_000_000).zfill(6)


def unpack(username,encrypted):
    try:
        value=json.loads(crypt().decrypt(encrypted.encode()).decode())
        if value['username']!=username:raise ValueError()
        if not isinstance(value.get('secret'),str) or not re.fullmatch('[A-Z2-7]{32}',value['secret']):raise ValueError()
        return value['secret']
    except RequestError:raise
    except Exception:raise RequestError(503,'MFA secret cannot be verified. Contact the local administrator.') from None


def check_factor(db,username,code,now=None,pending=False):
    """Return an internal, account-bound proof without consuming the factor."""
    now=time.time() if now is None else now
    if not isinstance(code,str) or len(code)>64:return None
    row=db.execute('SELECT * FROM mfa_accounts WHERE username=?',(username,)).fetchone()
    if not row or (not row['enabled'] and not pending):return None
    if pending and (row['enabled'] or row['expires']<now):return None
    binding={'secret':row['secret'],'enabled':row['enabled']}
    if code.startswith('recovery-') and not pending:
        digest=hashlib.sha256((username+':'+code).encode()).hexdigest()
        if db.execute('SELECT 1 FROM mfa_recovery WHERE username=? AND code_hash=?',(username,digest)).fetchone():return dict(binding,recovery=digest)
        return None
    if not re.fullmatch('[0-9]{6}',code):return None
    secret=unpack(username,row['secret']);current=int(now//30)
    for counter in (current-1,current,current+1):
        if counter>=0 and counter>row['last_counter'] and hmac.compare_digest(totp(secret,counter),code):
            return dict(binding,counter=counter)
    return None


def consume(db,username,code,now=None,pending=False,expected=None):
    proof=check_factor(db,username,code,now,pending)
    if not proof or (expected is not None and proof!=expected):return False
    if 'recovery' in proof:
        return db.execute('''DELETE FROM mfa_recovery WHERE username=? AND code_hash=? AND EXISTS
            (SELECT 1 FROM mfa_accounts WHERE username=? AND secret=? AND enabled=?)''',
            (username,proof['recovery'],username,proof['secret'],proof['enabled'])).rowcount==1
    return db.execute('UPDATE mfa_accounts SET last_counter=? WHERE username=? AND secret=? AND enabled=? AND last_counter<?',
        (proof['counter'],username,proof['secret'],proof['enabled'],proof['counter'])).rowcount==1


def backoff_factor(db,username,code,now):
    """Reserve a separate recovery guess, then verify before any password hash."""
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    identity=hashlib.sha256(username.encode()).hexdigest()
    db.execute('DELETE FROM mfa_backoff_budget WHERE updated_at<?',(now-86400,))
    row=db.execute('SELECT * FROM mfa_backoff_budget WHERE identity=?',(identity,)).fetchone()
    start,count=(row['start'],row['attempts']) if row and now-row['start']<900 else (now,0)
    if count>=5:
        if count==5:
            db.execute('UPDATE mfa_backoff_budget SET attempts=6 WHERE identity=?',(identity,))
            events.append(db,'mfa_backoff_throttled')
        return None
    if not row and db.execute('SELECT count(*) FROM mfa_backoff_budget').fetchone()[0]>=4096:
        db.execute('DELETE FROM mfa_backoff_budget WHERE identity=(SELECT identity FROM mfa_backoff_budget ORDER BY updated_at LIMIT 1)')
    db.execute('INSERT OR REPLACE INTO mfa_backoff_budget VALUES(?,?,?,?)',(identity,start,count+1,now))
    return check_factor(db,username,code,now)


def require_recent(user,now=None):
    now=time.time() if now is None else now
    if not user or not 0<=now-user.get('_auth_time',0)<=300:
        raise RequestError(428,'Fresh authentication required. Reauthenticate in Account security, then retry.')


def begin(db,user,now=None):
    require_recent(user,now);now=time.time() if now is None else now
    if active(db,user['username']):raise RequestError(409,'MFA is already enabled. Use trusted local recovery to reset it.')
    secret=base64.b32encode(secrets.token_bytes(20)).decode()
    encoded=crypt().encrypt(json.dumps({'username':user['username'],'secret':secret}).encode()).decode()
    db.execute('INSERT OR REPLACE INTO mfa_accounts VALUES(?,?,0,?,-1)',(user['username'],encoded,now+600))
    events.append(db,'mfa_enrollment_started',actor=user['username'])
    uri='otpauth://totp/'+quote('Schooldesk:'+user['username'],safe='')+'?secret='+secret+'&issuer=Schooldesk&algorithm=SHA1&digits=6&period=30'
    return {'secret':secret,'uri':uri,'expires_in':600}


def confirm(db,user,code,now=None):
    require_recent(user,now)
    current=time.time() if now is None else now
    db.execute('BEGIN IMMEDIATE')
    budget=db.execute('SELECT * FROM mfa_budget WHERE username=?',(user['username'],)).fetchone()
    start,count=(budget['start'],budget['attempts']) if budget and current-budget['start']<900 else (current,0)
    if count>=5:
        if count==5:
            db.execute('UPDATE mfa_budget SET attempts=6 WHERE username=?',(user['username'],));events.append(db,'mfa_enrollment_throttled',actor=user['username'])
        db.commit();raise auth_throttled()
    db.execute('INSERT OR REPLACE INTO mfa_budget VALUES(?,?,?)',(user['username'],start,count+1));db.commit()
    db.execute('BEGIN IMMEDIATE')
    if not consume(db,user['username'],code,now,pending=True):
        events.append(db,'mfa_enrollment_failed',actor=user['username']);db.commit()
        raise RequestError(400,'Invalid or expired enrollment code.')
    codes=['recovery-'+secrets.token_hex(16) for _ in range(8)]
    db.execute('UPDATE mfa_accounts SET enabled=1 WHERE username=?',(user['username'],))
    db.execute('DELETE FROM mfa_recovery WHERE username=?',(user['username'],))
    db.executemany('INSERT INTO mfa_recovery VALUES(?,?)',[(user['username'],hashlib.sha256((user['username']+':'+code).encode()).hexdigest()) for code in codes])
    db.execute('DELETE FROM sessions WHERE username=?',(user['username'],))
    events.append(db,'mfa_enabled',actor=user['username'])
    return {'recovery_codes':codes,'signed_out':True}


def enforce_login_budget(db,username,now):
    row=db.execute('SELECT * FROM mfa_login_budget WHERE username=?',(username,)).fetchone()
    start,count=(row['start'],row['attempts']) if row and now-row['start']<900 else (now,0)
    if count>=5:
        if count==5:
            db.execute('UPDATE mfa_login_budget SET attempts=6 WHERE username=?',(username,))
            events.append(db,'mfa_login_throttled',target=username)
        db.commit();raise auth_throttled()
    return start,count


def login_factor(db,username,code,now):
    start,count=enforce_login_budget(db,username,now)
    valid=consume(db,username,code,now)
    db.execute('INSERT OR REPLACE INTO mfa_login_budget VALUES(?,?,?)',(username,start,0 if valid else count+1))
    return valid
