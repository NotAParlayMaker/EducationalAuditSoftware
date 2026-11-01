"""Allowlisted security metadata with a verifiable hash chain, never payloads."""
import hashlib
import hmac
import json
import re
import secret_config
from datetime import datetime, timezone

CODES = frozenset({'account_created','account_disabled','password_reset','login_succeeded',
    'login_failed','login_throttled','session_revoked','sessions_revoked','session_evicted',
    'password_changed','password_change_failed','password_change_throttled',
    'import_preview','import_committed','export_completed','mfa_login_throttled','mfa_policy_enabled','mfa_enrollment_started','mfa_enrollment_failed','mfa_enrollment_throttled','mfa_enabled','mfa_reset','reauthenticated','evidence_scanned','evidence_quarantined','startup_sessions_revoked','cli_users_listed','event_history_sealed'})
ZERO = '0' * 64
CODES=CODES | {'cli_maintenance','cli_maintenance_failed','cli_account_failed','cli_doctor','cli_server_started','mfa_backoff_throttled'}


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, event TEXT NOT NULL,
        actor TEXT NOT NULL, target TEXT NOT NULL, previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL)''')
    if 'event_mac' not in {row[1] for row in db.execute('PRAGMA table_info(security_events)')}:
        db.execute("ALTER TABLE security_events ADD COLUMN event_mac TEXT NOT NULL DEFAULT ''")


def signing_key():
    value=secret_config.read('SCHOOL_EVENT_KEY')
    if value is None:return None
    if not re.fullmatch('[a-f0-9]{64}',value):raise ValueError('SCHOOL_EVENT_KEY must be a 32-byte lowercase hexadecimal key.')
    return bytes.fromhex(value)


def event_mac(key,record,previous):
    message=json.dumps({'id':record['id'],'event_hash':record['event_hash'],'previous_mac':previous},sort_keys=True,separators=(',',':')).encode()
    return hmac.new(key,b'schooldesk.events.hmac.v1\0'+message,hashlib.sha256).hexdigest()


def event_hash(record):
    values={key:record[key] for key in ('id','occurred_at','event','actor','target','previous_hash')}
    return hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def append(db, event, actor='', target=''):
    if event not in CODES or any(value and not re.fullmatch(r'[a-z][a-z0-9_.-]{2,49}',value) for value in (actor,target)):
        raise ValueError('Invalid security event metadata.')
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    key=signing_key()
    last=db.execute('SELECT id,event_hash,event_mac FROM security_events ORDER BY id DESC LIMIT 1').fetchone()
    if last and bool(last['event_mac'])!=bool(key):raise ValueError('Event signing configuration changed. Use the trusted migration procedure.')
    record={'id':last['id']+1 if last else 1,'occurred_at':datetime.now(timezone.utc).isoformat(),
            'event':event,'actor':actor,'target':target,'previous_hash':last['event_hash'] if last else ZERO}
    record['event_hash']=event_hash(record)
    record['event_mac']=event_mac(key,record,last['event_mac'] if last else ZERO) if key else ''
    db.execute('INSERT INTO security_events VALUES(?,?,?,?,?,?,?,?)',tuple(record[field] for field in
        ('id','occurred_at','event','actor','target','previous_hash','event_hash','event_mac')))


def verify(db, checkpoint=None):
    return _verify(db,checkpoint,signing_key())


def _verify(db,checkpoint,key):
    expected_id=1;head=ZERO;anchor_seen=checkpoint is None
    previous_mac=ZERO
    if checkpoint is not None:
        if not isinstance(checkpoint,dict) or set(checkpoint)!={'count','head'} or type(checkpoint['count']) is not int or checkpoint['count']<0 or not isinstance(checkpoint['head'],str) or not re.fullmatch('[a-f0-9]{64}',checkpoint['head']):
            raise ValueError('Invalid checkpoint.')
        if checkpoint=={'count':0,'head':ZERO}:anchor_seen=True
    for row in db.execute('SELECT * FROM security_events ORDER BY id'):
        record=dict(row)
        mac=record.get('event_mac','')
        valid_shape=all(isinstance(record[key],str) for key in ('occurred_at','event','previous_hash','event_hash'))
        valid_metadata=all(isinstance(record[key],str) and (not record[key] or re.fullmatch(r'[a-z][a-z0-9_.-]{2,49}',record[key])) for key in ('actor','target'))
        if not valid_shape or not valid_metadata or record['id']!=expected_id or record['previous_hash']!=head or record['event_hash']!=event_hash(record) or record['event'] not in CODES:
            return {'valid':False,'count':expected_id-1,'head':head,'checkpoint_matched':False}
        if (key and (not isinstance(mac,str) or not re.fullmatch('[a-f0-9]{64}',mac) or not hmac.compare_digest(mac,event_mac(key,record,previous_mac)))) or (not key and mac):
            return {'valid':False,'count':expected_id-1,'head':head,'checkpoint_matched':False}
        head=record['event_hash']
        previous_mac=mac
        if checkpoint and record['id']==checkpoint['count'] and head==checkpoint['head']:anchor_seen=True
        expected_id+=1
    return {'valid':anchor_seen,'count':expected_id-1,'head':head,'checkpoint_matched':anchor_seen}


def seal_existing(db):
    """Explicit trusted baseline migration; does not prove legacy authenticity."""
    key=signing_key()
    if not key:raise ValueError('Configure an external event key before sealing history.')
    if not db.in_transaction:db.execute('BEGIN IMMEDIATE')
    if db.execute("SELECT 1 FROM security_events WHERE event_mac<>'' LIMIT 1").fetchone():raise ValueError('History is already signed. Key rotation requires a separate reviewed migration.')
    if not _verify(db,None,None)['valid']:raise ValueError('Legacy history is inconsistent. Preserve it for investigation.')
    previous=ZERO
    for row in db.execute('SELECT * FROM security_events ORDER BY id').fetchall():
        previous=event_mac(key,dict(row),previous)
        db.execute('UPDATE security_events SET event_mac=? WHERE id=?',(previous,row['id']))
    append(db,'event_history_sealed',actor='local-maintenance')


def audit_cli(event,target=''):
    """Do not create a workspace or append to a history that fails verification."""
    import app
    if not app.DB.is_file():return
    with app.connect() as db:
        if not verify(db)['valid']:raise ValueError('Cannot record CLI action in unverifiable history.')
        append(db,event,actor='local-maintenance',target=target)
