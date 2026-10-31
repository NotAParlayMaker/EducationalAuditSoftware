"""Allowlisted security metadata with a verifiable hash chain, never payloads."""
import hashlib
import json
import re
from datetime import datetime, timezone

CODES = frozenset({'account_created','account_disabled','password_reset','login_succeeded',
    'login_failed','login_throttled','session_revoked','sessions_revoked','session_evicted',
    'password_changed','password_change_failed','password_change_throttled'})
ZERO = '0' * 64


def initialize(db):
    db.execute('''CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, event TEXT NOT NULL,
        actor TEXT NOT NULL, target TEXT NOT NULL, previous_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL)''')


def event_hash(record):
    values={key:record[key] for key in ('id','occurred_at','event','actor','target','previous_hash')}
    return hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def append(db, event, actor='', target=''):
    if event not in CODES or any(value and not re.fullmatch(r'[a-z][a-z0-9_.-]{2,49}',value) for value in (actor,target)):
        raise ValueError('Invalid security event metadata.')
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    last=db.execute('SELECT id,event_hash FROM security_events ORDER BY id DESC LIMIT 1').fetchone()
    record={'id':last['id']+1 if last else 1,'occurred_at':datetime.now(timezone.utc).isoformat(),
            'event':event,'actor':actor,'target':target,'previous_hash':last['event_hash'] if last else ZERO}
    record['event_hash']=event_hash(record)
    db.execute('INSERT INTO security_events VALUES(?,?,?,?,?,?,?)',tuple(record[key] for key in
        ('id','occurred_at','event','actor','target','previous_hash','event_hash')))


def verify(db, checkpoint=None):
    expected_id=1;head=ZERO;anchor_seen=checkpoint is None
    if checkpoint is not None:
        if not isinstance(checkpoint,dict) or set(checkpoint)!={'count','head'} or type(checkpoint['count']) is not int or checkpoint['count']<0 or not isinstance(checkpoint['head'],str) or not re.fullmatch('[a-f0-9]{64}',checkpoint['head']):
            raise ValueError('Invalid checkpoint.')
        if checkpoint=={'count':0,'head':ZERO}:anchor_seen=True
    for row in db.execute('SELECT * FROM security_events ORDER BY id'):
        record=dict(row)
        valid_shape=all(isinstance(record[key],str) for key in ('occurred_at','event','previous_hash','event_hash'))
        valid_metadata=all(isinstance(record[key],str) and (not record[key] or re.fullmatch(r'[a-z][a-z0-9_.-]{2,49}',record[key])) for key in ('actor','target'))
        if not valid_shape or not valid_metadata or record['id']!=expected_id or record['previous_hash']!=head or record['event_hash']!=event_hash(record) or record['event'] not in CODES:
            return {'valid':False,'count':expected_id-1,'head':head,'checkpoint_matched':False}
        head=record['event_hash']
        if checkpoint and record['id']==checkpoint['count'] and head==checkpoint['head']:anchor_seen=True
        expected_id+=1
    return {'valid':anchor_seen,'count':expected_id-1,'head':head,'checkpoint_matched':anchor_seen}
