"""Bounded AI requests, controlled evidence, and list queries."""
import base64
import hashlib
import os
import re
import threading
import time

from security import RequestError
import accounts
import audit_workflow
import evidence_scan
import security_events as events

AI_SLOTS = threading.BoundedSemaphore(2)
MAX_EVIDENCE = 256 * 1024


def initialize(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS request_budgets (
            scope TEXT NOT NULL, period TEXT NOT NULL, start INTEGER NOT NULL, count INTEGER NOT NULL,
            PRIMARY KEY(scope,period));
        CREATE TABLE IF NOT EXISTS audit_evidence (
            id INTEGER PRIMARY KEY, audit_id INTEGER NOT NULL, filename TEXT NOT NULL,
            media_type TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
            actor TEXT NOT NULL, created_at REAL NOT NULL, content BLOB NOT NULL);
    ''')
    columns={row[1] for row in db.execute('PRAGMA table_info(audit_evidence)')}
    if 'scan_status' not in columns:db.execute("ALTER TABLE audit_evidence ADD COLUMN scan_status TEXT NOT NULL DEFAULT 'legacy_unscanned'")


def reserve_ai(db, username, now=None):
    now = time.time() if now is None else now
    db.execute('BEGIN IMMEDIATE')
    updates = []
    # Global caps complement per-user limits; count attempts, including provider failures.
    for scope in ('global', 'user:' + username):
        for period, seconds, maximum in [('minute',60,10), ('day',86400,100)]:
            start = int(now) // seconds * seconds
            row = db.execute('SELECT start,count FROM request_budgets WHERE scope=? AND period=?', (scope,period)).fetchone()
            count = row['count'] if row and row['start'] == start else 0
            if count >= maximum:
                raise RequestError(429, 'AI request budget exhausted. Wait for the next budget window.')
            updates.append((scope,period,start,count+1))
    db.executemany('INSERT OR REPLACE INTO request_budgets VALUES(?,?,?,?)',updates)


def authorize_upload(db,user,audit_id):
    if not user:
        raise RequestError(403,'Individual account sign-in is required for evidence uploads.')
    row=accounts.require_audit_access(db,user,audit_id)
    if row['status']=='Closed':
        raise RequestError(409,'Reopen the finding before adding evidence.')
    if user['role'] not in ('administrator','auditor') and not (user['role']=='remediation_owner' and row['owner']==user['username']):
        raise RequestError(403,'Only an assigned owner or auditor can upload evidence.')
    return row


def validate_upload(data):
    if not isinstance(data,dict) or set(data)!={'filename','content_base64'}:
        raise RequestError(400,'Supply a filename and base64 content.')
    filename=data['filename']
    if not isinstance(filename,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,99}',filename):
        raise RequestError(400,'Use a simple filename of at most 100 characters.')
    value=data['content_base64']
    if not isinstance(value,str) or len(value)>350000:
        raise RequestError(413,'Evidence exceeds 256 KiB.')
    try:
        content=base64.b64decode(value,validate=True)
    except (ValueError,UnicodeError):
        raise RequestError(400,'Invalid evidence encoding.') from None
    if not 0<len(content)<=MAX_EVIDENCE:
        raise RequestError(413,'Evidence must contain 1–256 KiB.')
    if filename.lower().endswith('.txt'):
        try:
            text=content.decode('utf-8')
            if any(ord(char)<32 and char not in '\n\r\t' for char in text):
                raise ValueError()
        except (UnicodeError,ValueError):
            raise RequestError(400,'Text evidence must be UTF-8 without binary control characters.') from None
        media_type='text/plain'
    elif filename.lower().endswith('.pdf') and content.startswith(b'%PDF-'):
        if os.environ.get('SCHOOL_ALLOW_PDF_EVIDENCE')!='1' or not evidence_scan.required():
            raise RequestError(400,'PDF evidence is disabled. Use UTF-8 text; PDF opt-in requires malware scanning.')
        media_type='application/pdf'
    else:
        raise RequestError(400,'Use UTF-8 .txt evidence. PDF evidence requires explicit opt-in and malware scanning.')
    checksum=hashlib.sha256(content).hexdigest()
    return filename,content,media_type,checksum


def add_evidence(db,user,audit_id,data,scan_result=None):
    row=authorize_upload(db,user,audit_id)
    filename,content,media_type,checksum=validate_upload(data)
    # Keep per-record storage bounded as well as individual file size.
    if db.execute('SELECT count(*) FROM audit_evidence WHERE audit_id=?',(audit_id,)).fetchone()[0]>=20:
        raise RequestError(413,'This finding already has the maximum 20 attachments.')
    scan_status=evidence_scan.scan(content) if scan_result is None else scan_result
    if scan_status not in ('clean','infected','unavailable','unscanned'):raise RequestError(503,'Scanner returned an unsupported result.')
    cursor=db.execute('INSERT INTO audit_evidence(audit_id,filename,media_type,sha256,size,actor,created_at,content,scan_status) VALUES(?,?,?,?,?,?,?,?,?)',
        (audit_id,filename,media_type,checksum,len(content),user['username'],time.time(),content,scan_status))
    if scan_status!='unscanned':events.append(db,'evidence_scanned' if scan_status=='clean' else 'evidence_quarantined',actor=user['username'])
    revision=row['revision']+1
    db.execute('UPDATE audits SET revision=? WHERE id=?',(revision,audit_id))
    snapshot=dict(row)
    snapshot.update(revision=revision,attachment_added=cursor.lastrowid,attachment_sha256=checksum)
    audit_workflow.record_event(db,snapshot,user['username'])
    return {'id':cursor.lastrowid,'filename':filename,'sha256':checksum,'size':len(content),'audit_revision':revision,'scan_status':scan_status,'released':evidence_scan.released(scan_status,media_type)}


def page_query(query):
    try:
        limit=int(query.get('limit',['50'])[0]);offset=int(query.get('offset',['0'])[0])
    except ValueError:
        raise RequestError(400,'Invalid pagination.') from None
    if not 1<=limit<=100 or not 0<=offset<=1_000_000:
        raise RequestError(400,'Use a limit of 1–100 and a bounded nonnegative offset.')
    return limit,offset


def audit_filters(query):
    clauses=[];params=[]
    for field in ('owner','severity','status'):
        value=query.get(field,[''])[0]
        if len(value)>100:
            raise RequestError(400,'Filter value too long.')
        if value:
            clauses.append(field+'=?');params.append(value)
    if query.get('overdue',[''])[0]=='1':
        clauses.append("due_date<>'' AND due_date<date('now') AND status<>'Closed'")
    return (' WHERE '+' AND '.join(clauses) if clauses else ''),params


def verify_attachments(db,audit_id):
    for row in db.execute("SELECT content,sha256,size,scan_status,media_type FROM audit_evidence WHERE audit_id=? AND scan_status<>'rejected'",(audit_id,)):
        if not evidence_scan.released(row['scan_status'],row['media_type']) or not isinstance(row['content'],bytes) or hashlib.sha256(row['content']).hexdigest()!=row['sha256'] or len(row['content'])!=row['size']:
            raise RequestError(423,'All active evidence must pass integrity and scanning checks before verification or closure.')
