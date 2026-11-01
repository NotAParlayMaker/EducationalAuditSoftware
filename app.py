"""Local school administration and IT workspace. Python 3.12+; security extras are pinned separately."""
import json
import os
import sqlite3
import security
import accounts
import security_events as events
import operations
import runtime
import data_pipeline
import mfa
import deployment
import evidence_scan
import time
from urllib.parse import urlsplit, parse_qs
import hashlib
import socket
import audit_workflow as audits
from assistant import AssistantError, suggest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer as BaseHTTPServer
import threading
import secrets
from pathlib import Path

class ThreadingHTTPServer(BaseHTTPServer):
    """Bound local worker growth; not a public-facing DDoS defense."""
    daemon_threads=True
    block_on_close=False
    worker_limit=16

    def __init__(self,*args,**kwargs):
        self.worker_slots=threading.BoundedSemaphore(self.worker_limit)
        self.demo_token=os.environ.get('SCHOOL_ACCESS_TOKEN') or secrets.token_urlsafe(32)
        super().__init__(*args,**kwargs)

    def process_request(self,request,client_address):
        if not self.worker_slots.acquire(blocking=False):
            body=b'{"error":"Server busy. Retry later."}'
            response=(b'HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\nConnection: close\r\nCache-Control: no-store\r\nRetry-After: 1\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
            try:
                request.settimeout(0.1)
                request.sendall(response)
            except OSError:pass
            self.shutdown_request(request)
            return
        try:super().process_request(request,client_address)
        except Exception:
            self.worker_slots.release()
            raise

    def process_request_thread(self,request,client_address):
        try:super().process_request_thread(request,client_address)
        finally:self.worker_slots.release()


ROOT = Path(__file__).parent
DB = Path(os.environ.get('SCHOOL_DB', ROOT / 'data' / 'school.db'))
SCHEMAS = {
    'students': ['name', 'year', 'guardian'],
    'attendance': ['student', 'date', 'status'],
    'grades': ['student', 'subject', 'grade'],
    'assets': ['tag', 'device', 'location', 'status'],
    'audits': audits.FIELDS,
    'tickets': ['title', 'requester', 'priority', 'status'],
}
CHOICES = {
    ('attendance', 'status'): ['Present', 'Absent', 'Late'],
    ('assets', 'status'): ['Available', 'In use', 'Repair'],
    ('audits', 'status'): audits.STATUSES,
    ('tickets', 'status'): ['Open', 'In progress', 'Resolved'],
    ('tickets', 'priority'): ['Low', 'Medium', 'High'],
}


def connect():
    DB.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(DB)
    if os.name == 'posix':
        DB.chmod(0o640 if deployment.cloud() else 0o600)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    deployment.validate()
    token = os.environ.get('SCHOOL_ACCESS_TOKEN')
    if token is not None and (not 32 <= len(token) <= 256 or any(not 33 <= ord(char) <= 126 for char in token)):
        raise ValueError('SCHOOL_ACCESS_TOKEN must contain 32–256 printable ASCII characters without spaces.')
    with connect() as db:
        for name, fields in SCHEMAS.items():
            columns = ', '.join(f'"{field}" TEXT NOT NULL' for field in fields)
            db.execute(f'CREATE TABLE IF NOT EXISTS {name} (id INTEGER PRIMARY KEY, {columns})')
        audits.migrate(db)
        accounts.initialize(db)
        if (events.signing_key() or db.execute("SELECT 1 FROM security_events WHERE event_mac<>'' LIMIT 1").fetchone()) and not events.verify(db)['valid']:
            raise ValueError('Signed event history cannot be verified. Restore the correct external key, or explicitly seal a reviewed legacy baseline with manage.py seal-events.')
        operations.initialize(db)
        runtime.initialize(db)
        data_pipeline.initialize(db)
        policy='all' if deployment.cloud() else ('privileged' if os.environ.get('SCHOOL_REQUIRE_MFA')=='1' else '')
        prior=db.execute("SELECT value FROM account_settings WHERE key='mfa_required'").fetchone()
        if policy and (not prior or (prior[0]!='all' and policy=='all')):
            db.execute("INSERT OR REPLACE INTO account_settings VALUES('mfa_required',?)",(policy,));events.append(db,'mfa_policy_enabled',actor='local-maintenance')


def validate(resource, data):
    if not isinstance(data, dict) or set(data) != set(SCHEMAS[resource]):
        raise ValueError('Supply all fields, with no extra fields.')
    clean = {}
    for field in SCHEMAS[resource]:
        value = data[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 500:
            raise ValueError(f'{field}: enter between 1 and 500 characters.')
        value = value.strip()
        if (resource, field) in CHOICES and value not in CHOICES[resource, field]:
            raise ValueError(f'{field}: choose a valid option.')
        if resource == 'attendance' and field == 'date':
            from datetime import date
            try:
                date.fromisoformat(value)
            except ValueError:
                raise ValueError('date: use a valid ISO date.') from None
        clean[field] = value
    return clean


class Handler(SimpleHTTPRequestHandler):
    server_version = 'Schooldesk'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format, *args):
        # Never record attacker-controlled paths, queries, credentials, or payloads.
        pass

    def end_headers(self):
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def guard(self, write=False):
        try:
            security.check_request(self, write, authenticate=False)
            with connect() as db:
                self.user = accounts.principal(db, self.headers.get('Authorization', ''))
                account_mode = accounts.enabled(db)
            if self.user and self.user.get('_mfa_setup_required') and self.path not in ('/api/auth/mfa/status','/api/auth/mfa/begin','/api/auth/mfa/confirm','/api/auth/logout','/api/auth/reauthenticate'):
                raise security.RequestError(403,'MFA enrollment is required before accessing workspace data.')
            if not account_mode:
                if deployment.cloud() or not getattr(self.server,'allow_demo',False):
                    raise security.RequestError(503,'Account setup required. Run schooldesk.py init or explicitly enable demo mode.')
                security.check_request(self, write)
                import hmac
                supplied=self.headers.get('Authorization','')
                if not hmac.compare_digest(supplied.encode(),('Bearer '+self.server.demo_token).encode()):
                    raise security.RequestError(401,'Unlock demo mode with its startup token.')
            return True
        except security.RequestError as error:
            self.close_connection = True
            self.reply(error.status, {'error': str(error)})
            return False

    def do_HEAD(self):
        # Do not inherit unrestricted directory/file handling.
        self.reply(405, {'error': 'Method not allowed'})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'static'), **kwargs)

    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def resource(self):
        parts = self.path.split('?')[0].strip('/').split('/')
        if len(parts) != 2 or parts[0] != 'api' or parts[1] not in SCHEMAS:
            return None
        return parts[1]

    def valid_host(self):
        return self.headers.get('Host') in (
            f'127.0.0.1:{self.server.server_port}',
            f'localhost:{self.server.server_port}')

    def do_GET(self):
        if self.path=='/health':
            security.check_request(self,authenticate=False)
            with connect() as db:db.execute('SELECT 1').fetchone()
            return self.reply(200,{'service':'schooldesk','status':'ok'})
        if not self.path.startswith('/api/'):
            try:
                # Static UI can load before workspace unlock, but host/origin checks still apply.
                security.check_request(self,authenticate=False)
                if self.path not in ('/', '/index.html', '/app.js', '/style.css'):
                    return self.reply(404, {'error': 'Unknown resource'})
                return super().do_GET()
            except OSError:
                return self.reply(404, {'error': 'Resource unavailable'})
        if self.path == '/api/auth/status':
            security.check_request(self, authenticate=False)
            with connect() as db:
                return self.reply(200, {'accounts_enabled': accounts.enabled(db),'demo_enabled':not deployment.cloud() and not accounts.enabled(db) and bool(getattr(self.server,'allow_demo',False))})
        if not self.guard():
            return
        if self.path.split('?')[0]=='/api/pipeline/batches':
            if not self.user:raise security.RequestError(403,'Individual account sign-in is required.')
            query=parse_qs(urlsplit(self.path).query,max_num_fields=4);limit,offset=operations.page_query(query)
            with connect() as db:
                rows=[dict(row) for row in db.execute("SELECT id,resource,CASE WHEN status='prepared' AND expires_at<unixepoch() THEN 'expired' ELSE status END AS status,row_count,inserted,skipped,created_at,expires_at FROM pipeline_batches WHERE actor=? ORDER BY created_at DESC LIMIT ? OFFSET ?",(self.user['username'],limit,offset))]
            return self.reply(200,rows)
        if self.path=='/api/auth/mfa/status':
            if not self.user:raise security.RequestError(403,'Individual account required.')
            with connect() as db:
                return self.reply(200,{'enabled':mfa.active(db,self.user['username']),'required':mfa.required(self.user,db)})
        if self.path=='/api/work-queue':
            with connect() as db:return self.reply(200,runtime.work_queue(db,self.user))
        if self.path=='/api/operations/status':
            if not self.user or self.user['role']!='administrator':
                raise security.RequestError(403,'Administrator access is required.')
            with connect() as db:return self.reply(200,runtime.status(db))
        if self.path == '/api/auth/sessions':
            with connect() as db:
                return self.reply(200,accounts.session_list(db,self.user,self.headers.get('Authorization','')))
        if self.path.split('?')[0] in ('/api/security/events','/api/security/verify'):
            if not self.user or self.user['role']!='administrator':
                raise security.RequestError(403,'Only administrators can review security events.')
            with connect() as db:
                if self.path.split('?')[0]=='/api/security/verify':
                    return self.reply(200,events.verify(db))
                query=parse_qs(urlsplit(self.path).query,max_num_fields=4)
                limit,offset=operations.page_query(query)
                rows=[dict(row) for row in db.execute('SELECT * FROM security_events ORDER BY id DESC LIMIT ? OFFSET ?',(limit,offset))]
            return self.reply(200,rows)
        if self.path == '/api/auth/me':
            return self.reply(200, {'user': {key:self.user[key] for key in ('username','role')} if self.user else None})
        if self.path == '/api/summary':
            with connect() as db:
                keys = [key for key in SCHEMAS if accounts.can_read_resource(self.user,key)]
                scope,scope_params=accounts.audit_scope(self.user)
                counts = {key:db.execute(f'SELECT count(*) FROM {key}'+(' WHERE '+scope if key=='audits' else ''),scope_params if key=='audits' else []).fetchone()[0] for key in keys}
                if 'audits' in keys:
                    counts['audit_severity'] = {row[0]:row[1] for row in db.execute("SELECT severity,count(*) FROM audits WHERE ("+scope+") AND status<>'Closed' GROUP BY severity",scope_params)}
                    counts['overdue_audits'] = db.execute("SELECT count(*) FROM audits WHERE ("+scope+") AND due_date<>'' AND due_date<date('now') AND status<>'Closed'",scope_params).fetchone()[0]
            return self.reply(200, counts)
        if self.path == '/api/users':
            if self.user is None:
                return self.reply(403, {'error': 'Accounts required.'})
            with connect() as db:
                if self.user['role'] in ('administrator','auditor'):
                    rows=[dict(row) for row in db.execute('SELECT username,role FROM users WHERE active=1 ORDER BY username')]
                else:
                    scope,params=accounts.audit_scope(self.user)
                    rows=[dict(row) for row in db.execute('SELECT username,role FROM users WHERE active=1 AND (username=? OR username IN (SELECT owner FROM audits WHERE '+scope+') OR username IN (SELECT reviewer FROM audits WHERE '+scope+')) ORDER BY username',[self.user['username']]+params+params)]
            return self.reply(200, rows)
        accounts.authorize_resource(self.user, self.resource())
        parts = self.path.split('?')[0].strip('/').split('/')
        query = parse_qs(urlsplit(self.path).query, max_num_fields=12)
        limit, offset = operations.page_query(query)
        if len(parts)==3 and parts[:2]==['api','evidence'] and parts[2].isascii() and parts[2].isdigit() and len(parts[2])<=18:
            with connect() as db:
                scope,params=accounts.audit_scope(self.user,'a.')
                row=db.execute('SELECT e.* FROM audit_evidence e JOIN audits a ON a.id=e.audit_id WHERE e.id=? AND ('+scope+')',[int(parts[2])]+params).fetchone()
            if not row:
                return self.reply(404,{'error':'Evidence not found.'})
            if not evidence_scan.released(row['scan_status'],row['media_type']):return self.reply(423,{'error':'Evidence is quarantined or requires a clean scan.'})
            if hashlib.sha256(row['content']).hexdigest()!=row['sha256']:
                return self.reply(409,{'error':'Evidence integrity check failed.'})
            self.send_response(200)
            self.send_header('Content-Type','application/octet-stream')
            self.send_header('Content-Disposition','attachment; filename="evidence-'+str(row['id'])+('.pdf' if row['media_type']=='application/pdf' else '.txt')+'"')
            self.send_header('Content-Length',str(row['size']))
            self.end_headers();self.wfile.write(row['content']);return
        if len(parts)==4 and parts[:2]==['api','audits'] and parts[2].isascii() and parts[2].isdigit() and len(parts[2])<=18 and parts[3]=='evidence':
            with connect() as db:
                accounts.require_audit_access(db,self.user,int(parts[2]))
                rows=[dict(row) for row in db.execute('SELECT id,audit_id,filename,media_type,sha256,size,actor,created_at,scan_status FROM audit_evidence WHERE audit_id=? ORDER BY id DESC LIMIT ? OFFSET ?', (int(parts[2]),limit,offset))]
            for row in rows:row['released']=evidence_scan.released(row['scan_status'],row['media_type'])
            return self.reply(200,rows)
        if len(parts) == 4 and parts[:2] == ['api', 'audits'] and parts[2].isascii() and parts[2].isdigit() and len(parts[2]) <= 18 and parts[3] == 'history':
            with connect() as db:
                accounts.require_audit_access(db,self.user,int(parts[2]))
                rows = [dict(row) for row in db.execute('SELECT * FROM audit_history WHERE audit_id=? ORDER BY revision LIMIT ? OFFSET ?', (int(parts[2]),limit,offset))]
            for row in rows:
                row['snapshot'] = json.loads(row['snapshot'])
            return self.reply(200, rows)
        resource = self.resource()
        if not resource:
            return self.reply(404, {'error': 'Unknown resource'})
        where, params = operations.audit_filters(query) if resource=='audits' else ('',[])
        if resource=='audits':
            scope,scope_params=accounts.audit_scope(self.user)
            where=(where+' AND ('+scope+')') if where else ' WHERE '+scope
            params+=scope_params
        with connect() as db:
            rows = [dict(row) for row in db.execute(f'SELECT * FROM {resource}{where} ORDER BY id DESC LIMIT ? OFFSET ?', params+[limit,offset])]
        self.reply(200, rows)

    def do_POST(self):
        if self.path == '/api/auth/login':
            security.check_request(self, write=True, authenticate=False)
            data = security.read_json(self)
            with connect() as db:
                result = accounts.login(db, data)
            return self.reply(200, result)
        if not self.guard(write=True):
            return
        if self.path in ('/api/auth/reauthenticate','/api/auth/mfa/begin','/api/auth/mfa/confirm'):
            data=security.read_json(self)
            with connect() as db:
                if self.path=='/api/auth/reauthenticate':
                    accounts.reauthenticate(db,self.user,self.headers.get('Authorization',''),data);result={'verified':True}
                elif self.path=='/api/auth/mfa/begin':
                    if set(data)!={'password'}:raise security.RequestError(400,'Supply the current password.')
                    accounts.reauthenticate(db,self.user,self.headers.get('Authorization',''),data)
                    self.user['_auth_time']=time.time();result=mfa.begin(db,self.user)
                else:
                    if set(data)!={'code'}:raise security.RequestError(400,'Supply the enrollment code.')
                    result=mfa.confirm(db,self.user,data['code'])
            return self.reply(200,result)
        if self.path in ('/api/pipeline/preview','/api/pipeline/commit','/api/pipeline/export'):
            if self.path in ('/api/pipeline/commit','/api/pipeline/export'):mfa.require_recent(self.user)
            data=security.read_json(self,maximum=512000)
            with connect() as db:
                if self.path=='/api/pipeline/preview':
                    result=data_pipeline.preview(db,self.user,data,validate,SCHEMAS)
                elif self.path=='/api/pipeline/commit':
                    result=data_pipeline.commit(db,self.user,data,validate,SCHEMAS)
                else:
                    if set(data)!={'resource','format','after_id','limit'} or data['format'] not in ('json','csv'):
                        raise security.RequestError(400,'Supply resource, format, cursor, and limit.')
                    result=data_pipeline.export_page(db,self.user,data['resource'],SCHEMAS,data['after_id'],data['limit'])
                    if data['format']=='csv':result['csv']=data_pipeline.csv_export(result,SCHEMAS[data['resource']])
            return self.reply(200,result)
        if self.path in ('/api/auth/revoke-session','/api/auth/revoke-all','/api/auth/change-password'):
            data=security.read_json(self)
            with connect() as db:
                if self.path=='/api/auth/revoke-session':
                    if set(data)!={'session_id'}:raise security.RequestError(400,'Supply a session identifier.')
                    accounts.revoke_sessions(db,self.user,data['session_id'])
                elif self.path=='/api/auth/revoke-all':
                    if data:raise security.RequestError(400,'Unexpected fields.')
                    accounts.revoke_sessions(db,self.user)
                else:
                    mfa.require_recent(self.user)
                    accounts.change_password(db,self.user,data)
            return self.reply(200,{'completed':True})
        parts = self.path.strip('/').split('/')
        if len(parts)==4 and parts[:2]==['api','evidence'] and parts[2].isascii() and parts[2].isdigit() and len(parts[2])<=18 and parts[3] in ('rescan','reject'):
            if not self.user or self.user['role'] not in ('administrator','auditor'):raise security.RequestError(403,'Oversight role required.')
            mfa.require_recent(self.user)
            action_data=security.read_json(self)
            if parts[3]=='rescan' and action_data:raise security.RequestError(400,'Unexpected fields.')
            if parts[3]=='reject' and (set(action_data)!={'reason'} or not isinstance(action_data['reason'],str) or not 1<=len(action_data['reason'].strip())<=500):raise security.RequestError(400,'Supply a rejection reason of 1–500 characters.')
            with connect() as db:
                row=db.execute('SELECT * FROM audit_evidence WHERE id=?',(int(parts[2]),)).fetchone()
                if not row:raise security.RequestError(404,'Evidence not found.')
                parent=accounts.require_audit_access(db,self.user,row['audit_id'])
                if row['scan_status']=='rejected':raise security.RequestError(409,'Rejected evidence is retained and cannot be released.')
                if parts[3]=='reject' and parent['status']=='Closed':raise security.RequestError(409,'Reopen the finding before rejecting evidence.')
            if parts[3]=='rescan' and not evidence_scan.required():raise security.RequestError(409,'Configure an active scanner before rescanning.')
            intact=isinstance(row['content'],bytes) and hashlib.sha256(row['content']).hexdigest()==row['sha256'] and len(row['content'])==row['size']
            status='rejected' if parts[3]=='reject' else (evidence_scan.scan(row['content']) if intact else 'integrity_failed')
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                current=db.execute('SELECT * FROM audit_evidence WHERE id=?',(row['id'],)).fetchone()
                if not current or current['content']!=row['content'] or current['sha256']!=row['sha256'] or current['scan_status']!=row['scan_status']:raise security.RequestError(409,'Evidence changed during scanning. Retry after review.')
                parent=accounts.require_audit_access(db,self.user,current['audit_id'])
                if parts[3]=='reject' and parent['status']=='Closed':raise security.RequestError(409,'Reopen the finding before rejecting evidence.')
                db.execute('UPDATE audit_evidence SET scan_status=? WHERE id=?',(status,row['id']))
                audit=dict(parent);audit['revision']+=1
                if audit['status']=='Closed' and not evidence_scan.released(status,row['media_type']):
                    audit.update(status='Open',reopen_reason='Evidence quarantined after rescan.',verification='',closure_reason='')
                    db.execute("UPDATE audits SET status='Open',reopen_reason=?,verification='',closure_reason='' WHERE id=?",(audit['reopen_reason'],audit['id']))
                db.execute('UPDATE audits SET revision=? WHERE id=?',(audit['revision'],audit['id']))
                audits.record_event(db,dict(audit,attachment_rescanned=row['id'],scan_status=status,rejection_reason=action_data.get('reason','')),self.user['username'])
                events.append(db,'evidence_scanned' if status=='clean' else 'evidence_quarantined',actor=self.user['username'])
            return self.reply(200,{'scan_status':status,'released':evidence_scan.released(status,row['media_type'])})
        if len(parts)==4 and parts[:2]==['api','audits'] and parts[2].isascii() and parts[2].isdigit() and len(parts[2])<=18 and parts[3]=='evidence':
            data=security.read_json(self,maximum=360000)
            with connect() as db:operations.authorize_upload(db,self.user,int(parts[2]))
            _,content,_,_=operations.validate_upload(data)
            scan_result=evidence_scan.scan(content)
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                try:
                    result=operations.add_evidence(db,self.user,int(parts[2]),data,scan_result=scan_result)
                except LookupError:
                    return self.reply(404,{'error':'Audit not found.'})
            return self.reply(201,result)
        if self.path == '/api/auth/logout':
            with connect() as db:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (accounts.digest(self.headers.get('Authorization', '').removeprefix('Bearer ')),))
                if self.user:events.append(db,'session_revoked',actor=self.user['username'])
            return self.reply(200, {'logged_out': True})
        is_assistant = self.path == '/api/assistant/draft'
        resource = self.resource()
        accounts.authorize_resource(self.user, resource, write=True)
        if not resource and not is_assistant:
            return self.reply(404, {'error': 'Unknown resource'})
        try:
            payload = security.read_json(self)
            data = payload if is_assistant or resource == 'audits' else validate(resource, payload)
        except security.RequestError as error:
            self.close_connection = True
            return self.reply(error.status, {'error': str(error)})
        except (ValueError, UnicodeError) as error:
            return self.reply(400, {'error': str(error)})
        if is_assistant:
            try:
                limited = os.environ.get('SCHOOL_AI_MODE')=='openai' and data.get('allow_external') is True
                if limited:
                    if not operations.AI_SLOTS.acquire(blocking=False):
                        raise security.RequestError(429,'AI is busy. Try again shortly.')
                    try:
                        with connect() as db:
                            operations.reserve_ai(db,self.user['username'] if self.user else 'demo')
                        result=suggest(data)
                    finally:
                        operations.AI_SLOTS.release()
                else:
                    result=suggest(data)
                return self.reply(200,result)
            except AssistantError as error:
                return self.reply(400, {'error': str(error)})
        if resource == 'audits':
            try:
                with connect() as db:
                    db.execute('BEGIN IMMEDIATE')
                    data = accounts.authorize_audit(db, self.user, data)
                    record = audits.save(db, data)
                return self.reply(201, record)
            except security.RequestError:
                raise
            except ValueError as error:
                return self.reply(400, {'error': str(error)})
        fields = SCHEMAS[resource]
        columns = ', '.join(f'"{field}"' for field in fields)
        placeholders = ', '.join('?' for _ in fields)
        with connect() as db:
            cursor = db.execute(f'INSERT INTO {resource} ({columns}) VALUES ({placeholders})', [data[f] for f in fields])
            data['id'] = cursor.lastrowid
        self.reply(201, data)

    def do_PUT(self):
        if not self.guard(write=True):
            return
        parts = self.path.strip('/').split('/')
        if len(parts) != 3 or parts[:2] != ['api', 'audits'] or not parts[2].isascii() or not parts[2].isdigit() or len(parts[2]) > 18:
            return self.reply(404, {'error': 'Unknown resource'})
        try:
            data = security.read_json(self)
            with connect() as db:
                db.execute('BEGIN IMMEDIATE')
                data = accounts.authorize_audit(db, self.user, data, int(parts[2]))
                previous=db.execute('SELECT status FROM audits WHERE id=?',(int(parts[2]),)).fetchone()
                next_status=data.get('status',previous['status'])
                if next_status=='Closed':mfa.require_recent(self.user)
                if next_status in ('Awaiting verification','Closed'):operations.verify_attachments(db,int(parts[2]))
                record = audits.save(db, data, int(parts[2]))
            return self.reply(200, record)
        except audits.Conflict as error:
            return self.reply(409, {'error': str(error)})
        except LookupError:
            return self.reply(404, {'error': 'Audit not found'})
        except security.RequestError as error:
            self.close_connection = True
            return self.reply(error.status, {'error': str(error)})
        except (ValueError, UnicodeError) as error:
            return self.reply(400, {'error': str(error)})


def safe_route(method):
    def wrapped(self):
        try:
            return method(self)
        except security.RequestError as error:
            self.close_connection = True
            self.reply(error.status, {'error': str(error)})
        except ValueError:
            self.close_connection = True
            self.reply(400, {'error':'Invalid request.'})
        except sqlite3.Error:
            self.close_connection = True
            self.reply(503, {'error': 'Storage temporarily unavailable.'})
        except (socket.timeout, TimeoutError):
            self.close_connection = True
            self.reply(408, {'error': 'Request timed out.'})
    return wrapped


for route in ('do_GET', 'do_POST', 'do_PUT'):
    setattr(Handler, route, safe_route(getattr(Handler, route)))


if __name__ == '__main__':
    import sys
    import schooldesk
    schooldesk.main(['serve',*sys.argv[1:]])
