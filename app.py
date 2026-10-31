"""Local school administration and IT workspace. Python 3.12+, no dependencies."""
import json
import os
import sqlite3
import security
import socket
import audit_workflow as audits
from assistant import AssistantError, suggest
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

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
        DB.chmod(0o600)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    token = os.environ.get('SCHOOL_ACCESS_TOKEN')
    if token is not None and (not 32 <= len(token) <= 256 or any(not 33 <= ord(char) <= 126 for char in token)):
        raise ValueError('SCHOOL_ACCESS_TOKEN must contain 32–256 printable ASCII characters without spaces.')
    with connect() as db:
        for name, fields in SCHEMAS.items():
            columns = ', '.join(f'"{field}" TEXT NOT NULL' for field in fields)
            db.execute(f'CREATE TABLE IF NOT EXISTS {name} (id INTEGER PRIMARY KEY, {columns})')
        audits.migrate(db)


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
            security.check_request(self, write)
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
        if not self.path.startswith('/api/'):
            try:
                # Static UI can load before workspace unlock, but host/origin checks still apply.
                hosts = self.headers.get_all('Host', [])
                if len(hosts) != 1 or not self.valid_host():
                    return self.reply(403, {'error': 'Untrusted host'})
                if self.path not in ('/', '/index.html', '/app.js', '/style.css'):
                    return self.reply(404, {'error': 'Unknown resource'})
                return super().do_GET()
            except OSError:
                return self.reply(404, {'error': 'Resource unavailable'})
        if not self.guard():
            return
        parts = self.path.split('?')[0].strip('/').split('/')
        if len(parts) == 4 and parts[:2] == ['api', 'audits'] and parts[2].isascii() and parts[2].isdigit() and len(parts[2]) <= 18 and parts[3] == 'history':
            with connect() as db:
                rows = [dict(row) for row in db.execute('SELECT * FROM audit_history WHERE audit_id=? ORDER BY revision', (int(parts[2]),))]
            for row in rows:
                row['snapshot'] = json.loads(row['snapshot'])
            return self.reply(200, rows)
        resource = self.resource()
        if not resource:
            return self.reply(404, {'error': 'Unknown resource'})
        with connect() as db:
            rows = [dict(row) for row in db.execute(f'SELECT * FROM {resource} ORDER BY id DESC')]
        self.reply(200, rows)

    def do_POST(self):
        if not self.guard(write=True):
            return
        is_assistant = self.path == '/api/assistant/draft'
        resource = self.resource()
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
                return self.reply(200, suggest(data))
            except AssistantError as error:
                return self.reply(400, {'error': str(error)})
        if resource == 'audits':
            try:
                with connect() as db:
                    record = audits.save(db, data)
                return self.reply(201, record)
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
    initialize()
    port = int(os.environ.get('PORT', '8000'))
    print(f'School workspace listening on 127.0.0.1:{port}', flush=True)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()

