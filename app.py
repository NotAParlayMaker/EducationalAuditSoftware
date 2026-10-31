"""Local school administration and IT workspace. Python 3.12+, no dependencies."""
import json
import os
import sqlite3
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
    DB.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def initialize():
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
            date.fromisoformat(value)
        clean[field] = value
    return clean


class Handler(SimpleHTTPRequestHandler):
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
        if not self.valid_host():
            return self.reply(403, {'error': 'Untrusted host'})
        if not self.path.startswith('/api/'):
            return super().do_GET()
        parts = self.path.split('?')[0].strip('/').split('/')
        if len(parts) == 4 and parts[:2] == ['api', 'audits'] and parts[2].isdigit() and parts[3] == 'history':
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
        if not self.valid_host():
            return self.reply(403, {'error': 'Untrusted host'})
        is_assistant = self.path == '/api/assistant/draft'
        resource = self.resource()
        if not resource and not is_assistant:
            return self.reply(404, {'error': 'Unknown resource'})
        # Local app: reject browser requests from other origins.
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers.get('Host', ''):
            return self.reply(403, {'error': 'Cross-origin request rejected'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 8192:
                raise ValueError('Invalid request size')
            payload = json.loads(self.rfile.read(size))
            data = payload if is_assistant or resource == 'audits' else validate(resource, payload)
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
        if not self.valid_host():
            return self.reply(403, {'error': 'Untrusted host'})
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers.get('Host', ''):
            return self.reply(403, {'error': 'Cross-origin request rejected'})
        parts = self.path.strip('/').split('/')
        if len(parts) != 3 or parts[:2] != ['api', 'audits'] or not parts[2].isdigit():
            return self.reply(404, {'error': 'Unknown resource'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 8192:
                raise ValueError('Invalid request size')
            data = json.loads(self.rfile.read(size))
            with connect() as db:
                record = audits.save(db, data, int(parts[2]))
            return self.reply(200, record)
        except audits.Conflict as error:
            return self.reply(409, {'error': str(error)})
        except LookupError:
            return self.reply(404, {'error': 'Audit not found'})
        except (ValueError, UnicodeError) as error:
            return self.reply(400, {'error': str(error)})


if __name__ == '__main__':
    initialize()
    port = int(os.environ.get('PORT', '8000'))
    print(f'School workspace listening on 127.0.0.1:{port}', flush=True)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()

