"""Local school administration and IT workspace. Python 3.12+, no dependencies."""
import json
import os
import sqlite3
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).parent
DB = Path(os.environ.get('SCHOOL_DB', ROOT / 'data' / 'school.db'))
SCHEMAS = {
    'students': ['name', 'year', 'guardian'],
    'attendance': ['student', 'date', 'status'],
    'grades': ['student', 'subject', 'grade'],
    'assets': ['tag', 'device', 'location', 'status'],
    'audits': ['area', 'finding', 'status'],
    'tickets': ['title', 'requester', 'priority', 'status'],
}
CHOICES = {
    ('attendance', 'status'): ['Present', 'Absent', 'Late'],
    ('assets', 'status'): ['Available', 'In use', 'Repair'],
    ('audits', 'status'): ['Open', 'In progress', 'Resolved'],
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

    def do_GET(self):
        if not self.path.startswith('/api/'):
            return super().do_GET()
        resource = self.resource()
        if not resource:
            return self.reply(404, {'error': 'Unknown resource'})
        with connect() as db:
            rows = [dict(row) for row in db.execute(f'SELECT * FROM {resource} ORDER BY id DESC')]
        self.reply(200, rows)

    def do_POST(self):
        resource = self.resource()
        if not resource:
            return self.reply(404, {'error': 'Unknown resource'})
        # Local app: reject browser requests from other origins.
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers.get('Host', ''):
            return self.reply(403, {'error': 'Cross-origin request rejected'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 8192:
                raise ValueError('Invalid request size')
            data = validate(resource, json.loads(self.rfile.read(size)))
        except (ValueError, UnicodeError) as error:
            return self.reply(400, {'error': str(error)})
        fields = SCHEMAS[resource]
        columns = ', '.join(f'"{field}"' for field in fields)
        placeholders = ', '.join('?' for _ in fields)
        with connect() as db:
            cursor = db.execute(f'INSERT INTO {resource} ({columns}) VALUES ({placeholders})', [data[f] for f in fields])
            data['id'] = cursor.lastrowid
        self.reply(201, data)


if __name__ == '__main__':
    initialize()
    port = int(os.environ.get('PORT', '8000'))
    print(f'School workspace listening on 127.0.0.1:{port}', flush=True)
    ThreadingHTTPServer(('127.0.0.1', port), Handler).serve_forever()
