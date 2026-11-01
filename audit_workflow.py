"""Deterministic audit lifecycle with transactional revision history."""
import json
from datetime import date, datetime, timezone

FIELDS = ['area', 'finding', 'status', 'owner', 'severity', 'evidence', 'due_date',
          'remediation', 'reviewer', 'verification', 'closure_reason', 'reopen_reason']
STATUSES = ['Draft', 'Open', 'In progress', 'Awaiting verification', 'Closed']
TRANSITIONS = {
    'Draft': {'Draft', 'Open'},
    'Open': {'Open', 'In progress'},
    'In progress': {'In progress', 'Awaiting verification'},
    'Awaiting verification': {'Awaiting verification', 'In progress', 'Closed'},
    'Closed': {'Open'},
}


class Conflict(ValueError):
    pass


def migrate(db):
    columns = {row[1] for row in db.execute('PRAGMA table_info(audits)')}
    for field in FIELDS[3:]:
        if field not in columns:
            db.execute(f'ALTER TABLE audits ADD COLUMN {field} TEXT NOT NULL DEFAULT ""')
    if 'revision' not in columns:
        db.execute('ALTER TABLE audits ADD COLUMN revision INTEGER NOT NULL DEFAULT 1')
    # Old Resolved records have no verification evidence and must be reviewed.
    db.execute("UPDATE audits SET status='Awaiting verification' WHERE status='Resolved'")
    db.execute('''CREATE TABLE IF NOT EXISTS audit_history (
        id INTEGER PRIMARY KEY, audit_id INTEGER NOT NULL, revision INTEGER NOT NULL,
        recorded_at TEXT NOT NULL, actor TEXT NOT NULL, snapshot TEXT NOT NULL,
        UNIQUE(audit_id, revision))''')
    for row in db.execute('SELECT * FROM audits').fetchall():
        record = dict(row)
        if not db.execute('SELECT 1 FROM audit_history WHERE audit_id=?', (record['id'],)).fetchone():
            record_event(db, record, 'legacy migration')


def validate(data, previous=None):
    if not isinstance(data, dict) or set(data) - set(FIELDS + ['actor', 'revision']):
        raise ValueError('Unknown audit fields.')
    if previous and (type(data.get('revision')) is not int or data['revision'] != previous['revision']):
        raise Conflict('Audit changed. Reload it before saving.')
    if previous and previous['status'] == 'Closed' and data.get('status') != 'Open':
        raise ValueError('Closed findings must be reopened before editing.')
    clean = {}
    for field in FIELDS:
        value = data.get(field, previous[field] if previous else ('Draft' if field == 'status' else ''))
        if not isinstance(value, str) or len(value) > 500:
            raise ValueError(f'{field}: use at most 500 characters.')
        clean[field] = value.strip()
    actor = data.get('actor', '')
    if not isinstance(actor, str) or not actor.strip() or len(actor) > 100:
        raise ValueError('Enter the name or identifier of the person making this change.')
    if not clean['area'] or not clean['finding']:
        raise ValueError('Area and finding are required.')
    status = clean['status']
    if status not in STATUSES:
        raise ValueError('Invalid audit status.')
    if previous and status not in TRANSITIONS.get(previous['status'], set()):
        raise ValueError('Invalid audit status transition.')
    if not previous and status not in ('Draft', 'Open'):
        raise ValueError('New findings must start Draft or Open.')
    if clean['severity'] not in ('', 'Low', 'Medium', 'High', 'Critical'):
        raise ValueError('Invalid severity.')
    if clean['due_date']:
        try:
            parsed = date.fromisoformat(clean['due_date'])
            if parsed.isoformat() != clean['due_date']:
                raise ValueError()
        except ValueError:
            raise ValueError('Due date must be YYYY-MM-DD.') from None
    required = []
    if status != 'Draft':
        required += ['owner', 'severity', 'due_date']
    if status in ('In progress', 'Awaiting verification', 'Closed'):
        required += ['remediation']
    if status in ('Awaiting verification', 'Closed'):
        required += ['evidence', 'reviewer']
        if clean['reviewer'].casefold() == clean['owner'].casefold():
            raise ValueError('Reviewer must differ from the remediation owner.')
    if status == 'Closed':
        required += ['verification', 'closure_reason']
        if actor.strip().casefold() != clean['reviewer'].casefold():
            raise ValueError('The recorded reviewer must perform closure.')
    if previous and previous['status'] == 'Closed':
        required += ['reopen_reason']
        clean['verification'] = ''
        clean['closure_reason'] = ''
    if any(not clean[field] for field in required):
        raise ValueError('Missing required fields: ' + ', '.join(field for field in required if not clean[field]))
    return clean, actor.strip()


def record_event(db, record, actor):
    db.execute('INSERT INTO audit_history(audit_id, revision, recorded_at, actor, snapshot) VALUES(?,?,?,?,?)',
               (record['id'], record['revision'], datetime.now(timezone.utc).isoformat(), actor,
                json.dumps(record, sort_keys=True)))


def save(db, data, audit_id=None):
    # A caller-supplied transaction must acquire its write lock before authorization.
    # Otherwise serialize read/validate/write here to prevent lost updates.
    if not db.in_transaction:
        db.execute('BEGIN IMMEDIATE')
    previous = None
    if audit_id is not None:
        row = db.execute('SELECT * FROM audits WHERE id=?', (audit_id,)).fetchone()
        if row is None:
            raise LookupError('Audit not found.')
        previous = dict(row)
    clean, actor = validate(data, previous)
    revision = previous['revision'] + 1 if previous else 1
    if previous:
        assignments = ', '.join(f'{field}=?' for field in FIELDS)
        db.execute(f'UPDATE audits SET {assignments}, revision=? WHERE id=?',
                   [clean[f] for f in FIELDS] + [revision, audit_id])
    else:
        placeholders = ','.join('?' for _ in FIELDS)
        cursor = db.execute(f'INSERT INTO audits({",".join(FIELDS)}) VALUES({placeholders})', [clean[f] for f in FIELDS])
        audit_id = cursor.lastrowid
    record = dict(clean, id=audit_id, revision=revision)
    record_event(db, record, actor)
    return record
