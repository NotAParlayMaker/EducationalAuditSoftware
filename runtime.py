"""Operational checks and role-specific work queues, without secret disclosure."""
import os
import time
from datetime import datetime, timezone

import accounts
import secret_config
import mfa
import evidence_scan
import json
import math
import durable_files
from pathlib import Path


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS operational_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)')


def status(db):
    db.execute('SELECT 1').fetchone()
    roles={role:0 for role in accounts.ROLES}
    for row in db.execute('SELECT role,count(*) FROM users WHERE active=1 GROUP BY role'):
        if row[0] in roles:roles[row[0]]=row[1]
    backup=db.execute("SELECT value FROM operational_state WHERE key='backup_success_at'").fetchone()
    kind_row=db.execute("SELECT value FROM operational_state WHERE key='backup_kind'").fetchone()
    backup_kind=kind_row[0] if kind_row else 'plain'
    receipt_valid=False
    receipt=os.environ.get('SCHOOL_BACKUP_STATUS_FILE')
    if receipt:
        try:
            with open(receipt,'rb') as status_file:raw=status_file.read(4097)
            if len(raw)>4096:raise ValueError()
            status=json.loads(raw)
            if set(status)!={'format','completed_at','kind'} or status['format']!='schooldesk.backup-receipt.v1' or status['kind']!='authenticated_encrypted' or type(status['completed_at']) not in (int,float) or not math.isfinite(status['completed_at']) or not 0<=status['completed_at']<=time.time()+60:raise ValueError()
            backup=(str(status['completed_at']),);backup_kind=status['kind'];receipt_valid=True
        except (OSError,ValueError,TypeError):backup=None
    mode=os.environ.get('SCHOOL_AI_MODE','offline')
    try:ai_key=secret_config.read('OPENAI_API_KEY')
    except ValueError:ai_key=None
    configured=mode=='offline' or (mode=='openai' and bool(ai_key) and bool(os.environ.get('SCHOOL_AI_MODEL')))
    warnings=[]
    if not accounts.enabled(db):warnings.append('Individual accounts have not been provisioned.')
    for role,count in roles.items():
        if not count:warnings.append('No active '+role.replace('_',' ')+' account.')
    if not configured:warnings.append('AI mode is unsupported or its required configuration is missing.')
    missing_mfa=sum(1 for row in db.execute('SELECT username,role FROM users WHERE active=1') if mfa.required(row,db) and not mfa.active(db,row['username']))
    if missing_mfa:warnings.append(str(missing_mfa)+' accounts require MFA enrollment.')
    if evidence_scan.required() and not evidence_scan.health():warnings.append('Evidence scanner unavailable; uploads remain quarantined.')
    if evidence_scan.required() and db.execute("SELECT 1 FROM audit_evidence WHERE scan_status<>'clean' LIMIT 1").fetchone():warnings.append('Evidence requires clean scans before release.')
    if os.environ.get('SCHOOL_PROFILE')=='cloud' and not receipt_valid:warnings.append('No independently recorded encrypted backup receipt.')
    if not backup:warnings.append('No successful backup has been recorded by this version.')
    elif time.time()-float(backup[0])>48*3600:warnings.append('Last recorded backup is older than 48 hours.')
    return {'database':'reachable','accounts_enabled':accounts.enabled(db),'active_accounts':sum(roles.values()),
            'roles':roles,'ai':{'mode':mode if mode in ('offline','openai') else 'unsupported','configured':configured},
            'backup':{'last_success_at':backup[0] if backup else None,'kind':backup_kind},'warnings':warnings}


def record_backup(db,kind='plain'):
    initialize(db)
    if kind not in ('plain','authenticated_encrypted'):raise ValueError('Invalid backup kind.')
    db.execute("INSERT OR REPLACE INTO operational_state VALUES('backup_success_at',?)",(str(time.time()),))
    db.execute("INSERT OR REPLACE INTO operational_state VALUES('backup_kind',?)",(kind,))


def work_queue(db,user):
    # Assignment scope applies before selecting actionable states.
    role=user['role'] if user else 'administrator'
    username=user['username'] if user else ''
    scope,params=accounts.audit_scope(user)
    where="("+scope+") AND status<>'Closed'"
    if role=='remediation_owner':
        where+=" AND owner=? AND status IN ('Open','In progress')";params.append(username)
    elif role=='reviewer':
        where+=" AND reviewer=? AND status='Awaiting verification'";params.append(username)
    counts={row['status']:row['total'] for row in db.execute('SELECT status,count(*) AS total FROM audits WHERE '+where+' GROUP BY status',params)}
    rows=[dict(row) for row in db.execute('SELECT * FROM audits WHERE '+where+" ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, CASE WHEN due_date='' THEN 1 ELSE 0 END, due_date, id LIMIT 50",params)]
    today=datetime.now(timezone.utc).date().isoformat()
    for row in rows:row['overdue']=bool(row['due_date'] and row['due_date']<today)
    return {'counts':counts,'total':sum(counts.values()),'shown':len(rows),'items':rows}


def record_backup_receipt(filename):
    import tempfile
    path=Path(filename)
    # The parent is provisioned by the operator: backup-worker owned, application read-only.
    descriptor,temporary=tempfile.mkstemp(prefix='.receipt-',dir=path.parent)
    try:
        os.fchmod(descriptor,0o640)
        with os.fdopen(descriptor,'w') as output:
            json.dump({'format':'schooldesk.backup-receipt.v1','completed_at':time.time(),'kind':'authenticated_encrypted'},output,sort_keys=True)
            output.flush();os.fsync(output.fileno())
        os.replace(temporary,path)
        durable_files.sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
