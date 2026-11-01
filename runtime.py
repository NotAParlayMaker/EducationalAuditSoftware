"""Operational checks and role-specific work queues, without secret disclosure."""
import os
import time
from datetime import datetime, timezone

import accounts


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS operational_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)')


def status(db):
    db.execute('SELECT 1').fetchone()
    roles={role:0 for role in accounts.ROLES}
    for row in db.execute('SELECT role,count(*) FROM users WHERE active=1 GROUP BY role'):
        if row[0] in roles:roles[row[0]]=row[1]
    backup=db.execute("SELECT value FROM operational_state WHERE key='backup_success_at'").fetchone()
    mode=os.environ.get('SCHOOL_AI_MODE','offline')
    configured=mode=='offline' or (mode=='openai' and bool(os.environ.get('OPENAI_API_KEY')) and bool(os.environ.get('SCHOOL_AI_MODEL')))
    warnings=[]
    if not accounts.enabled(db):warnings.append('Individual accounts have not been provisioned.')
    for role,count in roles.items():
        if not count:warnings.append('No active '+role.replace('_',' ')+' account.')
    if not configured:warnings.append('AI mode is unsupported or its required configuration is missing.')
    if not backup:warnings.append('No successful backup has been recorded by this version.')
    elif time.time()-float(backup[0])>48*3600:warnings.append('Last recorded backup is older than 48 hours.')
    return {'database':'reachable','accounts_enabled':accounts.enabled(db),'active_accounts':sum(roles.values()),
            'roles':roles,'ai':{'mode':mode if mode in ('offline','openai') else 'unsupported','configured':configured},
            'backup':{'last_success_at':backup[0] if backup else None},'warnings':warnings}


def record_backup(db):
    initialize(db)
    db.execute("INSERT OR REPLACE INTO operational_state VALUES('backup_success_at',?)",(str(time.time()),))


def work_queue(db,user):
    # IT data remains readable to all account roles; task selection is role-specific.
    role=user['role'] if user else 'administrator'
    username=user['username'] if user else ''
    where="status<>'Closed'";params=[]
    if role=='remediation_owner':
        where+=" AND owner=? AND status IN ('Open','In progress')";params.append(username)
    elif role=='reviewer':
        where+=" AND reviewer=? AND status='Awaiting verification'";params.append(username)
    counts={row['status']:row['total'] for row in db.execute('SELECT status,count(*) AS total FROM audits WHERE '+where+' GROUP BY status',params)}
    rows=[dict(row) for row in db.execute('SELECT * FROM audits WHERE '+where+" ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, CASE WHEN due_date='' THEN 1 ELSE 0 END, due_date, id LIMIT 50",params)]
    today=datetime.now(timezone.utc).date().isoformat()
    for row in rows:row['overdue']=bool(row['due_date'] and row['due_date']<today)
    return {'counts':counts,'total':sum(counts.values()),'shown':len(rows),'items':rows}
