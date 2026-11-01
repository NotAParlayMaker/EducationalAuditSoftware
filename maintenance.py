"""Local SQLite backup, integrity verification, and restore-to-new-file tools."""
import argparse
import os
import re
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

import app
import runtime
import deployment
import json
import security_events as events
import integrity_anchor


def readonly(path):
    db=sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True)
    db.row_factory=sqlite3.Row
    return db


def verify(path):
    with readonly(path) as db:
        if [row[0] for row in db.execute('PRAGMA quick_check')]!=['ok']:
            raise ValueError('Database integrity check failed.')
        tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'audits','audit_history','students','users','account_settings'}<=tables:
            raise ValueError('Not a current Schooldesk database.')
        if 'security_events' in tables and not events.verify(db)['valid']:
            raise ValueError('Security event chain is inconsistent.')


def copy_database(source,destination):
    destination=Path(destination)
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    # Exclusive creation prevents accidental overwrite of the live database or backup.
    descriptor=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(descriptor)
    try:
        with readonly(source) as origin, sqlite3.connect(destination) as target:
            origin.backup(target)
            # Backups must never reactivate old sessions when restored.
            target.execute('DELETE FROM sessions')
            tables={row[0] for row in target.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'mfa_recovery' in tables:target.execute('DELETE FROM mfa_recovery')
            if 'mfa_accounts' in tables:target.execute('UPDATE mfa_accounts SET last_counter=max(last_counter,?)',(int(time.time()//30),))
        verify(destination)
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def prune_backups(directory, days, apply=False, now=None):
    if not 1 <= days <= 3650:
        raise ValueError('Choose retention of 1–3650 days.')
    cutoff=(time.time() if now is None else now)-days*86400
    candidates=[]
    for path in Path(directory).iterdir():
        if path.is_symlink() or not path.is_file() or not re.fullmatch(r'schooldesk-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}\.db',path.name):
            continue
        if path.stat().st_mtime < cutoff:
            candidates.append(path)
    for path in candidates:
        if apply:
            path.unlink()
    return candidates


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['backup','verify','restore','snapshot','prune-backups','security-checkpoint','security-verify','anchor-create','anchor-verify'])
    parser.add_argument('file',nargs='?',help='backup destination, or backup source for verify/restore')
    parser.add_argument('--destination',help='new database path for restore; never overwrite the running database')
    parser.add_argument('--older-than-days',type=int,default=30,help='backup retention age; default 30 days')
    parser.add_argument('--published-commitment',help='independently obtained public commitment hash, optionally prefixed 0x')
    parser.add_argument('--checkpoint',help='previous trusted checkpoint JSON for security-verify')
    parser.add_argument('--apply',action='store_true',help='actually remove expired generated backups; otherwise preview')
    args=parser.parse_args()
    if args.command!='security-verify' and not args.file:
        parser.error('A destination or directory is required.')
    try:
        if deployment.cloud() and args.command in ('backup','snapshot','restore'):raise ValueError('Use encrypted backup tooling in the cloud profile.')
        if args.command in ('anchor-create','anchor-verify'):
            with app.connect() as db:
                if args.command=='anchor-create':
                    bundle=integrity_anchor.create(db)
                    descriptor=os.open(args.file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                    with os.fdopen(descriptor,'w',encoding='utf-8') as output:output.write(json.dumps(bundle,sort_keys=True)+'\n')
                    print('Public commitment: '+bundle['commitment'])
                    print('Private bundle created. No blockchain transaction was submitted.')
                else:
                    with open(args.file,'rb') as source:raw=source.read(8193)
                    if len(raw)>8192:raise ValueError('Anchor bundle too large.')
                    result=integrity_anchor.verify(db,json.loads(raw),args.published_commitment)
                    print(json.dumps(result,sort_keys=True))
                    if not result['valid']:parser.exit(1,'Snapshot differs or history does not match. Verify against the corresponding backup; legitimate later edits also change the dataset root.\n')
            return
        if args.command in ('security-checkpoint','security-verify'):
            with app.connect() as db:
                checkpoint=None
                if args.checkpoint:
                    raw=Path(args.checkpoint).read_bytes()
                    if len(raw)>1024:raise ValueError('Checkpoint too large.')
                    checkpoint=json.loads(raw)
                result=events.verify(db,checkpoint)
            if not result['valid']:raise ValueError('Security history verification failed.')
            if args.command=='security-checkpoint':
                destination=Path(args.file)
                descriptor=os.open(destination,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                with os.fdopen(descriptor,'w',encoding='utf-8') as output:
                    output.write(json.dumps({'count':result['count'],'head':result['head']},sort_keys=True)+'\n')
                if os.name=='posix':destination.chmod(0o600)
            else:print('Security chain verified; trusted checkpoint matched.' if checkpoint else 'Security chain internally consistent; no trusted checkpoint supplied.')
            return
        if args.command=='prune-backups':
            for path in prune_backups(args.file,args.older_than_days,args.apply):
                print(('Removed: ' if args.apply else 'Would remove: ')+path.name)
            return
        if args.command=='snapshot':
            verify(app.DB)
            directory=Path(args.file)
            name='schooldesk-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)+'.db'
            copy_database(app.DB,directory/name)
            with app.connect() as db:runtime.record_backup(db)
            print('Snapshot created: '+name)
        elif args.command=='backup':
            verify(app.DB)
            copy_database(app.DB,args.file)
            with app.connect() as db:runtime.record_backup(db)
        elif args.command=='verify':
            verify(args.file)
        else:
            if not args.destination: parser.error('--destination is required')
            verify(args.file)
            copy_database(args.file,args.destination)
        print('Completed. Database integrity verified; no record contents displayed.')
    except (ValueError,OSError,sqlite3.Error):
        if args.command in ('security-checkpoint','security-verify'):
            parser.exit(1,'Security verification or checkpoint operation failed. Preserve the database and trusted checkpoint; check integrity and file access.\n')
        parser.exit(1,'Maintenance failed. Check file access, database version, and destination existence. No existing destination is overwritten.\n')


if __name__=='__main__':
    main()
