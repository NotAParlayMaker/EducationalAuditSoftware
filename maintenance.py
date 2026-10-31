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


def readonly(path):
    return sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro',uri=True)


def verify(path):
    with readonly(path) as db:
        if db.execute('PRAGMA quick_check').fetchall()!=[('ok',)]:
            raise ValueError('Database integrity check failed.')
        tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {'audits','audit_history','students','users','account_settings'}<=tables:
            raise ValueError('Not a current Schooldesk database.')


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
    parser.add_argument('command',choices=['backup','verify','restore','snapshot','prune-backups'])
    parser.add_argument('file',help='backup destination, or backup source for verify/restore')
    parser.add_argument('--destination',help='new database path for restore; never overwrite the running database')
    parser.add_argument('--older-than-days',type=int,default=30,help='backup retention age; default 30 days')
    parser.add_argument('--apply',action='store_true',help='actually remove expired generated backups; otherwise preview')
    args=parser.parse_args()
    try:
        if args.command=='prune-backups':
            for path in prune_backups(args.file,args.older_than_days,args.apply):
                print(('Removed: ' if args.apply else 'Would remove: ')+path.name)
            return
        if args.command=='snapshot':
            verify(app.DB)
            directory=Path(args.file)
            name='schooldesk-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)+'.db'
            copy_database(app.DB,directory/name)
        elif args.command=='backup':
            verify(app.DB)
            copy_database(app.DB,args.file)
        elif args.command=='verify':
            verify(args.file)
        else:
            if not args.destination: parser.error('--destination is required')
            verify(args.file)
            copy_database(args.file,args.destination)
        print('Completed. Database integrity verified; no record contents displayed.')
    except (ValueError,OSError,sqlite3.Error):
        parser.exit(1,'Maintenance failed. Check file access, database version, and destination existence. No existing destination is overwritten.\n')


if __name__=='__main__':
    main()
