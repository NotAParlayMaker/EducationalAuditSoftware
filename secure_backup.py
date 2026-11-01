"""Authenticated encrypted local backups. Keys are supplied outside the database."""
import argparse
import os
from pathlib import Path
import tempfile
import sqlite3

import maintenance
import runtime
import app
import secret_config

MAX_DATABASE=64*1024*1024
MAX_TOKEN=90*1024*1024


def exclusive(path,data):
    descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(descriptor,'wb') as output:output.write(data);output.flush();os.fsync(output.fileno())


def backup(source,destination):
    cipher=secret_config.fernet('SCHOOL_BACKUP_KEY')
    with tempfile.TemporaryDirectory(prefix='schooldesk-secure-') as folder:
        snapshot=Path(folder)/'snapshot.db';maintenance.copy_database(source,snapshot)
        if snapshot.stat().st_size>MAX_DATABASE:raise ValueError('Use managed encrypted storage for databases above 64 MiB.')
        exclusive(destination,cipher.encrypt(snapshot.read_bytes()))


def restore(source,destination):
    cipher=secret_config.fernet('SCHOOL_BACKUP_KEY')
    with open(source,'rb') as encrypted:token=encrypted.read(MAX_TOKEN+1)
    if len(token)>MAX_TOKEN:raise ValueError('Encrypted backup exceeds supported size.')
    try:plain=cipher.decrypt(token)
    except Exception:raise ValueError('Backup authentication failed.') from None
    if len(plain)>MAX_DATABASE:raise ValueError('Database exceeds supported size.')
    with tempfile.TemporaryDirectory(prefix='schooldesk-restore-') as folder:
        snapshot=Path(folder)/'snapshot.db';exclusive(snapshot,plain);maintenance.verify(snapshot)
        maintenance.copy_database(snapshot,destination)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=['backup','restore']);parser.add_argument('file');parser.add_argument('--destination');args=parser.parse_args()
    try:
        if args.command=='backup':
            backup(app.DB,args.file)
            receipt=os.environ.get('SCHOOL_BACKUP_STATUS_FILE')
            if receipt:runtime.record_backup_receipt(receipt)
            else:
                with app.connect() as db:runtime.record_backup(db,kind='authenticated_encrypted')
        else:
            if not args.destination:parser.error('--destination is required')
            restore(args.file,args.destination)
        print('Encrypted backup operation completed and database integrity checked.')
    except (ValueError,OSError,ImportError,sqlite3.Error):parser.exit(1,'Encrypted backup failed. Check keys, integrity, size, and destination access. Existing destinations are never overwritten.\n')


if __name__=='__main__':main()
