"""Scheduler entry point. Output paths are generated, never supplied by HTTP."""
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import app
import integrity_anchor
import runtime
import secure_backup


def main():
    directory=Path(os.environ.get('SCHOOL_BACKUP_DIR','/var/lib/schooldesk-backups'))
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    stem='schooldesk-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
    destination=directory/(stem+'.db.enc')
    secure_backup.backup(app.DB,destination)
    # Anchor the exact recovery copy, not a changing live dataset.
    import tempfile
    import maintenance
    with tempfile.TemporaryDirectory() as folder:
        snapshot=Path(folder)/'verify.db';secure_backup.restore(destination,snapshot)
        with maintenance.readonly(snapshot) as db:bundle=integrity_anchor.create(db)
    secure_backup.exclusive(directory/(stem+'.anchor.json'),integrity_anchor.canonical(bundle)+b'\n')
    receipt=os.environ.get('SCHOOL_BACKUP_STATUS_FILE')
    if receipt:runtime.record_backup_receipt(receipt)
    print('Encrypted backup, recovery check, and private anchor bundle completed. Copy to separately protected storage.')


if __name__=='__main__':main()
