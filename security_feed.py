"""Incremental, payload-free security feed for a separately configured collector."""
import argparse
import json
import os
from pathlib import Path
import tempfile

import maintenance
import security_events as events
import durable_files


def export(database,directory,limit=1000):
    if not 1<=limit<=1000:raise ValueError('Use 1–1000 events per segment.')
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True,mode=0o750)
    cursor=directory/'cursor.json';checkpoint=None
    if cursor.exists():
        raw=cursor.read_bytes()
        if len(raw)>1024:raise ValueError('Invalid feed cursor.')
        checkpoint=json.loads(raw)
    with maintenance.readonly(database) as db:
        db.execute('BEGIN')
        if not events.verify(db,checkpoint)['valid']:raise ValueError('Security prefix changed. Preserve feed and database.')
        after=checkpoint['count'] if checkpoint else 0
        rows=[dict(row) for row in db.execute('SELECT * FROM security_events WHERE id>? ORDER BY id LIMIT ?',(after,limit))]
    if not rows:return 0
    data=b''.join(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n' for row in rows)
    segment=directory/('events-'+str(rows[0]['id']).zfill(10)+'-'+str(rows[-1]['id']).zfill(10)+'.jsonl')
    if segment.exists():
        if segment.read_bytes()!=data:raise ValueError('Existing segment differs; preserve it for investigation.')
    else:
        durable_files.write_new(segment,data,mode=0o640)
    # A cursor must never become durable ahead of its event segment.
    durable_files.sync_directory(directory)
    descriptor,name=tempfile.mkstemp(prefix='.cursor-',dir=directory)
    try:
        with os.fdopen(descriptor,'w') as output:
            json.dump({'count':rows[-1]['id'],'head':rows[-1]['event_hash']},output,sort_keys=True);output.flush();os.fsync(output.fileno())
        os.replace(name,cursor)
        durable_files.sync_directory(directory)
    finally:
        if os.path.exists(name):os.unlink(name)
    return len(rows)


def main():
    import app
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory');args=parser.parse_args()
    print('Security events exported: '+str(export(app.DB,args.directory)))


if __name__=='__main__':main()
