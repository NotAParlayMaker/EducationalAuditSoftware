"""Versioned, preview-first batch ingestion and scoped exports. No model calls."""
import csv
import hashlib
import io
import json
import secrets
import time

import accounts
import audit_workflow
import security_events as events
from security import RequestError

MAX_ROWS=200
AUDIT_INPUT={'area','finding','owner','reviewer','severity','due_date','remediation','status'}


def initialize(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS pipeline_batches (
            id TEXT PRIMARY KEY, actor TEXT NOT NULL, resource TEXT NOT NULL,
            digest TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
            status TEXT NOT NULL, row_count INTEGER NOT NULL, inserted INTEGER NOT NULL DEFAULT 0,
            skipped INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS pipeline_actor ON pipeline_batches(actor,created_at);
        CREATE TABLE IF NOT EXISTS pipeline_items (
            resource TEXT NOT NULL, fingerprint TEXT NOT NULL, record_id INTEGER NOT NULL,
            PRIMARY KEY(resource,fingerprint));
    ''')


def writer(user,resource,schemas):
    if not user or user['role'] not in ('administrator','auditor'):
        raise RequestError(403,'Only signed-in administrators or auditors can import records.')
    if resource not in schemas:
        raise RequestError(400,'Unsupported resource.')
    accounts.authorize_resource(user,resource,write=True)


def parse_source(source,schemas):
    if not isinstance(source,dict) or source.get('schema_version')!=1 or type(source.get('schema_version')) is not int:
        raise RequestError(400,'Use pipeline schema version 1.')
    resource=source.get('resource')
    if not isinstance(resource,str) or resource not in schemas:
        raise RequestError(400,'Unsupported resource.')
    if source.get('format')=='json' and set(source)=={'schema_version','resource','format','rows'}:
        rows=source['rows']
    elif source.get('format')=='json' and set(source)=={'schema_version','resource','format','data'}:
        text=source['data']
        if not isinstance(text,str):raise RequestError(400,'JSON data must be text.')
        def unique_pairs(items):
            result={}
            for key,value in items:
                if key in result:raise ValueError()
                result[key]=value
            return result
        def no_constant(value):raise ValueError()
        try:
            if len(text.encode('utf-8'))>262144:raise RequestError(413,'JSON file exceeds 256 KiB.')
            rows=json.loads(text.removeprefix('\ufeff'),object_pairs_hook=unique_pairs,parse_constant=no_constant)
        except RequestError:raise
        except (ValueError,UnicodeError,RecursionError):raise RequestError(400,'Invalid JSON record array.') from None
    elif source.get('format')=='csv' and set(source)=={'schema_version','resource','format','data'}:
        text=source['data']
        if not isinstance(text,str):raise RequestError(400,'CSV data must be text.')
        try:
            if len(text.encode('utf-8'))>262144:raise RequestError(413,'CSV exceeds 256 KiB.')
            reader=csv.DictReader(io.StringIO(text.removeprefix('\ufeff'),newline=''),strict=True)
            headers=reader.fieldnames
            if not headers or len(headers)>20 or len(set(headers))!=len(headers):raise ValueError()
            expected=AUDIT_INPUT if resource=='audits' else set(schemas[resource])
            if set(headers)-expected:raise ValueError()
            rows=[]
            for row in reader:
                if len(rows)>=MAX_ROWS:raise RequestError(413,'Use at most 200 records per batch.')
                if None in row or any(value is None for value in row.values()):raise ValueError()
                rows.append(row)
        except RequestError:raise
        except (ValueError,UnicodeError,csv.Error):
            raise RequestError(400,'Invalid CSV headers, encoding, or row shape.') from None
    else:
        raise RequestError(400,'Use an exact JSON or CSV source envelope.')
    if not isinstance(rows,list) or not 1<=len(rows)<=MAX_ROWS:
        raise RequestError(400,'Supply 1–200 records.')
    return resource,rows


def normalize(user,source,validator,schemas,db,check_assignments=True):
    if not user or user['role'] not in ('administrator','auditor'):raise RequestError(403,'Import access required.')
    resource,rows=parse_source(source,schemas)
    writer(user,resource,schemas)
    clean=[];errors=[]
    for index,row in enumerate(rows,1):
        try:
            if not isinstance(row,dict):raise ValueError()
            for value in row.values():
                if not isinstance(value,str) or any(ord(char)<32 and char not in '\r\n\t' for char in value):raise ValueError()
                value.encode('utf-8')
            if resource=='audits':
                if set(row)-AUDIT_INPUT or row.get('status','Draft')!='Draft':raise ValueError()
                candidate=dict(row,status='Draft',actor=user['username'])
                if check_assignments:candidate=accounts.authorize_audit(db,user,candidate)
                record,_=audit_workflow.validate(candidate)
            else:
                record=validator(resource,row)
            clean.append(record)
        except (ValueError,UnicodeError):
            errors.append({'row':index,'code':'invalid_record'})
    digest=hashlib.sha256(json.dumps({'schema_version':1,'resource':resource,'rows':clean},sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()
    return resource,clean,errors,digest,len(rows)


def fingerprint(record):
    return hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def existing(db,resource,record):
    key=fingerprint(record)
    tracked=db.execute('SELECT record_id FROM pipeline_items WHERE resource=? AND fingerprint=?',(resource,key)).fetchone()
    if tracked:
        if not db.execute(f'SELECT 1 FROM {resource} WHERE id=?',(tracked[0],)).fetchone():
            raise RequestError(409,'A prior import target is missing. Review the dataset before retrying.')
        return tracked[0]
    fields=list(record)
    where=' AND '.join('"'+field+'"=?' for field in fields)
    found=db.execute(f'SELECT id FROM {resource} WHERE '+where+' LIMIT 1',[record[field] for field in fields]).fetchone()
    return found[0] if found else None


def preview(db,user,source,validator,schemas):
    resource,rows,errors,digest,count=normalize(user,source,validator,schemas,db)
    if errors:return {'valid':False,'row_count':count,'error_count':len(errors),'errors':errors}
    db.execute('BEGIN IMMEDIATE')
    now=time.time()
    old=db.execute("SELECT * FROM pipeline_batches WHERE actor=? AND resource=? AND digest=? AND status='prepared' AND expires_at>? ORDER BY created_at DESC LIMIT 1",(user['username'],resource,digest,now)).fetchone()
    seen=set();duplicates=0
    for row in rows:
        key=fingerprint(row)
        if key in seen or existing(db,resource,row) is not None:duplicates+=1
        seen.add(key)
    if old:batch_id=old['id'];expires=old['expires_at']
    else:
        if db.execute("SELECT count(*) FROM pipeline_batches WHERE actor=? AND status='prepared' AND expires_at>?",(user['username'],now)).fetchone()[0]>=20:
            raise RequestError(429,'Too many prepared batches. Commit existing previews or wait for expiry.')
        batch_id=secrets.token_urlsafe(24);expires=now+86400
        db.execute("INSERT INTO pipeline_batches(id,actor,resource,digest,created_at,expires_at,status,row_count) VALUES(?,?,?,?,?,?,'prepared',?)",(batch_id,user['username'],resource,digest,now,expires,count))
        events.append(db,'import_preview',actor=user['username'])
    return {'valid':True,'batch_id':batch_id,'digest':digest,'expires_at':expires,'row_count':count,
            'duplicates':duplicates,'would_insert':count-duplicates,'normalized_rows':rows,'errors':[]}


def commit(db,user,data,validator,schemas):
    if not isinstance(data,dict) or set(data)!={'batch_id','digest','source'} or not isinstance(data['batch_id'],str) or len(data['batch_id'])>64:
        raise RequestError(400,'Supply batch ID, preview digest, and source.')
    if not user or user['role'] not in ('administrator','auditor'):raise RequestError(403,'Import access required.')
    db.execute('BEGIN IMMEDIATE')
    batch=db.execute('SELECT * FROM pipeline_batches WHERE id=? AND actor=?',(data['batch_id'],user['username'])).fetchone()
    if not batch:raise RequestError(404,'Batch not found.')
    resource,rows,errors,digest,count=normalize(user,data['source'],validator,schemas,db,check_assignments=batch['status']!='committed')
    if errors:raise RequestError(400,'Batch validation failed. Prepare a new preview.')
    if batch['resource']!=resource or batch['digest']!=digest or data['digest']!=digest:
        raise RequestError(409,'Source changed after preview. Prepare a new preview.')
    if batch['status']=='committed':
        return {'batch_id':batch['id'],'inserted':batch['inserted'],'skipped':batch['skipped'],'replayed':True}
    if time.time()>batch['expires_at']:raise RequestError(409,'Preview expired. Prepare a new preview.')
    inserted=0;skipped=0
    for row in rows:
        record_id=existing(db,resource,row)
        if record_id is None:
            if resource=='audits':
                candidate=accounts.authorize_audit(db,user,row)
                saved=audit_workflow.save(db,candidate);record_id=saved['id']
            else:
                fields=list(row);columns=','.join('"'+field+'"' for field in fields)
                cursor=db.execute(f'INSERT INTO {resource}({columns}) VALUES('+','.join('?' for _ in fields)+')',[row[field] for field in fields]);record_id=cursor.lastrowid
            inserted+=1
        else:skipped+=1
        db.execute('INSERT OR IGNORE INTO pipeline_items VALUES(?,?,?)',(resource,fingerprint(row),record_id))
    db.execute("UPDATE pipeline_batches SET status='committed',inserted=?,skipped=? WHERE id=?",(inserted,skipped,batch['id']))
    events.append(db,'import_committed',actor=user['username'])
    return {'batch_id':batch['id'],'inserted':inserted,'skipped':skipped,'replayed':False}


def export_page(db,user,resource,schemas,after_id=0,limit=200):
    if not user:raise RequestError(403,'Individual account sign-in is required.')
    if not isinstance(resource,str) or resource not in schemas:raise RequestError(400,'Unsupported resource.')
    accounts.authorize_resource(user,resource)
    if type(after_id) is not int or type(limit) is not int or not 0<=after_id<=9223372036854775807 or not 1<=limit<=1000:
        raise RequestError(400,'Invalid export cursor or limit.')
    scope,params=accounts.audit_scope(user) if resource=='audits' else ('1=1',[])
    rows=[dict(row) for row in db.execute(f'SELECT * FROM {resource} WHERE id>? AND ('+scope+') ORDER BY id LIMIT ?',[after_id]+params+[limit+1])]
    more=len(rows)>limit;rows=rows[:limit]
    events.append(db,'export_completed',actor=user['username'])
    return {'format':'schooldesk.export.v1','resource':resource,'rows':rows,'has_more':more,'next_after_id':rows[-1]['id'] if more else None}


def csv_export(result,fields):
    output=io.StringIO(newline='');writer=csv.writer(output);writer.writerow(['id']+fields)
    for row in result['rows']:
        values=[]
        for field in ['id']+fields:
            value=str(row.get(field,''))
            prefix=value
            while prefix and (prefix[0].isspace() or ord(prefix[0])<32 or prefix[0]=='\ufeff'):prefix=prefix[1:]
            if prefix.startswith(('=','+','-','@')) or value.startswith(('\t','\r','\n')):value="'"+value
            values.append(value)
        writer.writerow(values)
    return output.getvalue()
