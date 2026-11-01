"""Private snapshot openings and public hash commitments. No chain/network client."""
import hashlib
import hmac
import json
import re
import secrets

import security_events
import learning

TABLES=('students','attendance','grades','assets','audits','tickets','audit_history','audit_evidence')
DOMAIN=b'schooldesk.anchor.v1\x00'


def canonical(value):
    try:return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
    except (TypeError,ValueError):raise ValueError('Unsupported dataset encoding.') from None


def data_root(db,nonce,tables=TABLES):
    if not isinstance(nonce,str) or not re.fullmatch('[a-f0-9]{64}',nonce):raise ValueError('Invalid nonce.')
    salt=bytes.fromhex(nonce);frontier=[];counts={};total=0
    for table in tables:
        count=0
        for row in db.execute('SELECT * FROM '+table+' ORDER BY id'):
            record=dict(row)
            if table=='audit_evidence':
                content=record.pop('content')
                if not isinstance(content,bytes):raise ValueError('Invalid evidence content.')
                digest=hashlib.sha256(content).hexdigest()
                if digest!=record['sha256'] or len(content)!=record['size']:raise ValueError('Evidence integrity check failed.')
                record['content_digest']=digest
            leaf=hashlib.sha256(b'\x00'+salt+canonical({'table':table,'row':record})).digest()
            level=0
            while level<len(frontier) and frontier[level] is not None:
                leaf=hashlib.sha256(b'\x01'+frontier[level]+leaf).digest();frontier[level]=None;level+=1
            if level==len(frontier):frontier.append(leaf)
            else:frontier[level]=leaf
            count+=1;total+=1
        counts[table]=count
    root=None
    for node in frontier:
        if node is not None:root=node if root is None else hashlib.sha256(b'\x01'+node+root).digest()
    if root is None:root=hashlib.sha256(b'\x02'+salt).digest()
    return {'root':root.hex(),'rows':total,'table_counts':counts}


def commitment(payload):
    domain=b'schooldesk.anchor.v2\x00' if payload.get('format')=='schooldesk.anchor.v2' else DOMAIN
    return hashlib.sha256(domain+canonical(payload)).hexdigest()


def create(db):
    if not db.in_transaction:db.execute('BEGIN')
    checked=security_events.verify(db)
    if not checked['valid']:raise ValueError('Security history is inconsistent.')
    nonce=secrets.token_hex(32)
    payload={'format':'schooldesk.anchor.v2','nonce':nonce,
             'checkpoint':{'count':checked['count'],'head':checked['head']},'dataset':data_root(db,nonce,TABLES+learning.TABLES)}
    return dict(payload,commitment=commitment(payload))


def validate(bundle):
    if not isinstance(bundle,dict) or set(bundle)!={'format','nonce','checkpoint','dataset','commitment'} or bundle['format'] not in ('schooldesk.anchor.v1','schooldesk.anchor.v2'):
        raise ValueError('Invalid anchor bundle.')
    if not isinstance(bundle['commitment'],str) or not re.fullmatch('[a-f0-9]{64}',bundle['commitment']):raise ValueError('Invalid commitment.')
    if not isinstance(bundle['nonce'],str) or not re.fullmatch('[a-f0-9]{64}',bundle['nonce']):raise ValueError('Invalid nonce.')
    checkpoint=bundle['checkpoint'];dataset=bundle['dataset']
    if not isinstance(checkpoint,dict) or set(checkpoint)!={'count','head'} or type(checkpoint['count']) is not int or checkpoint['count']<0 or not isinstance(checkpoint['head'],str) or not re.fullmatch('[a-f0-9]{64}',checkpoint['head']):raise ValueError('Invalid checkpoint.')
    if not isinstance(dataset,dict) or set(dataset)!={'root','rows','table_counts'} or not isinstance(dataset['root'],str) or not re.fullmatch('[a-f0-9]{64}',dataset['root']) or type(dataset['rows']) is not int or dataset['rows']<0:raise ValueError('Invalid dataset root.')
    counts=dataset['table_counts']
    tables=TABLES+learning.TABLES if bundle['format']=='schooldesk.anchor.v2' else TABLES
    if not isinstance(counts,dict) or set(counts)!=set(tables) or any(type(value) is not int or value<0 for value in counts.values()) or sum(counts.values())!=dataset['rows']:raise ValueError('Invalid dataset counts.')
    payload={key:bundle[key] for key in ('format','nonce','checkpoint','dataset')}
    if not hmac.compare_digest(commitment(payload),bundle['commitment']):raise ValueError('Anchor commitment mismatch.')


def verify(db,bundle,published=None):
    validate(bundle)
    if published is not None:
        if not isinstance(published,str):raise ValueError('Invalid published commitment.')
        published=published.removeprefix('0x')
        if not re.fullmatch('[a-f0-9]{64}',published) or not hmac.compare_digest(published,bundle['commitment']):raise ValueError('Published commitment mismatch.')
    if not db.in_transaction:db.execute('BEGIN')
    chain=security_events.verify(db,bundle['checkpoint'])
    current=data_root(db,bundle['nonce'],TABLES+learning.TABLES if bundle['format']=='schooldesk.anchor.v2' else TABLES)
    matched=current==bundle['dataset']
    return {'valid':chain['valid'] and matched,'security_prefix_matches':chain['valid'],
            'dataset_matches':matched,'published_commitment_matches':True if published is not None else None,
            'commitment':bundle['commitment'],'format':bundle['format'],'learning_records_covered':bundle['format']=='schooldesk.anchor.v2'}
