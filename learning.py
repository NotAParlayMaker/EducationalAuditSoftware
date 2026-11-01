"""Class-scoped, revisable learning evidence. No model calls or mastery scores."""
from datetime import date, datetime, timedelta, timezone
import json
import re
import sqlite3
import statistics

import mfa
import security_events
from security import RequestError

WINDOW_DAYS=30
MAX_OBSERVATIONS=2000
MAX_REVIEWS=500
MAX_REQUESTS=200
METHODS=('written','oral','diagram','transfer','practice')
OUTCOMES=('demonstrated','developing','incorrect','not_assessed','absent','inaccessible')
MISSING=('not_assessed','absent','inaccessible')
JUDGMENTS=('insufficient_evidence','developing','demonstrated_across_contexts')
TABLES=('learning_classes','learning_enrollments','learning_skills','learning_observations','learning_reviews','learning_reassessments','learning_history')


def initialize(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS learning_classes(id INTEGER PRIMARY KEY,name TEXT NOT NULL,
        teacher TEXT NOT NULL REFERENCES users(username),revision INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS learning_enrollments(id INTEGER PRIMARY KEY,class_id INTEGER NOT NULL REFERENCES learning_classes(id),
        student_id INTEGER NOT NULL REFERENCES students(id),active INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1,UNIQUE(class_id,student_id));
    CREATE TABLE IF NOT EXISTS learning_skills(id INTEGER PRIMARY KEY,class_id INTEGER NOT NULL REFERENCES learning_classes(id),
        code TEXT NOT NULL,title TEXT NOT NULL,rubric_version TEXT NOT NULL,criteria TEXT NOT NULL,active INTEGER NOT NULL,
        UNIQUE(class_id,code,rubric_version));
    CREATE TABLE IF NOT EXISTS learning_observations(id INTEGER PRIMARY KEY,class_id INTEGER NOT NULL REFERENCES learning_classes(id),
        student_id INTEGER NOT NULL REFERENCES students(id),skill_id INTEGER NOT NULL REFERENCES learning_skills(id),observed_on TEXT NOT NULL,
        recorded_at TEXT NOT NULL,method TEXT NOT NULL,outcome TEXT NOT NULL,context TEXT NOT NULL,observation TEXT NOT NULL,
        source_id TEXT NOT NULL,supersedes_id INTEGER UNIQUE REFERENCES learning_observations(id),correction_reason TEXT NOT NULL,
        actor TEXT NOT NULL,UNIQUE(class_id,source_id));
    CREATE INDEX IF NOT EXISTS learning_observation_scope ON learning_observations(class_id,student_id,skill_id,observed_on);
    CREATE TABLE IF NOT EXISTS learning_reviews(id INTEGER PRIMARY KEY,class_id INTEGER NOT NULL REFERENCES learning_classes(id),
        student_id INTEGER NOT NULL REFERENCES students(id),skill_id INTEGER NOT NULL REFERENCES learning_skills(id),judgment TEXT NOT NULL,
        rationale TEXT NOT NULL,evidence_ids TEXT NOT NULL,recorded_at TEXT NOT NULL,actor TEXT NOT NULL,
        previous_review_id INTEGER REFERENCES learning_reviews(id));
    CREATE INDEX IF NOT EXISTS learning_review_scope ON learning_reviews(class_id,student_id,skill_id,id);
    CREATE TABLE IF NOT EXISTS learning_reassessments(id INTEGER PRIMARY KEY,class_id INTEGER NOT NULL REFERENCES learning_classes(id),
        student_id INTEGER NOT NULL REFERENCES students(id),skill_id INTEGER NOT NULL REFERENCES learning_skills(id),reason TEXT NOT NULL,
        student_statement TEXT NOT NULL,reported_source TEXT NOT NULL,status TEXT NOT NULL,revision INTEGER NOT NULL,
        recorded_at TEXT NOT NULL,actor TEXT NOT NULL,resolution TEXT NOT NULL DEFAULT '',resolved_by TEXT NOT NULL DEFAULT '',
        observation_id INTEGER REFERENCES learning_observations(id),resolved_at TEXT NOT NULL DEFAULT '');
    CREATE INDEX IF NOT EXISTS learning_request_scope ON learning_reassessments(class_id,student_id,status);
    CREATE TABLE IF NOT EXISTS learning_history(id INTEGER PRIMARY KEY,class_id INTEGER NOT NULL REFERENCES learning_classes(id),
        student_id INTEGER REFERENCES students(id),kind TEXT NOT NULL,entity_id INTEGER NOT NULL,recorded_at TEXT NOT NULL,
        actor TEXT NOT NULL,snapshot TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS learning_history_scope ON learning_history(class_id,student_id,id);
    ''')


def now():return datetime.now(timezone.utc).isoformat()


def text(value,maximum=1000,optional=False):
    if not isinstance(value,str) or len(value)>maximum or (not optional and not value.strip()) or any(ord(c)<32 and c not in '\n\r\t' for c in value):
        raise RequestError(400,'Use bounded, nonempty text without binary controls.')
    try:value.encode('utf-8')
    except UnicodeError:raise RequestError(400,'Invalid text encoding.') from None
    return value.strip()


def number(value):
    if type(value) is not int or not 1<=value<=9223372036854775807:raise RequestError(400,'Use a positive record ID.')
    return value


def exact(data,fields):
    if not isinstance(data,dict) or set(data)!=set(fields):raise RequestError(400,'Supply the exact fields for this learning operation.')


def authorize(db,user,registrar=False):
    if not user or user['role'] not in (('registrar',) if registrar else ('registrar','teacher')):
        raise RequestError(403,'Learning access requires a registrar or assigned teacher account.')
    fresh=db.execute('SELECT role,active FROM users WHERE username=?',(user['username'],)).fetchone()
    if not fresh or not fresh['active'] or fresh['role']!=user['role']:raise RequestError(401,'Account changed. Sign in again.')


def classroom(db,user,class_id):
    authorize(db,user)
    row=db.execute('SELECT * FROM learning_classes WHERE id=?',(class_id,)).fetchone()
    if not row or (user['role']=='teacher' and row['teacher']!=user['username']):raise RequestError(404,'Class not found.')
    return dict(row)


def learner(db,user,class_id,student_id):
    classroom(db,user,class_id)
    row=db.execute('''SELECT s.id,s.name,s.year,e.active,e.revision FROM students s JOIN learning_enrollments e ON e.student_id=s.id
        WHERE e.class_id=? AND s.id=?''',(class_id,student_id)).fetchone()
    if not row or (not row['active'] and user['role']=='teacher'):raise RequestError(404,'Student not found in this class.')
    return dict(row)


def skill(db,class_id,skill_id,active=True):
    row=db.execute('SELECT * FROM learning_skills WHERE id=? AND class_id=?',(number(skill_id),class_id)).fetchone()
    if not row or (active and not row['active']):raise RequestError(404,'Current skill version not found.')
    return dict(row)


def history(db,user,class_id,student_id,kind,record):
    db.execute('INSERT INTO learning_history(class_id,student_id,kind,entity_id,recorded_at,actor,snapshot) VALUES(?,?,?,?,?,?,?)',
        (class_id,student_id,kind,record['id'],now(),user['username'],json.dumps(record,sort_keys=True)))
    security_events.append(db,'learning_recorded',actor=user['username'])


def teacher(db,name):
    name=text(name,50)
    if not db.execute("SELECT 1 FROM users WHERE username=? AND active=1 AND role='teacher'",(name,)).fetchone():
        raise RequestError(400,'Choose an active teacher account.')
    return name


def query_shape(query,allowed=()):
    if set(query)-set(allowed) or any(len(v)!=1 for v in query.values()):raise RequestError(400,'Invalid learning query.')


def page(query,allowed=()):
    query_shape(query,set(allowed)|{'limit','before_id'})
    try:
        limit=int(query.get('limit',['50'])[0]);before=int(query.get('before_id',['9223372036854775807'])[0])
        if not 1<=limit<=100 or not 1<=before<=9223372036854775807:raise ValueError()
    except ValueError:raise RequestError(400,'Invalid page cursor or limit.') from None
    return limit,before


def pack(rows,limit):
    more=len(rows)>limit;rows=rows[:limit]
    return {'rows':rows,'has_more':more,'next_before_id':rows[-1]['id'] if more else None}


def current_observations(db,class_id,student_id,skill_id):
    return [dict(r) for r in db.execute('''SELECT o.id,o.skill_id,o.method,o.outcome,o.context,o.observed_on,o.recorded_at FROM learning_observations o WHERE class_id=? AND student_id=? AND skill_id=?
        AND NOT EXISTS(SELECT 1 FROM learning_observations n WHERE n.supersedes_id=o.id) ORDER BY observed_on DESC,id DESC''',
        (class_id,student_id,skill_id))]


def summaries(db,class_id,student_id):
    cutoff=(datetime.now(timezone.utc).date()-timedelta(days=WINDOW_DAYS)).isoformat()
    result=[]
    for row in db.execute('SELECT * FROM learning_skills WHERE class_id=? AND active=1 ORDER BY code',(class_id,)):
        item=dict(row);observations=current_observations(db,class_id,student_id,item['id'])
        completed=[o for o in observations if o['outcome'] not in MISSING]
        recent=[o for o in completed if o['observed_on']>=cutoff]
        review=db.execute('SELECT * FROM learning_reviews WHERE class_id=? AND student_id=? AND skill_id=? ORDER BY id DESC LIMIT 1',(class_id,student_id,item['id'])).fetchone()
        review=dict(review) if review else None
        flags=[]
        if not recent:flags.append('no_recent_completed_evidence')
        if len({o['method'] for o in recent})<2:flags.append('limited_formats')
        if any(o['outcome'] in MISSING and o['observed_on']>=cutoff for o in observations):flags.append('missing_opportunities')
        outcomes={o['outcome'] for o in recent}
        if 'demonstrated' in outcomes and outcomes & {'developing','incorrect'}:flags.append('mixed_recent_observations')
        if review:
            review['evidence_ids']=json.loads(review['evidence_ids'])
            if review['recorded_at'][:10]<cutoff:flags.append('stale_review')
            cited=[o for o in completed if o['id'] in review['evidence_ids']]
            if cited and all(o['observed_on']<cutoff for o in cited):flags.append('review_uses_old_evidence')
            effective={o['id'] for o in observations}
            if set(review['evidence_ids'])-effective or any(o['recorded_at']>review['recorded_at'] for o in observations):flags.append('evidence_changed_since_review')
        item.update(recent_completed=len(recent),total_completed=len(completed),missing_count=len(observations)-len(completed),
                    formats=len({o['method'] for o in recent}),flags=flags,review=review)
        result.append(item)
    return result


def observation(db,user,class_id,student_id,data):
    exact(data,('skill_id','observed_on','method','outcome','context','observation','source_id','supersedes_id','correction_reason'))
    item=skill(db,class_id,data['skill_id'],False);observed=text(data['observed_on'],10)
    try:
        parsed=date.fromisoformat(observed)
        if parsed.isoformat()!=observed or parsed>datetime.now(timezone.utc).date():raise ValueError()
    except ValueError:raise RequestError(400,'Use an assessment date in YYYY-MM-DD, no later than today.') from None
    if data['method'] not in METHODS or data['outcome'] not in OUTCOMES:raise RequestError(400,'Invalid assessment format or outcome.')
    clean=dict(class_id=class_id,student_id=student_id,skill_id=item['id'],observed_on=observed,method=data['method'],outcome=data['outcome'],
        context=text(data['context'],500),observation=text(data['observation'],2000),source_id=text(data['source_id'],100),
        supersedes_id=number(data['supersedes_id']) if data['supersedes_id'] is not None else None,
        correction_reason=text(data['correction_reason'],1000,optional=data['supersedes_id'] is None))
    existing=db.execute('SELECT * FROM learning_observations WHERE class_id=? AND source_id=?',(class_id,clean['source_id'])).fetchone()
    if existing:
        if any(existing[k]!=v for k,v in clean.items()):raise RequestError(409,'Source ID already identifies different evidence.')
        return dict(existing,replayed=True)
    if not item['active']:raise RequestError(409,'Use the current rubric version for new evidence.')
    if clean['supersedes_id'] is not None:
        prior=db.execute('SELECT * FROM learning_observations WHERE id=? AND class_id=? AND student_id=?',(clean['supersedes_id'],class_id,student_id)).fetchone()
        if not prior or db.execute('SELECT 1 FROM learning_observations WHERE supersedes_id=?',(prior['id'],)).fetchone():raise RequestError(409,'Choose current evidence from this learner to correct.')
    if db.execute('SELECT count(*) FROM learning_observations WHERE class_id=? AND student_id=?',(class_id,student_id)).fetchone()[0]>=MAX_OBSERVATIONS:raise RequestError(413,'Evidence capacity reached. Ask the operator to review storage before adding records.')
    clean.update(recorded_at=now(),actor=user['username'])
    fields=list(clean);cursor=db.execute('INSERT INTO learning_observations('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',[clean[k] for k in fields])
    clean['id']=cursor.lastrowid;history(db,user,class_id,student_id,'observation',clean)
    return dict(clean,replayed=False)


def review(db,user,class_id,student_id,data):
    exact(data,('skill_id','judgment','rationale','evidence_ids','previous_review_id'))
    item=skill(db,class_id,data['skill_id'])
    if db.execute('SELECT count(*) FROM learning_reviews WHERE class_id=? AND student_id=?',(class_id,student_id)).fetchone()[0]>=MAX_REVIEWS:raise RequestError(413,'Review capacity reached. Ask the operator to review storage.')
    if data['judgment'] not in JUDGMENTS:raise RequestError(400,'Choose a formative teacher judgment.')
    ids=data['evidence_ids']
    if not isinstance(ids,list) or len(ids)>20 or any(type(i) is not int or i<1 for i in ids) or len(set(ids))!=len(ids):raise RequestError(400,'Choose at most 20 distinct evidence IDs.')
    available={o['id']:o for o in current_observations(db,class_id,student_id,item['id']) if o['outcome'] not in MISSING}
    if set(ids)-set(available):raise RequestError(409,'Evidence was corrected, missing, or outside this learner and skill.')
    if data['judgment']!='insufficient_evidence' and not ids:raise RequestError(400,'Cite completed observations for this judgment.')
    if data['judgment']=='demonstrated_across_contexts':
        supporting=[available[i] for i in ids if available[i]['outcome']=='demonstrated']
        if len({o['method'] for o in supporting})<2 or len({o['observed_on'] for o in supporting})<2 or len({o['context'] for o in supporting})<2:raise RequestError(400,'This judgment requires demonstrated evidence on two dates, in two formats and contexts.')
    previous=db.execute('SELECT id FROM learning_reviews WHERE class_id=? AND student_id=? AND skill_id=? ORDER BY id DESC LIMIT 1',(class_id,student_id,item['id'])).fetchone()
    expected=previous['id'] if previous else None
    if data['previous_review_id']!=expected or (expected is not None and type(data['previous_review_id']) is not int):raise RequestError(409,'Review changed. Reload before recording a new judgment.')
    record=dict(class_id=class_id,student_id=student_id,skill_id=item['id'],judgment=data['judgment'],rationale=text(data['rationale'],2000),
        evidence_ids=json.dumps(ids),recorded_at=now(),actor=user['username'],previous_review_id=expected)
    fields=list(record);cursor=db.execute('INSERT INTO learning_reviews('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',[record[k] for k in fields])
    record.update(id=cursor.lastrowid,evidence_ids=ids);history(db,user,class_id,student_id,'review',record)
    return record


def coverage(db,class_id):
    cutoff=(datetime.now(timezone.utc).date()-timedelta(days=WINDOW_DAYS)).isoformat()
    students=[];skills=db.execute('SELECT count(*) FROM learning_skills WHERE class_id=? AND active=1',(class_id,)).fetchone()[0]
    for row in db.execute('''SELECT s.id,s.name,s.year FROM students s JOIN learning_enrollments e ON e.student_id=s.id
        WHERE e.class_id=? AND e.active=1 ORDER BY s.name,s.id''',(class_id,)):
        counts=db.execute('''SELECT o.skill_id,o.method,o.outcome,o.observed_on FROM learning_observations o JOIN learning_skills k ON k.id=o.skill_id
            WHERE o.class_id=? AND o.student_id=? AND k.active=1 AND o.observed_on>=?
            AND NOT EXISTS(SELECT 1 FROM learning_observations n WHERE n.supersedes_id=o.id)''',(class_id,row['id'],cutoff)).fetchall()
        done=[r for r in counts if r['outcome'] not in MISSING]
        students.append(dict(row,recent_completed=len(done),skills_with_recent_evidence=len({r['skill_id'] for r in done}),
            missing_count=len(counts)-len(done),formats=len({r['method'] for r in done}),
            open_requests=db.execute("SELECT count(*) FROM learning_reassessments WHERE class_id=? AND student_id=? AND status='Open'",(class_id,row['id'])).fetchone()[0]))
    median=statistics.median([r['recent_completed'] for r in students]) if students else 0
    for row in students:row['fewer_observed_opportunities']=row['recent_completed']<median
    return {'window_days':WINDOW_DAYS,'active_skills':skills,'recent_completed_median':median,'students':students,
            'note':'Observation coverage describes opportunities and data gaps, not ability or a validated fairness score.'}


def route(db,user,method,path,query,data=None):
    db.execute('BEGIN IMMEDIATE' if method=='POST' else 'BEGIN')
    authorize(db,user)
    if method=='POST' and query:raise RequestError(400,'Write operations do not accept query parameters.')
    if path=='/api/learning/teachers' and method=='GET':
        authorize(db,user,True);query_shape(query)
        return [dict(r) for r in db.execute("SELECT username FROM users WHERE role='teacher' AND active=1 ORDER BY username LIMIT 200")]
    if path=='/api/learning/students' and method=='GET':
        authorize(db,user,True);query_shape(query,('search',))
        term=text(query.get('search',[''])[0],100,True).replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
        return [dict(r) for r in db.execute("SELECT id,name,year FROM students WHERE name LIKE ? ESCAPE '\\' ORDER BY name,id LIMIT 50",('%'+term+'%',))]
    if path=='/api/learning/classes':
        if method=='GET':
            query_shape(query)
            return [dict(r) for r in db.execute('SELECT * FROM learning_classes'+(' WHERE teacher=?' if user['role']=='teacher' else '')+' ORDER BY name,id LIMIT 200',([user['username']] if user['role']=='teacher' else []))]
        authorize(db,user,True);mfa.require_recent(user);exact(data,('name','teacher'))
        if db.execute('SELECT count(*) FROM learning_classes').fetchone()[0]>=200:raise RequestError(413,'Use at most 200 classes in this workspace.')
        record={'name':text(data['name'],100),'teacher':teacher(db,data['teacher']),'revision':1}
        record['id']=db.execute('INSERT INTO learning_classes(name,teacher) VALUES(?,?)',(record['name'],record['teacher'])).lastrowid
        history(db,user,record['id'],None,'class',record);return record
    parts=path.strip('/').split('/')
    if len(parts)<5 or parts[:3]!=['api','learning','classes'] or not re.fullmatch('[0-9]{1,18}',parts[3]):raise RequestError(404,'Unknown learning route.')
    class_id=number(int(parts[3]));group=classroom(db,user,class_id);action=parts[4]
    if len(parts)==5 and action=='assignment' and method=='POST':
        authorize(db,user,True);mfa.require_recent(user);exact(data,('teacher','revision'))
        if type(data['revision']) is not int or data['revision']!=group['revision']:raise RequestError(409,'Class assignment changed. Reload before saving.')
        group.update(teacher=teacher(db,data['teacher']),revision=group['revision']+1)
        db.execute('UPDATE learning_classes SET teacher=?,revision=? WHERE id=?',(group['teacher'],group['revision'],class_id))
        history(db,user,class_id,None,'class_assignment',group);return group
    if len(parts)==5 and action=='enrollments':
        if method=='GET':
            query_shape(query)
            return [dict(r) for r in db.execute('''SELECT s.id,s.name,s.year,e.active,e.revision FROM learning_enrollments e JOIN students s ON s.id=e.student_id
                WHERE e.class_id=?'''+(' AND e.active=1' if user['role']=='teacher' else '')+' ORDER BY s.name,s.id',(class_id,))]
        authorize(db,user,True);mfa.require_recent(user);exact(data,('student_id','active','revision'))
        sid=number(data['student_id'])
        if type(data['active']) is not bool or type(data['revision']) is not int:raise RequestError(400,'Use an enrollment state and revision.')
        if not db.execute('SELECT 1 FROM students WHERE id=?',(sid,)).fetchone():raise RequestError(404,'Student not found.')
        prior=db.execute('SELECT * FROM learning_enrollments WHERE class_id=? AND student_id=?',(class_id,sid)).fetchone()
        if data['revision']!=(prior['revision'] if prior else 0):raise RequestError(409,'Enrollment changed. Reload before saving.')
        if not prior and db.execute('SELECT count(*) FROM learning_enrollments WHERE class_id=?',(class_id,)).fetchone()[0]>=200:raise RequestError(413,'Use at most 200 students per class.')
        if prior:
            db.execute('UPDATE learning_enrollments SET active=?,revision=revision+1 WHERE id=?',(int(data['active']),prior['id']));eid=prior['id']
        else:eid=db.execute('INSERT INTO learning_enrollments(class_id,student_id,active) VALUES(?,?,?)',(class_id,sid,int(data['active']))).lastrowid
        record=dict(db.execute('SELECT * FROM learning_enrollments WHERE id=?',(eid,)).fetchone());history(db,user,class_id,sid,'enrollment',record);return record
    if len(parts)==5 and action=='skills':
        if method=='GET':
            query_shape(query);return [dict(r) for r in db.execute('SELECT * FROM learning_skills WHERE class_id=? ORDER BY code,id DESC',(class_id,))]
        mfa.require_recent(user);exact(data,('code','title','rubric_version','criteria'))
        code=text(data['code'],50)
        if not re.fullmatch('[a-z][a-z0-9_.-]{1,49}',code):raise RequestError(400,'Use a skill code with 2–50 lowercase letters, digits, dots, underscores, or hyphens.')
        version=text(data['rubric_version'],40)
        if db.execute('SELECT 1 FROM learning_skills WHERE class_id=? AND code=? AND rubric_version=?',(class_id,code,version)).fetchone():raise RequestError(409,'This rubric version already exists.')
        exists=db.execute('SELECT 1 FROM learning_skills WHERE class_id=? AND code=?',(class_id,code)).fetchone()
        if db.execute('SELECT count(*) FROM learning_skills WHERE class_id=?',(class_id,)).fetchone()[0]>=200 or (not exists and db.execute('SELECT count(*) FROM learning_skills WHERE class_id=? AND active=1',(class_id,)).fetchone()[0]>=30):raise RequestError(413,'Use at most 30 current skills and 200 versions per class.')
        title=text(data['title'],120);criteria=text(data['criteria'],1000)
        db.execute('UPDATE learning_skills SET active=0 WHERE class_id=? AND code=?',(class_id,code))
        kid=db.execute('INSERT INTO learning_skills(class_id,code,title,rubric_version,criteria,active) VALUES(?,?,?,?,?,1)',(class_id,code,title,version,criteria)).lastrowid
        record=dict(db.execute('SELECT * FROM learning_skills WHERE id=?',(kid,)).fetchone());history(db,user,class_id,None,'skill_version',record);return record
    if len(parts)==5 and action=='coverage' and method=='GET':query_shape(query);return coverage(db,class_id)
    if len(parts)<6 or action!='students' or not re.fullmatch('[0-9]{1,18}',parts[5]):raise RequestError(404,'Unknown learning route.')
    sid=number(int(parts[5]));student=learner(db,user,class_id,sid)
    if len(parts)==6 and method=='GET':
        limit,before=page(query)
        rows=[dict(r) for r in db.execute('SELECT * FROM learning_history WHERE class_id=? AND student_id=? AND id<? ORDER BY id DESC LIMIT ?',(class_id,sid,before,limit+1))]
        for row in rows:row['snapshot']=json.loads(row['snapshot'])
        return {'student':student,'class':group,'window_days':WINDOW_DAYS,'skills':summaries(db,class_id,sid),'activity':pack(rows,limit),
                'reassessments':[dict(r) for r in db.execute('SELECT * FROM learning_reassessments WHERE class_id=? AND student_id=? ORDER BY id DESC LIMIT 100',(class_id,sid))]}
    if len(parts)==7 and parts[6]=='observations':
        if method=='GET':
            limit,before=page(query,('skill_id',));params=[class_id,sid,before]
            condition=''
            if 'skill_id' in query:
                try:kid=int(query['skill_id'][0])
                except ValueError:raise RequestError(400,'Invalid skill ID.') from None
                skill(db,class_id,kid,False);condition=' AND o.skill_id=?';params.append(kid)
            rows=[dict(r) for r in db.execute('''SELECT o.*,EXISTS(SELECT 1 FROM learning_observations n WHERE n.supersedes_id=o.id) AS superseded
                FROM learning_observations o WHERE o.class_id=? AND o.student_id=? AND o.id<?'''+condition+' ORDER BY o.id DESC LIMIT ?',params+[limit+1])]
            return pack(rows,limit)
        return observation(db,user,class_id,sid,data)
    if len(parts)==7 and parts[6]=='reviews' and method=='POST':mfa.require_recent(user);return review(db,user,class_id,sid,data)
    if len(parts)==7 and parts[6]=='reassessments' and method=='POST':
        exact(data,('skill_id','reason','student_statement','reported_source'));kid=skill(db,class_id,data['skill_id'])['id']
        if data['reported_source'] not in ('student','guardian','teacher'):raise RequestError(400,'Choose the reported request source.')
        if db.execute('SELECT count(*) FROM learning_reassessments WHERE class_id=? AND student_id=?',(class_id,sid)).fetchone()[0]>=MAX_REQUESTS:raise RequestError(413,'Reassessment capacity reached. Ask the operator to review storage.')
        record=dict(class_id=class_id,student_id=sid,skill_id=kid,reason=text(data['reason'],1000),student_statement=text(data['student_statement'],2000,True),
            reported_source=data['reported_source'],status='Open',revision=1,recorded_at=now(),actor=user['username'])
        fields=list(record);record['id']=db.execute('INSERT INTO learning_reassessments('+','.join(fields)+') VALUES('+','.join('?' for _ in fields)+')',[record[k] for k in fields]).lastrowid
        history(db,user,class_id,sid,'reassessment_opened',record);return record
    if len(parts)==9 and parts[6]=='reassessments' and re.fullmatch('[0-9]{1,18}',parts[7]) and parts[8]=='resolve' and method=='POST':
        mfa.require_recent(user);exact(data,('revision','resolution','observation_id'))
        record=db.execute('SELECT * FROM learning_reassessments WHERE id=? AND class_id=? AND student_id=?',(int(parts[7]),class_id,sid)).fetchone()
        if not record:raise RequestError(404,'Reassessment not found.')
        record=dict(record)
        if type(data['revision']) is not int or data['revision']!=record['revision'] or record['status']!='Open':raise RequestError(409,'Reassessment changed. Reload before resolving.')
        oid=number(data['observation_id']) if data['observation_id'] is not None else None
        if oid is not None and not any(o['id']==oid and o['outcome'] not in MISSING for o in current_observations(db,class_id,sid,record['skill_id'])):raise RequestError(409,'Choose current completed evidence for this reassessment.')
        record.update(status='Resolved',revision=record['revision']+1,resolution=text(data['resolution'],2000),resolved_by=user['username'],observation_id=oid,resolved_at=now())
        db.execute('UPDATE learning_reassessments SET status=?,revision=?,resolution=?,resolved_by=?,observation_id=?,resolved_at=? WHERE id=?',('Resolved',record['revision'],record['resolution'],record['resolved_by'],oid,record['resolved_at'],record['id']))
        history(db,user,class_id,sid,'reassessment_resolved',record);return record
    raise RequestError(404,'Unknown learning route.')
