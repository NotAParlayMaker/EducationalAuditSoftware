from datetime import datetime,timedelta,timezone
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import accounts
import app
import integrity_anchor
import learning
import maintenance
import security_events
import security
import test_accounts


class LearningHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_accounts.AccountHTTPTest.setUpClass.__func__(cls)
        with app.connect() as db:
            accounts.create_user(db,'teacher-one','teacher','fictional-password-for-tests')
            accounts.create_user(db,'teacher-two','teacher','fictional-password-for-tests')
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def setUp(self):
        test_accounts.AccountHTTPTest.setUp(self)
        with app.connect() as db:
            for table in reversed(learning.TABLES):db.execute('DELETE FROM '+table)
            db.execute('DELETE FROM students')
        self.registrar=self.login('registrar');self.first=self.login('teacher-one');self.second=self.login('teacher-two')
        self.one=self.call('students',{'name':'Fictional one','year':'8','guardian':'PRIVATE-GUARDIAN'},token=self.registrar)
        self.two=self.call('students',{'name':'Fictional two','year':'8','guardian':'PRIVATE-GUARDIAN'},token=self.registrar)
        self.group=self.call('learning/classes',{'name':'Ecosystems','teacher':'teacher-one'},token=self.registrar)
        self.other=self.call('learning/classes',{'name':'Other class','teacher':'teacher-two'},token=self.registrar)
        self.root='learning/classes/'+str(self.group['id'])
        for student in (self.one,self.two):self.call(self.root+'/enrollments',{'student_id':student['id'],'active':True,'revision':0},token=self.registrar)
        self.path=self.root+'/students/'+str(self.one['id'])
        self.skill=self.call(self.root+'/skills',{'code':'food-web','title':'Food-web reasoning','rubric_version':'1','criteria':'Explain a causal chain and justify a prediction.'},token=self.first)

    def source(self,**changes):
        result={'skill_id':self.skill['id'],'observed_on':datetime.now(timezone.utc).date().isoformat(),'method':'written','outcome':'demonstrated',
            'context':'Fictional forest food web','observation':'Explained the predator-prey chain.','source_id':'source-one','supersedes_id':None,'correction_reason':''}
        result.update(changes);return result

    def evidence(self,**changes):return self.call(self.path+'/observations',self.source(**changes),token=self.first)

    def review(self,ids,**changes):
        data={'skill_id':self.skill['id'],'judgment':'developing','rationale':'Human review; further transfer evidence needed.','evidence_ids':ids,'previous_review_id':None}
        data.update(changes);return data

    def test_roles_assignment_and_enrollment_bound_every_learning_read_and_write(self):
        for name in ('admin','auditor','owner','reviewer'):
            token=self.login(name)
            for path in ('learning/classes',self.path,self.root+'/coverage','learning/students'):
                self.denied(403,path,token=token)
            self.denied(403,self.path+'/observations',self.source(),token=token)
        self.assertEqual([r['id'] for r in self.call('learning/classes',token=self.first)],[self.group['id']])
        for path in (self.root+'/enrollments',self.path,self.path+'/observations',self.root+'/coverage'):
            self.denied(404,path,token=self.second)
        self.denied(404,self.path+'/observations',self.source(),token=self.second)
        self.denied(403,'students',token=self.first)
        self.denied(403,'learning/students',token=self.first)
        self.denied(403,self.root+'/enrollments',{'student_id':self.one['id'],'active':False,'revision':1},token=self.first)
        self.denied(403,self.root+'/assignment',{'teacher':'teacher-two','revision':1},token=self.first)
        payload=json.dumps(self.call(self.path,token=self.first))
        self.assertNotIn('PRIVATE-GUARDIAN',payload)
        self.call(self.root+'/enrollments',{'student_id':self.one['id'],'active':False,'revision':1},token=self.registrar)
        self.denied(404,self.path,token=self.first)
        self.denied(404,self.path+'/observations',self.source(),token=self.first)
        self.assertEqual(len(self.call(self.root+'/coverage',token=self.first)['students']),1)
        self.assertEqual(self.call(self.path,token=self.registrar)['student']['active'],0)

    def test_transfer_revokes_old_teacher_and_keeps_history_for_new_teacher(self):
        self.evidence()
        self.call(self.root+'/assignment',{'teacher':'teacher-two','revision':1},token=self.registrar)
        self.denied(404,self.path,token=self.first)
        self.denied(404,self.path+'/observations',self.source(source_id='blocked'),token=self.first)
        data=self.call(self.path,token=self.second)
        self.assertIn('teacher-one',json.dumps(data['activity']))
        self.denied(409,self.root+'/assignment',{'teacher':'teacher-one','revision':1},token=self.registrar)

    def test_assignment_change_after_session_guard_is_rechecked_before_write(self):
        original=security.read_json
        def transfer(handler,*args,**kwargs):
            data=original(handler,*args,**kwargs)
            if handler.path=='/api/'+self.path+'/observations':
                with app.connect() as db:db.execute('UPDATE learning_classes SET teacher=?,revision=revision+1 WHERE id=?',('teacher-two',self.group['id']))
            return data
        with patch('app.security.read_json',side_effect=transfer):
            self.denied(404,self.path+'/observations',self.source(),token=self.first)
        with app.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM learning_observations').fetchone()[0],0)

    def test_same_named_students_keep_distinct_learning_records(self):
        with app.connect() as db:db.execute('UPDATE students SET name=?',('Same fictional name',))
        other=self.root+'/students/'+str(self.two['id'])
        self.call(other+'/observations',self.source(),token=self.first)
        self.assertEqual(self.call(self.path,token=self.first)['skills'][0]['total_completed'],0)
        self.assertEqual(self.call(other,token=self.first)['skills'][0]['total_completed'],1)

    def test_idempotent_source_and_append_only_correction_preserve_original(self):
        original=self.evidence();same=self.evidence()
        self.assertTrue(same['replayed']);self.assertEqual(same['id'],original['id'])
        self.denied(409,self.path+'/observations',self.source(observation='Different content'),token=self.first)
        corrected=self.evidence(source_id='correction',supersedes_id=original['id'],correction_reason='Transcription correction',observation='Accurately captured explanation.')
        rows=self.call(self.path+'/observations',token=self.first)['rows']
        self.assertEqual(len(rows),2);self.assertEqual(next(r for r in rows if r['id']==original['id'])['superseded'],1)
        self.assertEqual(next(r for r in rows if r['id']==original['id'])['observation'],original['observation'])
        self.assertEqual(self.call(self.path,token=self.first)['skills'][0]['total_completed'],1)
        self.denied(409,self.path+'/observations',self.source(source_id='second-correction',supersedes_id=original['id'],correction_reason='Conflict'),token=self.first)
        self.denied(409,self.path+'/reviews',self.review([original['id']]),token=self.first)
        self.call(self.path+'/reviews',self.review([corrected['id']]),token=self.first)
        self.denied(404,self.path+'/observations/'+str(original['id']),{},token=self.first,method='PUT')

    def test_missing_observations_are_not_failures_or_review_support(self):
        missing=self.evidence(outcome='inaccessible',observation='Task could not be accessed in this format.')
        data=self.call(self.path,token=self.first);summary=data['skills'][0]
        self.assertEqual((summary['total_completed'],summary['missing_count']),(0,1))
        self.assertIn('no_recent_completed_evidence',summary['flags'])
        self.denied(409,self.path+'/reviews',self.review([missing['id']]),token=self.first)
        self.call(self.path+'/reviews',self.review([],judgment='insufficient_evidence'),token=self.first)
        report=self.call(self.root+'/coverage',token=self.first)
        row=next(r for r in report['students'] if r['id']==self.one['id'])
        self.assertEqual((row['recent_completed'],row['missing_count']),(0,1))
        self.assertEqual(len(report['students']),2)

    def test_recent_evidence_staleness_and_mixed_results_are_explicit(self):
        old=(datetime.now(timezone.utc).date()-timedelta(days=60)).isoformat()
        original=self.evidence(observed_on=old)
        review=self.call(self.path+'/reviews',self.review([original['id']]),token=self.first)
        summary=self.call(self.path,token=self.first)['skills'][0]
        self.assertEqual(summary['recent_completed'],0);self.assertIn('review_uses_old_evidence',summary['flags'])
        self.evidence(source_id='new',outcome='incorrect',context='New transfer context')
        self.evidence(source_id='another',method='oral')
        summary=self.call(self.path,token=self.first)['skills'][0]
        self.assertIn('mixed_recent_observations',summary['flags']);self.assertIn('evidence_changed_since_review',summary['flags'])
        self.assertEqual(summary['review']['id'],review['id'])

    def test_old_missing_opportunity_remains_history_without_a_permanent_recent_flag(self):
        old=(datetime.now(timezone.utc).date()-timedelta(days=60)).isoformat()
        self.evidence(observed_on=old,outcome='absent')
        self.evidence(source_id='current-opportunity')
        data=self.call(self.path,token=self.first)
        self.assertNotIn('missing_opportunities',data['skills'][0]['flags'])
        self.assertEqual(data['skills'][0]['missing_count'],1)
        self.assertIn('absent',json.dumps(data['activity']))

    def test_demonstration_review_requires_varied_evidence_and_revision(self):
        one=self.evidence()
        self.denied(400,self.path+'/reviews',self.review([one['id']],judgment='demonstrated_across_contexts'),token=self.first)
        yesterday=(datetime.now(timezone.utc).date()-timedelta(days=1)).isoformat()
        two=self.evidence(source_id='transfer',observed_on=yesterday,method='transfer',context='Fictional pond with unfamiliar population data')
        reviewed=self.call(self.path+'/reviews',self.review([one['id'],two['id']],judgment='demonstrated_across_contexts'),token=self.first)
        self.denied(409,self.path+'/reviews',self.review([one['id']]),token=self.first)
        revised=self.call(self.path+'/reviews',self.review([one['id']],previous_review_id=reviewed['id'],judgment='developing'),token=self.first)
        data=self.call(self.path,token=self.first)
        self.assertEqual(data['skills'][0]['review']['id'],revised['id'])
        self.assertEqual(sum(e['kind']=='review' for e in data['activity']['rows']),2)

    def test_rubric_versions_do_not_mix_evidence_or_rewrite_judgments(self):
        evidence=self.evidence();self.call(self.path+'/reviews',self.review([evidence['id']]),token=self.first)
        new=self.call(self.root+'/skills',{'code':'food-web','title':'Food-web reasoning','rubric_version':'2','criteria':'Include competing explanations.'},token=self.first)
        summary=self.call(self.path,token=self.first)['skills']
        self.assertEqual(len(summary),1);self.assertEqual(summary[0]['id'],new['id']);self.assertIsNone(summary[0]['review'])
        self.assertEqual(summary[0]['total_completed'],0)
        self.assertTrue(self.evidence()['replayed'])
        self.denied(409,self.path+'/observations',self.source(source_id='old-version-new-evidence'),token=self.first)
        self.denied(404,self.path+'/reviews',self.review([evidence['id']]),token=self.first)

    def test_reassessment_opens_resolves_and_rejects_stale_resolution(self):
        request=self.call(self.path+'/reassessments',{'skill_id':self.skill['id'],'reason':'Offer an accessible oral task','student_statement':'I can explain the chain orally.','reported_source':'student'},token=self.first)
        row=next(r for r in self.call(self.root+'/coverage',token=self.first)['students'] if r['id']==self.one['id']);self.assertEqual(row['open_requests'],1)
        evidence=self.evidence(method='oral')
        other=self.call(self.root+'/students/'+str(self.two['id'])+'/observations',self.source(source_id='other-request-student'),token=self.first)
        self.denied(409,self.path+'/reassessments/'+str(request['id'])+'/resolve',{'revision':1,'resolution':'Invalid link','observation_id':other['id']},token=self.first)
        payload={'revision':1,'resolution':'Completed oral explanation; review evidence next.','observation_id':evidence['id']}
        resolved=self.call(self.path+'/reassessments/'+str(request['id'])+'/resolve',payload,token=self.first)
        self.assertEqual(resolved['status'],'Resolved');self.assertTrue(resolved['resolved_at'])
        self.denied(409,self.path+'/reassessments/'+str(request['id'])+'/resolve',payload,token=self.first)
        activity=self.call(self.path,token=self.first)['activity']['rows']
        self.assertIn('reassessment_opened',{r['kind'] for r in activity});self.assertIn('reassessment_resolved',{r['kind'] for r in activity})

    def test_dates_queries_cross_student_links_and_actor_injection_fail_closed(self):
        future=(datetime.now(timezone.utc).date()+timedelta(days=1)).isoformat()
        self.denied(400,self.path+'/observations',self.source(observed_on=future),token=self.first)
        self.denied(400,self.path+'/observations',dict(self.source(),actor='registrar'),token=self.first)
        other_path=self.root+'/students/'+str(self.two['id'])
        other=self.call(other_path+'/observations',self.source(source_id='other-student'),token=self.first)
        self.denied(409,self.path+'/reviews',self.review([other['id']]),token=self.first)
        self.denied(409,self.path+'/observations',self.source(supersedes_id=other['id'],correction_reason='Invalid cross-student correction'),token=self.first)
        for suffix in ('?limit=101','?limit=2&limit=3','?before_id=-1','?unknown=1'):self.denied(400,self.path+suffix,token=self.first)

    def test_fresh_auth_and_capacity_checks_preserve_existing_records(self):
        self.evidence()
        with patch('learning.MAX_OBSERVATIONS',1):self.denied(413,self.path+'/observations',self.source(source_id='exceeds-capacity'),token=self.first)
        with app.connect() as db:db.execute("UPDATE sessions SET auth_time=0 WHERE username='teacher-one'")
        self.denied(428,self.path+'/reviews',self.review([]),token=self.first)
        self.assertEqual(len(self.call(self.path+'/observations',token=self.first)['rows']),1)

    def test_activity_pagination_security_feed_privacy_and_recovery_anchor_coverage(self):
        self.evidence()
        first=self.call(self.path+'?limit=1',token=self.first)
        second=self.call(self.path+'?limit=1&before_id='+str(first['activity']['next_before_id']),token=self.first)
        self.assertNotEqual(first['activity']['rows'][0]['id'],second['activity']['rows'][0]['id'])
        with app.connect() as db:
            self.assertTrue(security_events.verify(db)['valid'])
            events=[dict(r) for r in db.execute("SELECT * FROM security_events WHERE event='learning_recorded'")]
            self.assertNotIn('Fictional',json.dumps(events));self.assertNotIn('predator',json.dumps(events))
            bundle=integrity_anchor.create(db)
        self.assertEqual(bundle['format'],'schooldesk.anchor.v2')
        with tempfile.TemporaryDirectory() as folder:
            destination=Path(folder)/'recovery.db';maintenance.copy_database(app.DB,destination)
            with maintenance.readonly(destination) as db:self.assertTrue(integrity_anchor.verify(db,bundle)['valid'])
        with app.connect() as db:
            checked=security_events.verify(db);nonce='a'*64
            old={'format':'schooldesk.anchor.v1','nonce':nonce,'checkpoint':{'count':checked['count'],'head':checked['head']},'dataset':integrity_anchor.data_root(db,nonce)}
            old['commitment']=integrity_anchor.commitment(old)
            self.assertTrue(integrity_anchor.verify(db,old)['valid'])
            self.assertFalse(integrity_anchor.verify(db,old)['learning_records_covered'])
            db.execute("UPDATE learning_observations SET observation='tampered'")
            self.assertFalse(integrity_anchor.verify(db,bundle)['valid'])
