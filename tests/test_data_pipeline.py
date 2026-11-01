import json
import sqlite3
import unittest
from unittest.mock import patch

import app
import data_pipeline as pipeline
import test_accounts


class PipelineHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_accounts.AccountHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def setUp(self):
        test_accounts.AccountHTTPTest.setUp(self)
        with app.connect() as db:
            for table in ('pipeline_items','pipeline_batches','audit_evidence','audit_history',*app.SCHEMAS):db.execute('DELETE FROM '+table)
        self.admin=self.login('admin');self.auditor=self.login('auditor');self.owner=self.login('owner')

    def source(self,resource,rows):return {'schema_version':1,'resource':resource,'format':'json','rows':rows}

    def preview(self,source,token=None):return self.call('pipeline/preview',source,token=token or self.admin)

    def commit(self,source,preview,token=None):
        return self.call('pipeline/commit',{'source':source,'batch_id':preview['batch_id'],'digest':preview['digest']},token=token or self.admin)

    def test_preview_commit_deduplication_and_retry(self):
        row={'tag':' DEMO-1 ','device':'Laptop','location':'Library','status':'Available'}
        source=self.source('assets',[row,row])
        preview=self.preview(source)
        self.assertEqual(preview['would_insert'],1);self.assertEqual(preview['duplicates'],1)
        self.assertEqual(preview['normalized_rows'][0]['tag'],'DEMO-1')
        self.assertEqual(self.call('assets',token=self.admin),[])
        result=self.commit(source,preview)
        self.assertEqual((result['inserted'],result['skipped']),(1,1))
        self.assertTrue(self.commit(source,preview)['replayed'])
        second=self.preview(source);self.assertEqual(second['would_insert'],0)
        self.assertEqual(self.commit(source,second)['inserted'],0)
        self.assertEqual(len(self.call('assets',token=self.admin)),1)

    def test_new_batch_of_old_source_does_not_overwrite_later_edits(self):
        source=self.source('audits',[{'area':'Demo','finding':'Original concern'}])
        preview=self.preview(source,self.auditor);self.commit(source,preview,self.auditor)
        record=self.call('audits',token=self.auditor)[0]
        self.call('audits/'+str(record['id']),{'revision':record['revision'],'finding':'Reviewed correction'},token=self.auditor,method='PUT')
        second=self.preview(source,self.auditor)
        self.assertEqual(self.commit(source,second,self.auditor)['inserted'],0)
        self.assertEqual(self.call('audits',token=self.auditor)[0]['finding'],'Reviewed correction')

    def test_separately_prepared_batches_recheck_duplicates_at_commit(self):
        source=self.source('audits',[{'area':'Demo','finding':'Shared source concern'}])
        first=self.preview(source,self.auditor);second=self.preview(source,self.admin)
        self.assertNotEqual(first['batch_id'],second['batch_id'])
        self.assertEqual(second['would_insert'],1)
        self.assertEqual(self.commit(source,first,self.auditor)['inserted'],1)
        result=self.commit(source,second,self.admin)
        self.assertEqual((result['inserted'],result['skipped']),(0,1))
        self.assertEqual(len(self.call('audits',token=self.auditor)),1)
        jobs=self.call('pipeline/batches',token=self.auditor)
        self.assertEqual([job['id'] for job in jobs],[first['batch_id']])

    def test_invalid_rows_report_positions_without_values_and_write_nothing(self):
        source=self.source('students',[{'name':'Fictional student','year':'8','guardian':'Fictional guardian'}, {'name':'PRIVATE-REJECTED-VALUE'}])
        result=self.preview(source)
        self.assertFalse(result['valid']);self.assertEqual(result['errors'],[{'row':2,'code':'invalid_record'}])
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn('batch_id',result)
        self.assertEqual(self.call('students',token=self.admin),[])
        self.assertEqual(self.call('pipeline/batches',token=self.admin),[])

    def test_changed_source_expiry_and_batch_ownership_are_enforced(self):
        source=self.source('audits',[{'area':'Demo','finding':'Fictional concern'}])
        preview=self.preview(source,self.auditor)
        changed=self.source('audits',[{'area':'Demo','finding':'Different concern'}])
        self.denied(409,'pipeline/commit',{'source':changed,'batch_id':preview['batch_id'],'digest':preview['digest']},token=self.auditor)
        self.denied(404,'pipeline/commit',{'source':source,'batch_id':preview['batch_id'],'digest':preview['digest']},token=self.admin)
        with app.connect() as db:db.execute('UPDATE pipeline_batches SET expires_at=0')
        self.denied(409,'pipeline/commit',{'source':source,'batch_id':preview['batch_id'],'digest':preview['digest']},token=self.auditor)
        self.assertEqual(self.call('audits',token=self.auditor),[])

    def test_imports_do_not_grant_privileged_audit_state(self):
        self.denied(403,'pipeline/preview',self.source('audits',[{'area':'Demo','finding':'Concern'}]),token=self.owner)
        self.denied(403,'pipeline/preview',self.source('students',[{'name':'Demo','year':'8','guardian':'Demo'}]),token=self.auditor)
        for extra in ({'status':'Closed'},{'actor':'admin'},{'verification':'verified'},{'revision':'1'}):
            result=self.preview(self.source('audits',[dict(area='Demo',finding='Concern',**extra)]),self.auditor)
            self.assertFalse(result['valid'])
        source=self.source('audits',[{'area':'Demo','finding':'Concern','owner':'owner','reviewer':'reviewer'}])
        preview=self.preview(source,self.auditor);self.commit(source,preview,self.auditor)
        rows=self.call('audits',token=self.owner);self.assertEqual(rows[0]['status'],'Draft')
        history=self.call('audits/'+str(rows[0]['id'])+'/history',token=self.auditor)
        self.assertEqual(history[0]['actor'],'auditor')

    def test_database_failure_rolls_back_entire_batch_and_history(self):
        source=self.source('audits',[{'area':'Demo','finding':'First'},{'area':'Demo','finding':'Second'}])
        preview=self.preview(source,self.auditor)
        original=pipeline.audit_workflow.save;calls=[]
        def fail_second(db,data):
            calls.append(1)
            if len(calls)==2:raise sqlite3.OperationalError('PRIVATE-DATABASE-DETAIL')
            return original(db,data)
        with patch('data_pipeline.audit_workflow.save',side_effect=fail_second):
            self.denied(503,'pipeline/commit',{'source':source,'batch_id':preview['batch_id'],'digest':preview['digest']},token=self.auditor)
        self.assertEqual(self.call('audits',token=self.auditor),[])
        with app.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM audit_history').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM pipeline_items').fetchone()[0],0)
        self.assertEqual(self.commit(source,preview,self.auditor)['inserted'],2)

    def test_csv_json_parsing_and_version_limits(self):
        source={'schema_version':1,'resource':'assets','format':'csv','data':'\ufefftag,device,location,status\r\nDEMO-1,"Laptop, test",Library,Available\r\n'}
        result=self.preview(source);self.assertTrue(result['valid']);self.assertEqual(result['normalized_rows'][0]['device'],'Laptop, test')
        for text in ('tag,tag\nx,y\n','tag,device,location,status\nx,y,z,Available,EXTRA\n'):
            self.denied(400,'pipeline/preview',dict(source,data=text),token=self.admin)
        for text in ('[{"tag":"x","tag":"y"}]','[NaN]','{broken'):
            self.denied(400,'pipeline/preview',{'schema_version':1,'resource':'assets','format':'json','data':text},token=self.admin)
        self.denied(400,'pipeline/preview',dict(source,schema_version=2),token=self.admin)
        self.denied(400,'pipeline/preview',self.source('assets',[{}]*201),token=self.admin)

    def test_export_preserves_assignment_scope_and_cursor_and_safe_csv(self):
        for owner,finding in [('owner','=SUM(1,1)'),('admin','PRIVATE-OTHER-FINDING'),('owner','Next authorized')]:
            self.call('audits',{'area':'Demo','finding':finding,'owner':owner},token=self.auditor)
        first=self.call('pipeline/export',{'resource':'audits','format':'csv','after_id':0,'limit':1},token=self.owner)
        self.assertEqual(len(first['rows']),1);self.assertTrue(first['has_more'])
        self.assertIn("'=SUM",first['csv']);self.assertNotIn('PRIVATE-OTHER',json.dumps(first))
        second=self.call('pipeline/export',{'resource':'audits','format':'json','after_id':first['next_after_id'],'limit':1},token=self.owner)
        self.assertEqual(second['rows'][0]['finding'],'Next authorized');self.assertFalse(second['has_more'])
        self.denied(403,'pipeline/export',{'resource':'students','format':'json','after_id':0,'limit':10},token=self.owner)
        self.denied(400,'pipeline/export',{'resource':[],'format':'json','after_id':0,'limit':10},token=self.admin)

    def test_commit_revalidates_assignments_after_preview(self):
        source=self.source('audits',[{'area':'Demo','finding':'Concern','owner':'owner'}])
        preview=self.preview(source,self.auditor)
        with app.connect() as db:db.execute("UPDATE users SET active=0 WHERE username='owner'")
        self.denied(400,'pipeline/commit',{'source':source,'batch_id':preview['batch_id'],'digest':preview['digest']},token=self.auditor)
        self.assertEqual(self.call('audits',token=self.auditor),[])
