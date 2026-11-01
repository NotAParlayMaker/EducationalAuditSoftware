import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch

import accounts
import app
import test_accounts


class AssignedRecordHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_accounts.AccountHTTPTest.setUpClass.__func__(cls)
        with app.connect() as db:
            accounts.create_user(db,'other-owner','remediation_owner','fictional-password-for-tests')
            accounts.create_user(db,'other-reviewer','reviewer','fictional-password-for-tests')

    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    setUp=test_accounts.AccountHTTPTest.setUp
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def setUp(self):
        test_accounts.AccountHTTPTest.setUp(self)
        with app.connect() as db:
            db.execute('DELETE FROM audit_evidence');db.execute('DELETE FROM audit_history');db.execute('DELETE FROM audits')
        self.auditor=self.login('auditor');self.owner=self.login('owner');self.reviewer=self.login('reviewer')
        self.mine=self.call('audits',{'area':'Assigned','finding':'MY-FINDING','owner':'owner','reviewer':'reviewer','severity':'Low','due_date':'2020-01-01'},token=self.auditor)
        self.other=self.call('audits',{'area':'OTHER-AREA','finding':'OTHER-PRIVATE-FINDING','owner':'other-owner','reviewer':'other-reviewer','severity':'Critical','due_date':'2020-01-01'},token=self.auditor)
        self.unassigned=self.call('audits',{'area':'Unassigned','finding':'UNASSIGNED-PRIVATE-FINDING'},token=self.auditor)

    def test_list_filters_pagination_counts_and_directory_are_scoped(self):
        for token in (self.owner,self.reviewer):
            listing=self.call('audits?limit=100',token=token)
            self.assertEqual([row['id'] for row in listing],[self.mine['id']])
            self.assertEqual(self.call('audits?owner=other-owner',token=token),[])
            self.assertEqual(self.call('audits?severity=Critical',token=token),[])
            self.assertEqual(self.call('audits?offset=1&limit=1',token=token),[])
            summary=self.call('summary',token=token)
            self.assertEqual(summary['audits'],1);self.assertEqual(summary['overdue_audits'],1)
            self.assertEqual(summary['audit_severity'],{'Low':1})
            for key in ('students','attendance','grades','assets','tickets'):self.assertNotIn(key,summary)
            directory=self.call('users',token=token)
            self.assertEqual({row['username'] for row in directory},{'owner','reviewer'})
            payload=json.dumps({'list':listing,'summary':summary,'directory':directory})
            self.assertNotIn('OTHER-',payload);self.assertNotIn('other-owner',payload)
        self.assertEqual(len(self.call('audits',token=self.auditor)),3)

    def test_history_evidence_and_mutations_reject_unassigned_and_unknown_ids(self):
        for token in (self.owner,self.reviewer):
            for audit_id in (self.other['id'],self.unassigned['id'],999999):
                path='audits/'+str(audit_id)
                self.denied(404,path+'/history',token=token)
                self.denied(404,path+'/evidence',token=token)
                self.denied(404,path,{'revision':1,'finding':'Unauthorized change'},token=token,method='PUT')
                self.denied(404,path+'/evidence',{'filename':'note.txt','content_base64':'eA=='},token=token)
            self.assertTrue(self.call('audits/'+str(self.mine['id'])+'/history',token=token))

    def test_attachment_download_rechecks_parent_assignment(self):
        payload={'filename':'PRIVATE-FILENAME.txt','content_base64':base64.b64encode(b'PRIVATE-ATTACHMENT').decode()}
        attachment=self.call('audits/'+str(self.other['id'])+'/evidence',payload,token=self.auditor)
        for token in (self.owner,self.reviewer):self.denied(404,'evidence/'+str(attachment['id']),token=token)
        own=self.call('audits/'+str(self.mine['id'])+'/evidence',payload,token=self.owner)
        with app.connect() as db:revision=db.execute('SELECT revision FROM audits WHERE id=?',(self.mine['id'],)).fetchone()[0]
        updated=self.call('audits/'+str(self.mine['id']),{'revision':revision,'owner':'other-owner','reviewer':'other-reviewer'},token=self.auditor,method='PUT')
        for token in (self.owner,self.reviewer):
            self.denied(404,'evidence/'+str(own['id']),token=token)
            self.denied(404,'audits/'+str(self.mine['id'])+'/history',token=token)
            self.denied(404,'audits/'+str(self.mine['id']),{'revision':updated['revision'],'remediation':'Unauthorized after reassignment'},token=token,method='PUT')
            self.assertEqual(self.call('audits',token=token),[])
        new_owner=self.login('other-owner')
        request=Request(self.base+'evidence/'+str(own['id']),headers={'Authorization':'Bearer '+new_owner})
        with urlopen(request) as response:self.assertEqual(response.read(),b'PRIVATE-ATTACHMENT')

    def test_other_it_resources_are_not_exposed_to_assignee_roles(self):
        for token in (self.owner,self.reviewer):
            for resource in ('assets','tickets','students','attendance','grades'):
                self.denied(403,resource,token=token)
        self.assertIsInstance(self.call('assets',token=self.auditor),list)
        self.assertEqual(self.call('work-queue',token=self.owner)['total'],0)  # Draft is visible but not remediation work.

    def test_explicit_demo_flag_cannot_bypass_provisioned_accounts(self):
        self.server.allow_demo=True
        try:self.denied(401,'audits')
        finally:self.server.allow_demo=False


class ExplicitDemoHTTPTest(unittest.TestCase):
    def test_arbitrary_server_is_closed_unless_demo_explicitly_enabled(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'demo.db'):
            app.initialize()
            server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            base=f'http://127.0.0.1:{server.server_port}'
            try:
                with self.assertRaises(HTTPError) as caught:urlopen(base+'/api/audits')
                self.assertEqual(caught.exception.code,503);caught.exception.close()
                with urlopen(base+'/api/auth/status') as response:self.assertFalse(json.load(response)['demo_enabled'])
                server.allow_demo=True
                with self.assertRaises(HTTPError) as missing:urlopen(base+'/api/audits')
                self.assertEqual(missing.exception.code,401);missing.exception.close()
                with urlopen(Request(base+'/api/audits',headers={'Authorization':'Bearer '+server.demo_token})) as response:self.assertEqual(json.load(response),[])
                with urlopen(base+'/api/auth/status') as response:self.assertTrue(json.load(response)['demo_enabled'])
            finally:server.shutdown();server.server_close();thread.join()

    def test_legacy_app_entry_point_requires_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            environment=dict(os.environ,SCHOOL_DB=str(Path(directory)/'new.db'))
            result=subprocess.run([sys.executable,str(Path(app.__file__).resolve())],env=environment,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,1)
        self.assertIn('init first',result.stderr)
        self.assertNotIn('Traceback',result.stderr)
