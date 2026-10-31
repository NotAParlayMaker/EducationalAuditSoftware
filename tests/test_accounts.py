import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import accounts
import app
from security import RequestError


class AccountHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.old_db = app.DB
        app.DB = Path(cls.temp.name) / 'accounts.db'
        app.initialize()
        with app.connect() as db:
            for name, role in [('admin','administrator'),('auditor','auditor'),('owner','remediation_owner'),('reviewer','reviewer')]:
                accounts.create_user(db,name,role,'fictional-password-for-tests')
        cls.server=app.ThreadingHTTPServer(('127.0.0.1',0), app.Handler)
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}/api/'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join()
        app.DB=cls.old_db
        cls.temp.cleanup()

    def setUp(self):
        with app.connect() as db:
            db.execute('DELETE FROM login_budget')
            db.execute('DELETE FROM sessions')
            db.execute('UPDATE users SET active=1')

    def call(self,path,data=None,token='',method=None):
        headers={'Content-Type':'application/json','X-Schooldesk-Request':'1'}
        if token: headers['Authorization']='Bearer '+token
        with urlopen(Request(self.base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers,method=method)) as response:
            return json.load(response)

    def login(self,name):
        return self.call('auth/login',{'username':name,'password':'fictional-password-for-tests'})['token']

    def denied(self,status,*args,**kwargs):
        with self.assertRaises(HTTPError) as caught:
            self.call(*args,**kwargs)
        self.assertEqual(caught.exception.code,status)
        caught.exception.close()

    def test_shared_token_cannot_bypass_account_mode(self):
        with patch.dict(os.environ,{'SCHOOL_ACCESS_TOKEN':'T'*48}):
            self.denied(401,'audits',token='T'*48)
        self.denied(401,'audits')
        self.assertTrue(self.call('auth/status')['accounts_enabled'])

    def test_session_logout_expiry_and_disable(self):
        token=self.login('admin')
        self.assertEqual(self.call('auth/me',token=token)['user']['username'],'admin')
        with app.connect() as db:
            self.assertNotIn(token,repr([tuple(row) for row in db.execute('SELECT * FROM sessions')]))
            db.execute('UPDATE sessions SET expires=0')
        self.denied(401,'audits',token=token)
        token=self.login('admin')
        self.call('auth/logout',{},token=token)
        self.denied(401,'audits',token=token)
        token=self.login('owner')
        with app.connect() as db: db.execute("UPDATE users SET active=0 WHERE username='owner'")
        self.denied(401,'audits',token=token)

    def test_role_access_blocks_student_records_and_writes(self):
        for name in ('auditor','owner','reviewer'):
            token=self.login(name)
            self.denied(403,'students',token=token)
            self.denied(403,'attendance',token=token)
            self.denied(403,'grades',token=token)
            self.denied(403,'assets',{},token=token)
        self.assertIsInstance(self.call('students',token=self.login('admin')),list)

    def test_login_throttling_and_generic_errors(self):
        with app.connect() as db:
            # Prime the budget without performing ten expensive password hashes.
            db.execute('INSERT INTO login_budget VALUES(1,?,10)',(accounts.time.time(),))
        self.denied(429,'auth/login',{'username':'admin','password':'invalid'})
        with app.connect() as db: db.execute('DELETE FROM login_budget')
        for name in ('admin','unknown-user'):
            with self.assertRaises(HTTPError) as caught:
                self.call('auth/login',{'username':name,'password':'incorrect'})
            self.assertEqual(json.load(caught.exception)['error'],'Invalid username or password.')

    def test_authenticated_lifecycle_rejects_forgery(self):
        auditor=self.login('auditor');owner=self.login('owner');reviewer=self.login('reviewer')
        record=self.call('audits',{'area':'Demo','finding':'Review updates','actor':'forged-admin'},token=auditor)
        audit_id=record['id'];path='audits/'+str(audit_id)
        def update(token,**changes):
            nonlocal record
            record=self.call(path,dict(changes,revision=record['revision']),token=token,method='PUT')
        self.denied(403,'audits',{'area':'Demo','finding':'Forged','actor':'admin'},token=owner)
        update(auditor,status='Open',owner='owner',reviewer='reviewer',severity='High',due_date='2026-12-01')
        self.denied(403,path,{'revision':record['revision'],'owner':'admin'},token=owner,method='PUT')
        update(owner,status='In progress',remediation='Review update evidence',actor='reviewer')
        update(owner,status='Awaiting verification',evidence='Fictional report')
        self.denied(403,path,{'revision':record['revision'],'status':'Closed','actor':'reviewer','verification':'Checked','closure_reason':'Done'},token=owner,method='PUT')
        self.denied(403,path,{'revision':record['revision'],'status':'Closed','actor':'reviewer','verification':'Checked','closure_reason':'Done'},token=auditor,method='PUT')
        update(reviewer,status='Closed',verification='Evidence independently checked',closure_reason='Verified',actor='owner')
        history=self.call(path+'/history',token=auditor)
        self.assertEqual(history[0]['actor'],'auditor')
        self.assertEqual(history[2]['actor'],'owner')
        self.assertEqual(history[-1]['actor'],'reviewer')
        update(auditor,status='Open',reopen_reason='New evidence')
        self.assertEqual(record['verification'],'')

    def test_accounts_never_fall_back_when_users_disabled(self):
        with app.connect() as db:
            db.execute('UPDATE users SET active=0')
            self.assertTrue(accounts.enabled(db))
        self.denied(401,'audits')

    def test_invalid_assignments_and_password_storage(self):
        token=self.login('auditor')
        self.denied(400,'audits',{'area':'Demo','finding':'Demo finding','owner':'unknown','actor':'admin'},token=token)
        with app.connect() as db:
            row=db.execute("SELECT * FROM users WHERE username='admin'").fetchone()
            self.assertNotEqual(row['password_hash'],'fictional-password-for-tests')
            self.assertEqual(len(row['salt']),32)
            self.assertEqual(len(row['password_hash']),64)
