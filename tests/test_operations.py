import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen

import app
import maintenance
import operations
import test_accounts
from security import RequestError


class OperationsHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_accounts.AccountHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    setUp=test_accounts.AccountHTTPTest.setUp
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def draft(self,token):
        return self.call('audits',{'area':'Fictional library','finding':'Review updates','owner':'owner','reviewer':'reviewer','severity':'High'},token=token)

    def test_evidence_authorization_integrity_and_download_headers(self):
        token=self.login('auditor');owner=self.login('owner');reviewer=self.login('reviewer')
        record=self.draft(token);path='audits/'+str(record['id'])+'/evidence'
        content=b'Fictional inspection evidence.'
        payload={'filename':'inspection.txt','content_base64':base64.b64encode(content).decode()}
        self.denied(401,path,payload)
        self.denied(403,path,payload,token=reviewer)
        saved=self.call(path,payload,token=owner)
        self.assertEqual(saved['sha256'],hashlib.sha256(content).hexdigest())
        self.assertEqual(saved['audit_revision'],record['revision']+1)
        self.denied(409,'audits/'+str(record['id']),{'revision':record['revision'],'finding':'Stale before attachment'},token=token,method='PUT')
        listing=self.call(path,token=reviewer)
        self.assertNotIn('content',listing[0])
        request=Request(self.base+'evidence/'+str(saved['id']),headers={'Authorization':'Bearer '+reviewer})
        with urlopen(request) as response:
            self.assertEqual(response.read(),content)
            self.assertEqual(response.headers['Content-Type'],'application/octet-stream')
            self.assertIn('attachment;',response.headers['Content-Disposition'])
        with app.connect() as db:
            db.execute('UPDATE audit_evidence SET content=? WHERE id=?',(b'tampered',saved['id']))
        self.denied(409,'evidence/'+str(saved['id']),token=reviewer)

    def test_evidence_limits_types_paths_and_closed_findings(self):
        token=self.login('auditor');record=self.draft(token);path='audits/'+str(record['id'])+'/evidence'
        for name,content in [('../private.txt',b'x'),('script.html',b'<script>'),('fake.pdf',b'not PDF'),('binary.txt',b'\x00'),('huge.txt',b'x'*262145)]:
            with self.subTest(name=name):
                self.denied(413 if name=='huge.txt' else 400,path,{'filename':name,'content_base64':base64.b64encode(content).decode()},token=token)
        with app.connect() as db:db.execute("UPDATE audits SET status='Closed' WHERE id=?",(record['id'],))
        self.denied(409,path,{'filename':'note.txt','content_base64':'eA=='},token=token)

    def test_pagination_filters_and_role_safe_summary(self):
        token=self.login('auditor')
        for index in range(53):
            self.call('audits',{'area':'Pagination case','finding':str(index),'owner':'owner','reviewer':'reviewer','severity':'High'},token=token)
        page=self.call('audits?owner=owner&severity=High&status=Draft&limit=50',token=token)
        next_page=self.call('audits?owner=owner&severity=High&status=Draft&limit=50&offset=50',token=token)
        self.assertEqual(len(page),50)
        self.assertGreaterEqual(len(next_page),3)
        self.assertFalse({row['id'] for row in page}&{row['id'] for row in next_page})
        self.denied(400,'audits?limit=1000',token=token)
        self.denied(400,'audits?offset=-1',token=token)
        summary=self.call('summary',token=token)
        self.assertNotIn('students',summary)
        self.assertIn('overdue_audits',summary)
        self.assertEqual(self.call('audits?owner=unknown',token=token),[])

    def test_ai_budget_denial_and_concurrency_never_call_provider(self):
        token=self.login('auditor')
        with app.connect() as db:db.execute('DELETE FROM request_budgets')
        payload={'note':'Fictional library update review.','allow_external':True}
        with patch.dict(os.environ,{'SCHOOL_EXTERNAL_AI_FICTIONAL_ONLY':'1','SCHOOL_AI_MODE':'openai'}),patch('app.suggest') as provider:
            operations.AI_SLOTS.acquire();operations.AI_SLOTS.acquire()
            try:self.denied(429,'assistant/draft',payload,token=token)
            finally:operations.AI_SLOTS.release();operations.AI_SLOTS.release()
            with app.connect() as db:
                for index in range(10):
                    operations.reserve_ai(db,'auditor')
                    db.commit()
            self.denied(429,'assistant/draft',payload,token=token)
            provider.assert_not_called()


class BackupRestoreTest(unittest.TestCase):
    def test_backup_restore_preserves_records_and_revokes_sessions(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(app,'DB',Path(directory)/'source.db'):
            app.initialize()
            with app.connect() as db:
                db.execute("INSERT INTO students(name,year,guardian) VALUES('Fictional student','8','Fictional guardian')")
                db.execute("INSERT INTO sessions(token_hash,username,expires,public_id,created_at) VALUES('hash','fictional',9999999999,'fixture-public-id',1)")
            backup=Path(directory)/'backup.db';restored=Path(directory)/'restored.db'
            maintenance.copy_database(app.DB,backup)
            maintenance.copy_database(backup,restored)
            maintenance.verify(restored)
            with maintenance.readonly(restored) as db:
                self.assertEqual(db.execute('SELECT name FROM students').fetchone()[0],'Fictional student')
                self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)
            with self.assertRaises(FileExistsError):maintenance.copy_database(app.DB,restored)
            if os.name=='posix':self.assertEqual(restored.stat().st_mode&0o777,0o600)


class BackupRetentionTest(unittest.TestCase):
    def test_pruning_previews_and_preserves_unknown_files(self):
        with tempfile.TemporaryDirectory() as directory:
            old=Path(directory)/'schooldesk-20200101T000000Z-abcd1234.db'
            unrelated=Path(directory)/'school.db'
            old.write_bytes(b'fixture');unrelated.write_bytes(b'fixture')
            os.utime(old,(1,1));os.utime(unrelated,(1,1))
            self.assertEqual(maintenance.prune_backups(directory,30),[old])
            self.assertTrue(old.exists())
            maintenance.prune_backups(directory,30,apply=True)
            self.assertFalse(old.exists())
            self.assertTrue(unrelated.exists())
