import base64
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import accounts
import app
import maintenance
import operations
import security_events as events
from security import RequestError
import test_accounts
import assistant
import schooldesk
import evidence_scan


class BoundaryHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_accounts.AccountHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    setUp=test_accounts.AccountHTTPTest.setUp
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def test_registrar_and_it_administrator_cannot_cross_data_domains(self):
        admin=self.login('admin');registrar=self.login('registrar')
        for resource in ('students','attendance','grades'):
            self.denied(403,resource,token=admin)
            self.denied(403,resource,{},token=admin)
            self.denied(403,'pipeline/export',{'resource':resource,'format':'json','after_id':0,'limit':10},token=admin)
        self.call('students',{'name':'Fictional','year':'8','guardian':'Fictional'},token=registrar)
        self.assertEqual(len(self.call('students',token=registrar)),1)
        for resource in ('audits','assets','tickets'):self.denied(403,resource,token=registrar)
        self.denied(403,'pipeline/preview',{'schema_version':1,'resource':'assets','format':'json','rows':[{'tag':'X','device':'X','location':'X','status':'Available'}]},token=registrar)
        self.assertEqual(set(self.call('summary',token=registrar)),{'students','attendance','grades'})
        self.assertNotIn('students',self.call('summary',token=admin))

    def test_idle_expiry_and_activity_do_not_extend_absolute_expiry(self):
        token=self.login('admin')
        with app.connect() as db:
            expiry=db.execute('SELECT expires FROM sessions WHERE token_hash=?',(accounts.digest(token),)).fetchone()[0]
            db.execute('UPDATE sessions SET last_seen=? WHERE token_hash=?',(time.time()-accounts.IDLE_SECONDS-1,accounts.digest(token)))
        self.denied(401,'auth/me',token=token)
        fresh=self.login('admin');self.call('auth/me',token=fresh)
        with app.connect() as db:
            session=db.execute('SELECT * FROM sessions WHERE token_hash=?',(accounts.digest(fresh),)).fetchone()
            self.assertGreater(session['last_seen'],session['created_at'])
            self.assertLessEqual(session['expires']-session['created_at'],accounts.SESSION_SECONDS)
            self.assertEqual(db.execute('SELECT expires FROM sessions WHERE token_hash=?',(accounts.digest(token),)).fetchone()[0],expiry)


class LoginBackoffTest(unittest.TestCase):
    def test_repeated_throttled_identity_does_not_lock_out_other_users(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'):
            app.initialize()
            with app.connect() as db:accounts.create_user(db,'admin','administrator','fictional-test-password')
            now=time.time()
            for _ in range(3):
                with app.connect() as db,self.assertRaises(RequestError) as caught:
                    accounts.login(db,{'username':'unknown','password':'incorrect'},now=now)
                self.assertEqual(caught.exception.status,401)
            for _ in range(20):
                with app.connect() as db,self.assertRaises(RequestError) as caught:
                    accounts.login(db,{'username':'unknown','password':'incorrect'},now=now)
                self.assertEqual(caught.exception.status,429)
            with app.connect() as db:
                self.assertEqual(db.execute('SELECT attempts FROM login_budget').fetchone()[0],3)
                result=accounts.login(db,{'username':'admin','password':'fictional-test-password'},now=now)
                self.assertIn('token',result)
            with app.connect() as db,self.assertRaises(RequestError) as caught:
                accounts.login(db,{'username':'unknown','password':'incorrect'},now=now+2)
            self.assertEqual(caught.exception.status,401)
            with app.connect() as db:self.assertEqual(db.execute('SELECT next_attempt FROM login_user_budget WHERE identity=?',(accounts.digest('unknown'),)).fetchone()[0],now+4)

    def test_unknown_and_known_users_both_take_password_hash_path(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'):
            app.initialize()
            with app.connect() as db:accounts.create_user(db,'admin','administrator','fictional-test-password')
            with patch('accounts.password_hash',wraps=accounts.password_hash) as hashing:
                for name in ('admin','unknown'):
                    with app.connect() as db,self.assertRaises(RequestError):accounts.login(db,{'username':name,'password':'incorrect'})
                self.assertEqual(hashing.call_count,2)


class SignedHistoryTest(unittest.TestCase):
    def test_explicit_migration_rejects_recomputed_unkeyed_chain_and_missing_key(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'):
            app.initialize()
            with app.connect() as db:events.append(db,'login_succeeded','fictional')
            with patch.dict(os.environ,{'SCHOOL_EVENT_KEY':'a'*64}):
                with app.connect() as db:
                    self.assertFalse(events.verify(db)['valid'])
                    with self.assertRaises(ValueError):events.append(db,'login_failed')
                    events.seal_existing(db)
                    self.assertTrue(events.verify(db)['valid'])
                    self.assertTrue(all(row[0] for row in db.execute('SELECT event_mac FROM security_events')))
                with patch.dict(os.environ,{'SCHOOL_EVENT_KEY':'b'*64}),app.connect() as db:self.assertFalse(events.verify(db)['valid'])
                with app.connect() as db:
                    previous=events.ZERO
                    for row in db.execute('SELECT * FROM security_events ORDER BY id').fetchall():
                        record=dict(row);record['actor']='attacker';record['previous_hash']=previous;previous=events.event_hash(record)
                        db.execute('UPDATE security_events SET actor=?,previous_hash=?,event_hash=? WHERE id=?',('attacker',record['previous_hash'],previous,record['id']))
                    self.assertFalse(events.verify(db)['valid'])
            with app.connect() as db:self.assertFalse(events.verify(db)['valid'])
            with self.assertRaises(ValueError):app.initialize()

    def test_new_signed_database_and_snapshot_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'),patch.dict(os.environ,{'SCHOOL_EVENT_KEY':'c'*64}):
            app.initialize()
            with app.connect() as db:
                accounts.create_user(db,'admin','administrator','fictional-test-password')
                self.assertTrue(events.verify(db)['valid'])
            snapshot=Path(directory)/'snapshot.db';maintenance.copy_database(app.DB,snapshot)
            maintenance.write_checkpoint(snapshot,snapshot)
            checkpoint=json.loads((Path(directory)/'checkpoints'/'snapshot.db.checkpoint.json').read_text())
            with maintenance.readonly(snapshot) as db:self.assertTrue(events.verify(db,checkpoint)['valid'])
            with self.assertRaises(FileExistsError):maintenance.write_checkpoint(snapshot,snapshot)


class EvidenceTypePolicyTest(unittest.TestCase):
    def test_pdf_requires_both_opt_in_and_scanner(self):
        payload={'filename':'fictional.pdf','content_base64':base64.b64encode(b'%PDF-1.7\nfictional').decode()}
        with patch.dict(os.environ,{'SCHOOL_ALLOW_PDF_EVIDENCE':'0','SCHOOL_EVIDENCE_SCAN':'disabled'}):
            with self.assertRaises(RequestError):operations.validate_upload(payload)
            self.assertFalse(evidence_scan.released('clean','application/pdf'))
        with patch.dict(os.environ,{'SCHOOL_ALLOW_PDF_EVIDENCE':'1','SCHOOL_EVIDENCE_SCAN':'disabled'}):
            with self.assertRaises(RequestError):operations.validate_upload(payload)
        with patch.dict(os.environ,{'SCHOOL_ALLOW_PDF_EVIDENCE':'1','SCHOOL_EVIDENCE_SCAN':'clamd'}):
            self.assertEqual(operations.validate_upload(payload)[2],'application/pdf')
            self.assertTrue(evidence_scan.released('clean','application/pdf'))

    def test_external_ai_cannot_be_enabled_in_cloud_or_without_operator_opt_in(self):
        note={'note':'Fictional student context would not match an email pattern.','allow_external':True}
        for profile,flag in [('local','0'),('cloud','1')]:
            with patch.dict(os.environ,{'SCHOOL_PROFILE':profile,'SCHOOL_AI_MODE':'openai','SCHOOL_EXTERNAL_AI_FICTIONAL_ONLY':flag}),patch('assistant.PROVIDER_OPENER.open') as transport:
                with self.assertRaises(assistant.AssistantError):assistant.suggest(note)
                transport.assert_not_called()


class StartupSessionPolicyTest(unittest.TestCase):
    def test_incident_flag_revokes_existing_sessions_and_records_the_action(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'):
            app.initialize()
            with app.connect() as db:
                accounts.create_user(db,'admin','administrator','fictional-test-password')
            with app.connect() as db:
                accounts.login(db,{'username':'admin','password':'fictional-test-password'})
            with patch('app.ThreadingHTTPServer') as server,patch('sys.stdout'):
                server.return_value.serve_forever.side_effect=KeyboardInterrupt
                schooldesk.main(['serve','--revoke-sessions'])
            with app.connect() as db:
                self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)
                self.assertEqual(db.execute("SELECT count(*) FROM security_events WHERE event='startup_sessions_revoked'").fetchone()[0],1)

    def test_generated_demo_token_is_unique_per_server_and_not_in_status(self):
        with patch.dict(os.environ,{},clear=True):
            first=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
            second=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
            try:
                self.assertNotEqual(first.demo_token,second.demo_token)
                self.assertGreaterEqual(len(first.demo_token),40)
            finally:first.server_close();second.server_close()
