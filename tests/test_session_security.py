import json
import sqlite3
import unittest
from unittest.mock import patch

import accounts
import app
import security_events as events
import test_accounts
from security import RequestError


class SessionSecurityHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_accounts.AccountHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    def setUp(self):
        test_accounts.AccountHTTPTest.setUp(self)
        with app.connect() as db:db.execute('DELETE FROM password_budget')
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def test_sessions_expose_only_public_metadata_and_cannot_revoke_other_users(self):
        admin=self.login('admin');owner=self.login('owner');second=self.login('owner')
        sessions=self.call('auth/sessions',token=owner)
        self.assertEqual(len(sessions),2)
        self.assertEqual(sum(row['current'] for row in sessions),1)
        for row in sessions:
            self.assertEqual(set(row),{'id','created_at','expires_at','current'})
            self.assertEqual(len(row['id']),24)
        admin_id=self.call('auth/sessions',token=admin)[0]['id']
        self.denied(404,'auth/revoke-session',{'session_id':admin_id},token=owner)
        other=next(row for row in sessions if not row['current'])
        self.call('auth/revoke-session',{'session_id':other['id']},token=owner)
        self.denied(401,'auth/me',token=second)
        self.assertEqual(self.call('auth/me',token=admin)['user']['username'],'admin')

    def test_revoke_all_is_scoped_to_current_account(self):
        admin=self.login('admin');first=self.login('owner');second=self.login('owner')
        self.call('auth/revoke-all',{},token=first)
        for token in (first,second):self.denied(401,'auth/me',token=token)
        self.assertEqual(self.call('auth/me',token=admin)['user']['username'],'admin')

    def test_password_change_requires_current_password_and_revokes_every_session(self):
        first=self.login('owner');second=self.login('owner')
        new='different-fictional-password'
        self.denied(401,'auth/change-password',{'current_password':'incorrect','new_password':new},token=first)
        self.assertEqual(self.call('auth/me',token=first)['user']['username'],'owner')
        self.denied(400,'auth/change-password',{'current_password':'fictional-password-for-tests','new_password':'short'},token=first)
        self.call('auth/change-password',{'current_password':'fictional-password-for-tests','new_password':new},token=first)
        for token in (first,second):self.denied(401,'auth/me',token=token)
        self.denied(401,'auth/login',{'username':'owner','password':'fictional-password-for-tests'})
        result=self.call('auth/login',{'username':'owner','password':new})
        self.assertEqual(result['user']['username'],'owner')
        # Restore the fixture for independent tests in this class.
        self.call('auth/change-password',{'current_password':new,'new_password':'fictional-password-for-tests'},token=result['token'])

    def test_password_throttle_does_not_consume_other_accounts_budget(self):
        owner=self.login('owner');admin=self.login('admin')
        with app.connect() as db:
            db.execute('INSERT OR REPLACE INTO password_budget VALUES(?,?,?)',('owner',accounts.time.time(),5))
        self.denied(429,'auth/change-password',{'current_password':'incorrect','new_password':'another-fictional-password'},token=owner)
        self.denied(401,'auth/change-password',{'current_password':'incorrect','new_password':'another-fictional-password'},token=admin)
        with app.connect() as db:
            self.assertEqual(db.execute("SELECT attempts FROM password_budget WHERE username='admin'").fetchone()[0],1)

    def test_event_access_is_admin_only_and_contains_no_payloads(self):
        admin=self.login('admin');owner=self.login('owner')
        for endpoint in ('security/events','security/verify'):
            self.denied(401,endpoint)
            self.denied(403,endpoint,token=owner)
        self.denied(401,'auth/login',{'username':'PRIVATE-NOTE@example.invalid','password':'PRIVATE-SECRET'})
        listing=self.call('security/events?limit=100',token=admin)
        serialized=json.dumps(listing)
        for value in ('PRIVATE-NOTE','PRIVATE-SECRET','fictional-password-for-tests',admin,owner):self.assertNotIn(value,serialized)
        self.assertTrue(self.call('security/verify',token=admin)['valid'])


    def test_reset_during_login_cannot_issue_a_new_session(self):
        with app.connect() as db:
            accounts.create_user(db,'race-user','auditor','fictional-password-for-tests')
        original=accounts.password_hash
        def reset_during_hash(password,salt):
            result=original(password,salt)
            with app.connect() as db:
                new_salt='11'*16
                db.execute('UPDATE users SET salt=?,password_hash=? WHERE username=?',
                    (new_salt,original('different-fictional-password',new_salt),'race-user'))
            return result
        with patch('accounts.password_hash',side_effect=reset_during_hash):
            self.denied(401,'auth/login',{'username':'race-user','password':'fictional-password-for-tests'})
        with app.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM sessions WHERE username='race-user'").fetchone()[0],0)


class EventChainTest(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');self.db.row_factory=sqlite3.Row
        events.initialize(self.db);self.addCleanup(self.db.close)

    def append(self,code='login_failed',actor=''):
        with self.db:events.append(self.db,code,actor)

    def test_append_and_checkpoint_prefix_accept_new_events(self):
        self.append();result=events.verify(self.db)
        checkpoint={key:result[key] for key in ('count','head')}
        self.append('login_succeeded','admin')
        self.assertTrue(events.verify(self.db,checkpoint)['valid'])

    def test_edit_delete_and_tail_truncation(self):
        self.append();self.append('login_succeeded','admin')
        result=events.verify(self.db);checkpoint={key:result[key] for key in ('count','head')}
        with self.db:self.db.execute('DELETE FROM security_events WHERE id=2')
        self.assertTrue(events.verify(self.db)['valid'])
        self.assertFalse(events.verify(self.db,checkpoint)['valid'])
        with self.db:self.db.execute("UPDATE security_events SET actor='owner' WHERE id=1")
        self.assertFalse(events.verify(self.db)['valid'])

    def test_allowlist_and_no_free_text(self):
        for code,actor in [('raw prompt',''),('login_failed','arbitrary notes or identifier@example.invalid')]:
            with self.assertRaises(ValueError):self.append(code,actor)
        for checkpoint in ({'count':1,'head':'bad'}, {'count':True,'head':'0'*64}):
            with self.assertRaises(ValueError):events.verify(self.db,checkpoint)

    def test_rollback_preserves_chain_and_sequence(self):
        self.append()
        try:
            with self.db:
                events.append(self.db,'login_succeeded','admin')
                raise RuntimeError('rollback')
        except RuntimeError:pass
        self.append()
        result=events.verify(self.db)
        self.assertTrue(result['valid']);self.assertEqual(result['count'],2)


class AccountMigrationTest(unittest.TestCase):
    def test_old_sessions_receive_public_ids_without_new_tokens(self):
        with sqlite3.connect(':memory:') as db:
            db.row_factory=sqlite3.Row
            db.execute('CREATE TABLE sessions(token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires REAL NOT NULL)')
            db.execute("INSERT INTO sessions VALUES('digest','owner',9999999999)")
            db.commit()
            accounts.initialize(db);accounts.initialize(db)
            row=db.execute('SELECT * FROM sessions').fetchone()
            self.assertEqual(row['token_hash'],'digest');self.assertEqual(len(row['public_id']),24)

class SessionCapTest(unittest.TestCase):
    def test_login_keeps_only_ten_active_sessions(self):
        with sqlite3.connect(':memory:') as db:
            db.row_factory=sqlite3.Row;accounts.initialize(db)
            accounts.create_user(db,'admin','administrator','fictional-test-password')
            db.commit()
            last=None
            for index in range(12):
                last=accounts.login(db,{'username':'admin','password':'fictional-test-password'},now=index*61)
                db.commit()
            sessions=accounts.session_list(db,{'username':'admin','role':'administrator'},'Bearer '+last['token'],now=11*61)
            self.assertEqual(len(sessions),10)
            self.assertTrue(any(item['current'] for item in sessions))
            self.assertTrue(events.verify(db)['valid'])

class CheckpointCLITest(unittest.TestCase):
    def test_checkpoint_file_and_external_anchor_verification(self):
        import io
        import tempfile
        from pathlib import Path
        import maintenance
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'checkpoint.db'):
            app.initialize()
            with app.connect() as db:events.append(db,'login_failed')
            checkpoint=Path(directory)/'checkpoint.json'
            with patch('sys.argv',['maintenance.py','security-checkpoint',str(checkpoint)]):
                maintenance.main()
            saved=json.loads(checkpoint.read_text())
            self.assertEqual(set(saved),{'count','head'})
            self.assertEqual(saved['count'],1)
            with app.connect() as db:events.append(db,'login_succeeded','admin')
            with patch('sys.argv',['maintenance.py','security-verify','--checkpoint',str(checkpoint)]),patch('sys.stdout',io.StringIO()) as output:
                maintenance.main()
                self.assertIn('checkpoint matched',output.getvalue())
            with app.connect() as db:db.execute('DELETE FROM security_events')
            with patch('sys.argv',['maintenance.py','security-verify','--checkpoint',str(checkpoint)]),patch('sys.stderr',io.StringIO()):
                with self.assertRaises(SystemExit) as caught:maintenance.main()
                self.assertEqual(caught.exception.code,1)
