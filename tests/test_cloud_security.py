import base64
from email.message import Message
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request,urlopen
from cryptography.fernet import Fernet

import accounts
import app
import deployment
import evidence_scan
import mfa
import secret_config
import secure_backup
import security
import test_accounts


class MFAHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_accounts.AccountHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def setUp(self):
        test_accounts.AccountHTTPTest.setUp(self)
        self.environment=patch.dict(os.environ,{'SCHOOL_MFA_KEY':Fernet.generate_key().decode()})
        self.environment.start();self.addCleanup(self.environment.stop)
        with app.connect() as db:
            for table in ('mfa_accounts','mfa_recovery','mfa_budget','mfa_login_budget'):db.execute('DELETE FROM '+table)
            db.execute("DELETE FROM account_settings WHERE key='mfa_required'")

    def enroll(self,token):
        value=self.call('auth/mfa/begin',{'password':'fictional-password-for-tests'},token=token)
        code=mfa.totp(value['secret'],int(time.time()//30))
        confirmed=self.call('auth/mfa/confirm',{'code':code},token=token)
        return value,code,confirmed

    def test_mandatory_mfa_restricts_password_only_session_and_uses_encrypted_seed(self):
        with patch.dict(os.environ,{'SCHOOL_REQUIRE_MFA':'1'}):
            result=self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests'})
            self.assertTrue(result['mfa_setup_required']);token=result['token']
            self.denied(403,'students',token=token)
            self.denied(403,'pipeline/export',{'resource':'audits','format':'json','after_id':0,'limit':1},token=token)
            value,code,confirmed=self.enroll(token)
            self.assertEqual(len(confirmed['recovery_codes']),8)
            self.denied(401,'auth/me',token=token)
            with app.connect() as db:
                stored=db.execute("SELECT secret FROM mfa_accounts WHERE username='admin'").fetchone()[0]
                self.assertNotIn(value['secret'],stored)
            self.denied(401,'auth/login',{'username':'admin','password':'fictional-password-for-tests','code':code})
            recovery=confirmed['recovery_codes'][0]
            fresh=self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests','code':recovery})
            self.assertFalse(fresh['mfa_setup_required'])
            self.assertIsInstance(self.call('students',token=fresh['token']),list)
            self.assertEqual(set(self.call('auth/me',token=fresh['token'])['user']),{'username','role'})
            self.denied(401,'auth/login',{'username':'admin','password':'fictional-password-for-tests','code':recovery})

    def test_enrollment_requires_password_and_rate_limits_confirmation(self):
        token=self.login('admin')
        self.denied(401,'auth/mfa/begin',{'password':'incorrect'},token=token)
        value=self.call('auth/mfa/begin',{'password':'fictional-password-for-tests'},token=token)
        window={mfa.totp(value['secret'],int(time.time()//30)+step) for step in (-1,0,1)}
        wrong=next(str(number).zfill(6) for number in range(10) if str(number).zfill(6) not in window)
        for _ in range(5):self.denied(400,'auth/mfa/confirm',{'code':wrong},token=token)
        self.denied(429,'auth/mfa/confirm',{'code':wrong},token=token)

    def test_persisted_cloud_policy_survives_environment_downgrade(self):
        with app.connect() as db:db.execute("INSERT OR REPLACE INTO account_settings VALUES('mfa_required','all')")
        result=self.call('auth/login',{'username':'owner','password':'fictional-password-for-tests'})
        self.assertTrue(result['mfa_setup_required']);self.denied(403,'audits',token=result['token'])

    def test_sensitive_export_requires_step_up_without_extra_sessions(self):
        token=self.login('admin')
        with app.connect() as db:db.execute('UPDATE sessions SET auth_time=?',(time.time()-301,))
        payload={'resource':'students','format':'json','after_id':0,'limit':10}
        self.denied(428,'pipeline/export',payload,token=token)
        self.call('auth/reauthenticate',{'password':'fictional-password-for-tests'},token=token)
        self.assertEqual(self.call('pipeline/export',payload,token=token)['rows'],[])
        with app.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0],1)

    def test_closure_requires_fresh_review_authentication(self):
        auditor=self.login('auditor');reviewer=self.login('reviewer')
        record=self.call('audits',{'area':'Demo','finding':'Concern','owner':'owner','reviewer':'reviewer','severity':'Low','due_date':'2026-12-01','remediation':'Fix','evidence':'Reviewed report'},token=auditor)
        with app.connect() as db:
            db.execute("UPDATE audits SET status='Awaiting verification' WHERE id=?",(record['id'],))
            db.execute("UPDATE sessions SET auth_time=? WHERE username='reviewer'",(time.time()-301,))
        change={'revision':record['revision'],'status':'Closed','verification':'Checked','closure_reason':'Verified'}
        self.denied(428,'audits/'+str(record['id']),change,token=reviewer,method='PUT')
        self.call('auth/reauthenticate',{'password':'fictional-password-for-tests'},token=reviewer)
        self.assertEqual(self.call('audits/'+str(record['id']),change,token=reviewer,method='PUT')['status'],'Closed')

    def test_factor_guessing_has_an_account_budget_and_expires(self):
        value,_,confirmed=self.enroll(self.login('admin'))
        window={mfa.totp(value['secret'],int(time.time()//30)+step) for step in (-1,0,1)}
        bad=next(str(number).zfill(6) for number in range(10) if str(number).zfill(6) not in window)
        for _ in range(5):self.denied(401,'auth/login',{'username':'admin','password':'fictional-password-for-tests','code':bad})
        self.denied(429,'auth/login',{'username':'admin','password':'fictional-password-for-tests','code':confirmed['recovery_codes'][0]})
        with app.connect() as db:db.execute("UPDATE mfa_login_budget SET start=? WHERE username='admin'",(time.time()-901,))
        result=self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests','code':confirmed['recovery_codes'][0]})
        self.assertIn('token',result)

    def test_mfa_seed_is_bound_to_account_and_bad_key_fails_closed(self):
        value,code,confirmed=self.enroll(self.login('admin'))
        with patch.dict(os.environ,{'SCHOOL_MFA_KEY':Fernet.generate_key().decode()}):
            self.denied(503,'auth/login',{'username':'admin','password':'fictional-password-for-tests','code':mfa.totp(value['secret'],int(time.time()//30)+1)})
        with app.connect() as db:
            stored=db.execute("SELECT secret FROM mfa_accounts WHERE username='admin'").fetchone()[0]
            with self.assertRaises(security.RequestError):mfa.unpack('owner',stored)


class EvidenceQuarantineHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_accounts.AccountHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    setUp=test_accounts.AccountHTTPTest.setUp
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def test_infected_attachment_blocks_release_and_requires_documented_rejection(self):
        auditor=self.login('auditor');owner=self.login('owner')
        record=self.call('audits',{'area':'Demo','finding':'Fictional concern','owner':'owner','reviewer':'reviewer','severity':'High','due_date':'2026-12-01','remediation':'Fictional fix','evidence':'Other reviewed evidence'},token=auditor)
        with patch.dict(os.environ,{'SCHOOL_EVIDENCE_SCAN':'clamd'}),patch('evidence_scan.scan',return_value='infected'):
            file=self.call('audits/'+str(record['id'])+'/evidence',{'filename':'fictional.txt','content_base64':'ZmljdGlvbmFs'},token=owner)
            self.assertFalse(file['released']);self.denied(423,'evidence/'+str(file['id']),token=owner)
            current=self.call('audits/'+str(record['id']),{'revision':file['audit_revision'],'status':'Open'},token=owner,method='PUT')
            current=self.call('audits/'+str(record['id']),{'revision':current['revision'],'status':'In progress'},token=owner,method='PUT')
            self.denied(423,'audits/'+str(record['id']),{'revision':current['revision'],'status':'Awaiting verification'},token=owner,method='PUT')
            self.denied(403,'evidence/'+str(file['id'])+'/reject',{'reason':'Unsafe'},token=owner)
            self.call('evidence/'+str(file['id'])+'/reject',{'reason':'Retain unsafe fictional sample; use other evidence'},token=auditor)
            latest=next(row for row in self.call('audits',token=owner) if row['id']==record['id'])
            self.call('audits/'+str(record['id']),{'revision':latest['revision'],'status':'Awaiting verification'},token=owner,method='PUT')
        self.denied(423,'evidence/'+str(file['id']),token=owner)

    def test_assignment_is_rechecked_after_scanner_work(self):
        auditor=self.login('auditor');owner=self.login('owner')
        record=self.call('audits',{'area':'Race','finding':'Concern','owner':'owner'},token=auditor)
        def reassign(content):
            with app.connect() as db:db.execute("UPDATE audits SET owner='admin',revision=revision+1 WHERE id=?",(record['id'],))
            return 'clean'
        with patch('evidence_scan.scan',side_effect=reassign):
            self.denied(404,'audits/'+str(record['id'])+'/evidence',{'filename':'note.txt','content_base64':'ZmljdGlvbmFs'},token=owner)
        with app.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM audit_evidence WHERE audit_id=?',(record['id'],)).fetchone()[0],0)

    def test_bad_rescan_reopens_a_closed_finding_and_cannot_be_bypassed(self):
        token=self.login('auditor');record=self.call('audits',{'area':'Closed','finding':'Concern'},token=token)
        file=self.call('audits/'+str(record['id'])+'/evidence',{'filename':'note.txt','content_base64':'ZmljdGlvbmFs'},token=token)
        with app.connect() as db:db.execute("UPDATE audits SET status='Closed',verification='Checked',closure_reason='Verified' WHERE id=?",(record['id'],))
        with patch.dict(os.environ,{'SCHOOL_EVIDENCE_SCAN':'clamd'}),patch('evidence_scan.scan',return_value='infected'):
            self.assertFalse(self.call('evidence/'+str(file['id'])+'/rescan',{},token=token)['released'])
        latest=next(row for row in self.call('audits',token=token) if row['id']==record['id'])
        self.assertEqual(latest['status'],'Open');self.assertEqual(latest['verification'],'');self.assertTrue(latest['reopen_reason'])
        self.denied(423,'evidence/'+str(file['id']),token=token)
        self.denied(409,'evidence/'+str(file['id'])+'/rescan',{},token=token)

    def test_integrity_failure_blocks_review_even_without_scanner_policy(self):
        auditor=self.login('auditor');owner=self.login('owner')
        record=self.call('audits',{'area':'Integrity','finding':'Concern','owner':'owner','reviewer':'reviewer','severity':'Low','due_date':'2026-12-01','remediation':'Fix','evidence':'Report'},token=auditor)
        file=self.call('audits/'+str(record['id'])+'/evidence',{'filename':'note.txt','content_base64':'ZmljdGlvbmFs'},token=owner)
        with app.connect() as db:
            db.execute("UPDATE audit_evidence SET content=? WHERE id=?",(b'tampered',file['id']))
            db.execute("UPDATE audits SET status='In progress' WHERE id=?",(record['id'],))
        self.denied(423,'audits/'+str(record['id']),{'revision':file['audit_revision'],'status':'Awaiting verification'},token=owner,method='PUT')
        with patch.dict(os.environ,{'SCHOOL_EVIDENCE_SCAN':'clamd'}),patch('evidence_scan.scan') as scanner:
            result=self.call('evidence/'+str(file['id'])+'/rescan',{},token=auditor)
            self.assertEqual(result['scan_status'],'integrity_failed');scanner.assert_not_called()

    def test_scanner_outage_stays_quarantined_until_clean_rescan(self):
        token=self.login('auditor');record=self.call('audits',{'area':'Demo','finding':'Concern'},token=token)
        with patch.dict(os.environ,{'SCHOOL_EVIDENCE_SCAN':'clamd'}),patch('evidence_scan.scan',return_value='unavailable'):
            file=self.call('audits/'+str(record['id'])+'/evidence',{'filename':'fictional.txt','content_base64':'ZmljdGlvbmFs'},token=token)
        self.denied(423,'evidence/'+str(file['id']),token=token)
        self.denied(409,'evidence/'+str(file['id'])+'/rescan',{},token=token)
        with patch.dict(os.environ,{'SCHOOL_EVIDENCE_SCAN':'clamd'}),patch('evidence_scan.scan',return_value='clean'):
            self.assertTrue(self.call('evidence/'+str(file['id'])+'/rescan',{},token=token)['released'])
        with urlopen(Request(self.base+'evidence/'+str(file['id']),headers={'Authorization':'Bearer '+token})) as response:self.assertEqual(response.read(),b'fictional')


class GatewayAndSecretsTest(unittest.TestCase):
    def handler(self,host='schooldesk.example.invalid',origin='https://schooldesk.example.invalid',token='x'*40,peer='127.0.0.1'):
        headers=Message()
        for key,value in {'Host':host,'Origin':origin,'X-Schooldesk-Proxy-Token':token,'X-Schooldesk-Request':'1'}.items():headers[key]=value
        return SimpleNamespace(headers=headers,client_address=(peer,100),server=SimpleNamespace(server_port=8000))

    def test_cloud_mfa_cannot_be_disabled_by_optional_local_flag(self):
        with patch.dict(os.environ,{'SCHOOL_PROFILE':'cloud','SCHOOL_REQUIRE_MFA':'0'}):
            for role in accounts.ROLES:self.assertTrue(mfa.required({'role':role}))

    def test_cloud_gateway_rejects_direct_and_forged_origins(self):
        with patch.dict(os.environ,{'SCHOOL_PROFILE':'cloud','SCHOOL_PUBLIC_ORIGIN':'https://schooldesk.example.invalid','SCHOOL_PROXY_TOKEN':'x'*40}):
            security.check_request(self.handler(),write=True,authenticate=False)
            for handler in (self.handler(token='wrong'),self.handler(origin='http://schooldesk.example.invalid'),self.handler(peer='203.0.113.5'),self.handler(host='untrusted.invalid')):
                with self.assertRaises(security.RequestError):security.check_request(handler,authenticate=False)

    def test_cloud_startup_checks_secrets_profile_and_nonroot_identity(self):
        environment={'SCHOOL_PROFILE':'cloud','SCHOOL_PUBLIC_ORIGIN':'https://schooldesk.example.invalid','SCHOOL_PROXY_TOKEN':'x'*40,'SCHOOL_MFA_KEY':Fernet.generate_key().decode(),'SCHOOL_EVIDENCE_SCAN':'clamd','SCHOOL_CLAMD_SOCKET':'/run/clamav/test.sock'}
        with patch.dict(os.environ,environment,clear=True),patch('deployment.os.geteuid',return_value=1001,create=True):
            deployment.validate()
            with patch.dict(os.environ,{'SCHOOL_BACKUP_KEY':Fernet.generate_key().decode()}):
                with self.assertRaises(ValueError):deployment.validate()
            with patch('deployment.os.geteuid',return_value=0):
                with self.assertRaises(ValueError):deployment.validate()
            with patch.dict(os.environ,{'SCHOOL_PUBLIC_ORIGIN':'http://schooldesk.example.invalid'}):
                with self.assertRaises(ValueError):deployment.validate()

    def test_secret_files_enforce_permissions_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'key';file.write_text('PRIVATE-KEY');file.chmod(0o600)
            with patch.dict(os.environ,{'TEST_SECRET_FILE':str(file),'TEST_SECRET':''}):self.assertEqual(secret_config.read('TEST_SECRET'),'PRIVATE-KEY')
            with patch.dict(os.environ,{'TEST_SECRET_FILE':str(file),'TEST_SECRET':'ambiguous'}):
                with self.assertRaises(ValueError):secret_config.read('TEST_SECRET')
            if os.name=='posix':
                file.chmod(0o644)
                with patch.dict(os.environ,{'TEST_SECRET_FILE':str(file),'TEST_SECRET':''}):
                    with self.assertRaises(ValueError):secret_config.read('TEST_SECRET')


class EncryptedBackupTest(unittest.TestCase):
    def test_authenticated_roundtrip_rejects_tampering_and_wrong_keys(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'source.db'),patch.dict(os.environ,{'SCHOOL_BACKUP_KEY':Fernet.generate_key().decode()}):
            app.initialize()
            with app.connect() as db:db.execute("INSERT INTO students(name,year,guardian) VALUES('PRIVATE-FICTIONAL-STUDENT','8','PRIVATE-GUARDIAN')")
            encrypted=Path(directory)/'snapshot.enc';restored=Path(directory)/'restored.db'
            secure_backup.backup(app.DB,encrypted)
            self.assertNotIn(b'PRIVATE',encrypted.read_bytes());self.assertNotIn(b'SQLite format',encrypted.read_bytes())
            secure_backup.restore(encrypted,restored)
            import sqlite3
            with sqlite3.connect(restored) as db:self.assertEqual(db.execute('SELECT name FROM students').fetchone()[0],'PRIVATE-FICTIONAL-STUDENT')
            with self.assertRaises(FileExistsError):secure_backup.restore(encrypted,restored)
            with patch.dict(os.environ,{'SCHOOL_BACKUP_KEY':Fernet.generate_key().decode()}):
                with self.assertRaises(ValueError):secure_backup.restore(encrypted,Path(directory)/'wrong.db')
            data=bytearray(encrypted.read_bytes());data[-10]^=1;encrypted.write_bytes(data)
            with self.assertRaises(ValueError):secure_backup.restore(encrypted,Path(directory)/'tampered.db')
            self.assertFalse((Path(directory)/'tampered.db').exists())

class ScannerProtocolTest(unittest.TestCase):
    @unittest.skipUnless(hasattr(socket,'AF_UNIX'),'UNIX scanner socket')
    def test_instream_bytes_and_clean_infected_responses(self):
        for reply,expected in [(b'stream: OK\x00','clean'),(b'stream: Test-Signature FOUND\x00','infected')]:
            with tempfile.TemporaryDirectory() as directory:
                path=str(Path(directory)/'scanner.sock');server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(path);server.listen(1);captured=[]
                def exact(client,size):
                    value=b''
                    while len(value)<size:
                        part=client.recv(size-len(value))
                        if not part:raise ValueError('Incomplete protocol')
                        value+=part
                    return value
                def daemon():
                    with server.accept()[0] as client:
                        captured.append(exact(client,10));content=b''
                        while True:
                            size=struct.unpack('>I',exact(client,4))[0]
                            if size==0:break
                            content+=exact(client,size)
                        captured.append(content);client.sendall(reply)
                thread=threading.Thread(target=daemon,daemon=True);thread.start()
                try:
                    with patch.dict(os.environ,{'SCHOOL_EVIDENCE_SCAN':'clamd','SCHOOL_CLAMD_SOCKET':path}):self.assertEqual(evidence_scan.scan(b'fictional bytes'),expected)
                    thread.join(timeout=2);self.assertEqual(captured,[b'zINSTREAM\x00',b'fictional bytes'])
                finally:server.close()


class RecoveryAndFeedTest(unittest.TestCase):
    def test_backup_removes_recovery_codes_and_feed_detects_rewrite(self):
        import maintenance
        import security_feed
        import security_events
        import sqlite3
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'):
            app.initialize()
            with app.connect() as db:
                accounts.create_user(db,'admin','administrator','fictional-test-password')
                db.execute("INSERT INTO mfa_recovery VALUES('admin','old-hash')")
            backup=Path(directory)/'copy.db';maintenance.copy_database(app.DB,backup)
            with maintenance.readonly(backup) as db:self.assertEqual(db.execute('SELECT count(*) FROM mfa_recovery').fetchone()[0],0)
            feed=Path(directory)/'feed'
            self.assertEqual(security_feed.export(app.DB,feed),1)
            self.assertEqual(security_feed.export(app.DB,feed),0)
            with app.connect() as db:security_events.append(db,'login_succeeded','admin')
            self.assertEqual(security_feed.export(app.DB,feed),1)
            self.assertEqual(len(list(feed.glob('events-*.jsonl'))),2)
            with app.connect() as db:db.execute("UPDATE security_events SET actor='owner' WHERE id=1")
            with self.assertRaises(ValueError):security_feed.export(app.DB,feed)

    def test_backup_receipt_contains_only_verified_metadata(self):
        import runtime
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'):
            app.initialize();receipt=Path(directory)/'receipt.json';runtime.record_backup_receipt(receipt)
            with patch.dict(os.environ,{'SCHOOL_BACKUP_STATUS_FILE':str(receipt)}),app.connect() as db:
                state=runtime.status(db);self.assertEqual(state['backup']['kind'],'authenticated_encrypted');self.assertIsNotNone(state['backup']['last_success_at'])
            receipt.write_text('{"PRIVATE":"invalid"}')
            with patch.dict(os.environ,{'SCHOOL_BACKUP_STATUS_FILE':str(receipt)}),app.connect() as db:
                self.assertIsNone(runtime.status(db)['backup']['last_success_at'])


class TOTPReferenceTest(unittest.TestCase):
    def test_rfc6238_sha1_vectors_truncated_to_six_digits(self):
        secret=base64.b32encode(b'12345678901234567890').decode()
        for timestamp,expected in [(59,'287082'),(1111111109,'081804'),(1234567890,'005924')]:
            self.assertEqual(mfa.totp(secret,timestamp//30),expected)

class DeploymentUtilityTest(unittest.TestCase):
    def test_scheduled_backup_produces_matching_anchor_and_private_receipt(self):
        import integrity_anchor
        import maintenance
        from deploy import run_backup
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'data.db'):
            app.initialize()
            with app.connect() as db:db.execute("INSERT INTO students(name,year,guardian) VALUES('Fictional','8','Fictional guardian')")
            status=Path(directory)/'status';status.mkdir()
            environment={'SCHOOL_BACKUP_KEY':Fernet.generate_key().decode(),'SCHOOL_BACKUP_DIR':str(Path(directory)/'backups'),'SCHOOL_BACKUP_STATUS_FILE':str(status/'receipt.json')}
            with patch.dict(os.environ,environment),patch('sys.stdout'):
                run_backup.main()
                archive=next((Path(directory)/'backups').glob('*.db.enc'))
                bundle=json.loads(next((Path(directory)/'backups').glob('*.anchor.json')).read_text())
                restored=Path(directory)/'restored.db';secure_backup.restore(archive,restored)
                with maintenance.readonly(restored) as db:self.assertTrue(integrity_anchor.verify(db,bundle)['valid'])
            self.assertEqual(json.loads((status/'receipt.json').read_text())['kind'],'authenticated_encrypted')

    def test_secret_generator_keeps_app_and_backup_keys_separate_and_exclusive(self):
        from deploy import create_secrets
        with tempfile.TemporaryDirectory() as directory:
            app_dir=Path(directory)/'app';backup_dir=Path(directory)/'backup'
            create_secrets.create(app_dir,backup_dir)
            self.assertNotEqual((app_dir/'mfa-key').read_bytes(),(backup_dir/'backup-key').read_bytes())
            self.assertFalse((app_dir/'backup-key').exists())
            with self.assertRaises(ValueError):create_secrets.create(app_dir,backup_dir)
            if os.name=='posix':self.assertEqual((app_dir/'mfa-key').stat().st_mode&0o777,0o600)
