import hashlib
import json
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import accounts
import app
import mfa
import security
import test_cloud_security


class BackoffFactorHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_cloud_security.MFAHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_cloud_security.MFAHTTPTest.tearDownClass.__func__)
    setUp=test_cloud_security.MFAHTTPTest.setUp
    call=test_cloud_security.MFAHTTPTest.call
    login=test_cloud_security.MFAHTTPTest.login
    denied=test_cloud_security.MFAHTTPTest.denied
    enroll=test_cloud_security.MFAHTTPTest.enroll

    def start_backoff(self):
        with app.connect() as db:
            db.execute('INSERT OR REPLACE INTO login_user_budget VALUES(?,?,?,?)',(accounts.digest('admin'),10,time.time()+300,time.time()))

    def rejected(self,password='fictional-password-for-tests',code=None,path='auth/login',token='',data=None):
        payload={'username':'admin','password':password}
        if code is not None:payload['code']=code
        try:self.call(path,data if data is not None else payload,token=token)
        except HTTPError as error:
            result=(error.code,error.read());error.close();return result
        self.fail('Expected authentication rejection')

    def fake_totp(self,secret):
        window={mfa.totp(secret,int(time.time()//30)+step) for step in (-1,0,1)}
        return next(str(value).zfill(6) for value in range(10) if str(value).zfill(6) not in window)

    def test_all_auth_lockout_statuses_and_bodies_are_identical(self):
        enrollment,_,confirmed=self.enroll(self.login('admin'))
        self.start_backoff();fake=self.fake_totp(enrollment['secret'])
        failures=[self.rejected(),self.rejected(code=fake),self.rejected(password='wrong',code=fake),
                  self.rejected(password='wrong',code=confirmed['recovery_codes'][0])]
        with app.connect() as db:
            db.execute('DELETE FROM login_user_budget')
            db.execute('INSERT OR REPLACE INTO mfa_login_budget VALUES(?,?,5)',('admin',time.time()))
        # The normal MFA throttle must hide password validity outside backoff.
        with patch('accounts.password_hash',side_effect=AssertionError('must reject before PBKDF2')):
            failures.extend([self.rejected(password='wrong',code=fake),self.rejected(code=confirmed['recovery_codes'][0])])
        with app.connect() as db:
            db.execute('DELETE FROM mfa_login_budget')
            db.execute('INSERT OR REPLACE INTO login_budget VALUES(1,?,?)',(time.time(),accounts.GLOBAL_LOGIN_LIMIT))
        failures.extend([self.rejected(password='wrong'),self.rejected(code=confirmed['recovery_codes'][0])])
        with app.connect() as db:db.execute('DELETE FROM login_budget')
        token=self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests','code':confirmed['recovery_codes'][1]})['token']
        with app.connect() as db:
            db.execute('INSERT OR REPLACE INTO password_budget VALUES(?,?,5)',('admin',time.time()))
            db.execute('INSERT OR REPLACE INTO mfa_budget VALUES(?,?,5)',('admin',time.time()))
        failures.append(self.rejected(path='auth/change-password',token=token,data={'current_password':'wrong','new_password':'fictional-new-password'}))
        failures.append(self.rejected(path='auth/mfa/confirm',token=token,data={'code':fake}))
        self.assertTrue(all(response==failures[0] for response in failures))
        self.assertEqual(failures[0][0],429)
        self.assertEqual(json.loads(failures[0][1]),{'error':security.AUTH_THROTTLE_MESSAGE})

    def test_fake_totp_never_hashes_password_or_spends_normal_mfa_budget(self):
        enrollment,_,confirmed=self.enroll(self.login('admin'))
        self.start_backoff();fake=self.fake_totp(enrollment['secret'])
        with app.connect() as db:before=db.execute('SELECT attempts FROM login_budget').fetchone()[0]
        with patch('accounts.password_hash',side_effect=AssertionError('fake code reached PBKDF2')),patch('mfa.check_factor',wraps=mfa.check_factor) as checking:
            for _ in range(8):self.assertEqual(self.rejected(code=fake)[0],429)
            self.assertEqual(checking.call_count,5)
        with app.connect() as db:
            self.assertIsNone(db.execute("SELECT 1 FROM mfa_login_budget WHERE username='admin'").fetchone())
            self.assertEqual(db.execute('SELECT attempts FROM login_budget').fetchone()[0],before)
            self.assertEqual(db.execute('SELECT attempts FROM mfa_backoff_budget WHERE identity=?',(accounts.digest('admin'),)).fetchone()[0],6)
            self.assertEqual(db.execute("SELECT count(*) FROM security_events WHERE event='mfa_backoff_throttled'").fetchone()[0],1)
            # Normal MFA remains usable once the password-backoff window ends.
            db.execute('UPDATE login_user_budget SET next_attempt=0')
        self.assertIn('token',self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests','code':confirmed['recovery_codes'][0]}))

    def test_valid_totp_is_checked_before_hashing_and_consumed_once(self):
        enrollment,_,_=self.enroll(self.login('admin'));self.start_backoff()
        code=mfa.totp(enrollment['secret'],int(time.time()//30)+1)
        sequence=[];original_check=mfa.check_factor;original_hash=accounts.password_hash
        def checked(*args,**kwargs):sequence.append('factor');return original_check(*args,**kwargs)
        def hashed(*args,**kwargs):sequence.append('password');return original_hash(*args,**kwargs)
        with patch('mfa.check_factor',side_effect=checked),patch('accounts.password_hash',side_effect=hashed),patch('mfa.login_factor',side_effect=AssertionError('normal budget must be independent')):
            self.assertIn('token',self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests','code':code}))
        self.assertEqual(sequence,['factor','password','factor'])
        self.start_backoff()
        with patch('accounts.password_hash',side_effect=AssertionError('replayed code reached PBKDF2')):
            self.assertEqual(self.rejected(code=code)[0],429)

    def test_wrong_password_does_not_consume_a_valid_recovery_code(self):
        _,_,confirmed=self.enroll(self.login('admin'));self.start_backoff()
        code=confirmed['recovery_codes'][0]
        self.assertEqual(self.rejected(password='wrong',code=code)[0],429)
        digest=hashlib.sha256(('admin:'+code).encode()).hexdigest()
        with app.connect() as db:self.assertIsNotNone(db.execute('SELECT 1 FROM mfa_recovery WHERE code_hash=?',(digest,)).fetchone())
        self.assertIn('token',self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests','code':code}))
        self.start_backoff()
        with patch('accounts.password_hash',side_effect=AssertionError('replayed recovery code reached PBKDF2')):
            self.assertEqual(self.rejected(code=code)[0],429)

    def test_mfa_reset_during_password_hash_cannot_fall_back_to_password_only(self):
        _,_,confirmed=self.enroll(self.login('admin'));self.start_backoff()
        original=accounts.password_hash
        def reset(*args):
            with app.connect() as db:db.execute("DELETE FROM mfa_accounts WHERE username='admin'")
            return original(*args)
        with patch('accounts.password_hash',side_effect=reset):
            self.assertEqual(self.rejected(code=confirmed['recovery_codes'][0])[0],429)
        with app.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)

    def test_concurrent_consumption_during_hash_prevents_second_use(self):
        _,_,confirmed=self.enroll(self.login('admin'));self.start_backoff()
        code=confirmed['recovery_codes'][0];original=accounts.password_hash
        def consume_elsewhere(*args):
            with app.connect() as db:self.assertTrue(mfa.consume(db,'admin',code))
            return original(*args)
        with patch('accounts.password_hash',side_effect=consume_elsewhere):
            self.assertEqual(self.rejected(code=code)[0],429)
        with app.connect() as db:self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0],0)

    def test_backoff_budget_expires_without_changing_normal_mfa_budget(self):
        _,_,confirmed=self.enroll(self.login('admin'));self.start_backoff()
        with app.connect() as db:
            db.execute('INSERT OR REPLACE INTO mfa_backoff_budget VALUES(?,?,6,?)',(accounts.digest('admin'),time.time()-901,time.time()))
            db.execute('INSERT OR REPLACE INTO mfa_login_budget VALUES(?,?,5)',('admin',time.time()))
        self.assertIn('token',self.call('auth/login',{'username':'admin','password':'fictional-password-for-tests','code':confirmed['recovery_codes'][0]}))
