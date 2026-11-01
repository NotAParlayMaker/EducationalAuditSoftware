import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import accounts
import app
import maintenance
import runtime
import schooldesk
import test_accounts


class RuntimeHTTPTest(unittest.TestCase):
    setUpClass=classmethod(test_accounts.AccountHTTPTest.setUpClass.__func__)
    tearDownClass=classmethod(test_accounts.AccountHTTPTest.tearDownClass.__func__)
    setUp=test_accounts.AccountHTTPTest.setUp
    call=test_accounts.AccountHTTPTest.call
    login=test_accounts.AccountHTTPTest.login
    denied=test_accounts.AccountHTTPTest.denied

    def test_queues_are_role_specific_and_exclude_closed_work(self):
        auditor=self.login('auditor');owner=self.login('owner');reviewer=self.login('reviewer')
        with app.connect() as db:
            for status,assigned_owner,assigned_reviewer,severity in [('Open','owner','reviewer','High'),('In progress','other-owner','reviewer','Critical'),('Awaiting verification','owner','reviewer','Medium'),('Closed','owner','reviewer','Critical')]:
                values={field:'' for field in app.audits.FIELDS};values.update(area='Queue fixture',finding='Fictional concern',status=status,owner=assigned_owner,reviewer=assigned_reviewer,severity=severity,due_date='2020-01-01')
                db.execute('INSERT INTO audits('+','.join(app.audits.FIELDS)+') VALUES('+','.join('?' for _ in app.audits.FIELDS)+')',[values[field] for field in app.audits.FIELDS])
        own=self.call('work-queue',token=owner)
        self.assertEqual(len(own['items']),1);self.assertEqual(own['items'][0]['status'],'Open')
        review=self.call('work-queue',token=reviewer)
        self.assertEqual(len(review['items']),1);self.assertEqual(review['items'][0]['status'],'Awaiting verification')
        all_work=self.call('work-queue',token=auditor)
        self.assertEqual(all_work['total'],3)
        self.assertEqual(all_work['items'][0]['severity'],'Critical')
        self.assertTrue(all(item['overdue'] for item in all_work['items']))
        self.denied(401,'work-queue')

    def test_liveness_is_minimal_without_authentication(self):
        from urllib.request import urlopen
        with urlopen(self.base.removesuffix('api/')+'health') as response:
            self.assertEqual(json.load(response),{'service':'schooldesk','status':'ok'})

    def test_readiness_is_admin_only_and_excludes_secret_values(self):
        admin=self.login('admin');owner=self.login('owner')
        self.denied(403,'operations/status',token=owner)
        with patch.dict(os.environ,{'OPENAI_API_KEY':'PRIVATE-API-KEY','SCHOOL_AI_MODEL':'PRIVATE-MODEL','SCHOOL_EXTERNAL_AI_FICTIONAL_ONLY':'1','SCHOOL_AI_MODE':'openai'}):
            result=self.call('operations/status',token=admin)
        self.assertTrue(result['ai']['configured'])
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual(result['active_accounts'],5)


class LauncherTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.database=Path(self.temp.name)/'school.db'
        patcher=patch.object(app,'DB',self.database);patcher.start();self.addCleanup(patcher.stop)

    def test_guided_setup_and_doctor_without_default_credentials(self):
        with patch('sys.argv',['schooldesk.py','init','--username','operator']),patch('getpass.getpass',return_value='fictional-setup-password'),patch('sys.stdout',io.StringIO()):
            schooldesk.main()
        with app.connect() as db:
            self.assertTrue(accounts.enabled(db));self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone()[0],1)
        with patch('sys.argv',['schooldesk.py','doctor']),patch('sys.stdout',io.StringIO()) as output:
            schooldesk.main();report=json.loads(output.getvalue())
        self.assertEqual(report['database'],'reachable')
        self.assertTrue(report['warnings'])
        with patch('sys.argv',['schooldesk.py','init']),patch('getpass.getpass') as prompt,patch('sys.stdout',io.StringIO()):
            schooldesk.main();prompt.assert_not_called()

    def test_serve_requires_accounts_without_explicit_demo_choice(self):
        with patch('sys.argv',['schooldesk.py','serve']),patch('sys.stderr',io.StringIO()),patch('app.ThreadingHTTPServer') as server:
            with self.assertRaises(SystemExit) as caught:schooldesk.main()
            self.assertEqual(caught.exception.code,1);server.assert_not_called()

    def test_mismatched_setup_password_does_not_create_account(self):
        with patch('sys.argv',['schooldesk.py','init']),patch('getpass.getpass',side_effect=['fictional-long-password','different-password']),patch('sys.stderr',io.StringIO()):
            with self.assertRaises(SystemExit):schooldesk.main()
        with app.connect() as db:self.assertFalse(accounts.enabled(db))

    def test_successful_snapshot_records_backup_freshness(self):
        app.initialize();destination=Path(self.temp.name)/'snapshot.db'
        with patch('sys.argv',['maintenance.py','backup',str(destination)]),patch('sys.stdout',io.StringIO()):maintenance.main()
        with app.connect() as db:self.assertIsNotNone(runtime.status(db)['backup']['last_success_at'])
        with self.assertRaises(SystemExit),patch('sys.argv',['maintenance.py','backup',str(destination)]),patch('sys.stderr',io.StringIO()):maintenance.main()


class DemoLaunchTest(unittest.TestCase):
    def test_explicit_demo_launch_stays_on_loopback_and_closes_cleanly(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'demo.db'),patch('sys.argv',['schooldesk.py','serve','--allow-demo','--port','8001']),patch('app.ThreadingHTTPServer') as factory,patch('sys.stdout',io.StringIO()):
            factory.return_value.serve_forever.side_effect=KeyboardInterrupt
            schooldesk.main()
            factory.assert_called_once_with(('127.0.0.1',8001),app.Handler)
            factory.return_value.server_close.assert_called_once()
