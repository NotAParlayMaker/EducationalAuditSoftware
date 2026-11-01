import json
import sqlite3
import unittest

import audit_workflow as workflow


class AuditLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.db.row_factory = sqlite3.Row
        self.db.execute('CREATE TABLE audits(id INTEGER PRIMARY KEY, area TEXT NOT NULL, finding TEXT NOT NULL, status TEXT NOT NULL)')
        workflow.migrate(self.db)
        self.db.commit()
        self.addCleanup(self.db.close)

    def save(self, data, audit_id=None):
        with self.db:
            return workflow.save(self.db, data, audit_id)

    def update(self, record, **changes):
        data = {key:record[key] for key in workflow.FIELDS}
        data.update(actor='Auditor', revision=record['revision'])
        data.update(changes)
        return self.save(data, record['id'])

    def draft(self):
        return self.save(dict(area='Fictional library', finding='Update evidence missing', actor='Auditor'))

    def test_complete_lifecycle_and_history(self):
        record = self.draft()
        record = self.update(record, status='Open', owner='Maintainer', severity='High', due_date='2026-12-01')
        record = self.update(record, status='In progress', remediation='Review updates')
        record = self.update(record, status='Awaiting verification', evidence='Fictional inspection report', reviewer='Reviewer')
        record = self.update(record, status='Closed', verification='Evidence checked', closure_reason='Remediation verified', actor='Reviewer')
        closed = record.copy()
        record = self.update(record, status='Open', reopen_reason='New contradictory evidence')
        self.assertEqual(record['revision'], 6)
        self.assertEqual(record['verification'], '')
        self.assertEqual(record['closure_reason'], '')
        history = self.db.execute('SELECT * FROM audit_history ORDER BY revision').fetchall()
        self.assertEqual(len(history), 6)
        self.assertEqual(json.loads(history[4]['snapshot'])['closure_reason'], closed['closure_reason'])

    def test_invalid_transition_and_stale_save_are_atomic(self):
        record = self.draft()
        with self.assertRaises(ValueError):
            self.update(record, status='Closed')
        self.assertEqual(self.db.execute('SELECT count(*) FROM audit_history').fetchone()[0], 1)
        self.update(record, finding='Corrected finding')
        with self.assertRaises(workflow.Conflict):
            self.update(record, finding='Stale overwrite')
        self.assertEqual(self.db.execute('SELECT finding FROM audits').fetchone()[0], 'Corrected finding')

    def test_required_fields_dates_and_review_separation(self):
        record = self.draft()
        for changes in ({'status':'Open'}, {'status':'Open','owner':'A','severity':'High','due_date':'not-a-date'}, {'severity':'Urgent'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.update(record, **changes)
        record=self.update(record,status='Open',owner='Owner',severity='Low',due_date='2026-12-01')
        record=self.update(record,status='In progress',remediation='Test fix')
        with self.assertRaises(ValueError):
            self.update(record,status='Awaiting verification',evidence='Evidence',reviewer='owner')
        record=self.update(record,status='Awaiting verification',evidence='Evidence',reviewer='Reviewer')
        with self.assertRaises(ValueError):
            self.update(record,status='Closed',verification='Checked',closure_reason='Done',actor='Owner')
        record=self.update(record,status='Closed',verification='Checked',closure_reason='Done',actor='Reviewer')
        with self.assertRaises(ValueError):
            self.update(record,status='Open')

    def test_migration_preserves_legacy_and_is_repeatable(self):
        self.db.execute("INSERT INTO audits(area,finding,status) VALUES('Legacy','Original','Resolved')")
        workflow.migrate(self.db)
        workflow.migrate(self.db)
        self.db.commit()
        row = self.db.execute('SELECT * FROM audits').fetchone()
        self.assertEqual(row['finding'],'Original')
        self.assertEqual(row['status'],'Awaiting verification')
        self.assertEqual(self.db.execute('SELECT count(*) FROM audit_history').fetchone()[0],1)

class AuditHTTPTest(unittest.TestCase):
    def test_routes_update_conflict_and_history(self):
        import app
        import tempfile
        import threading
        from pathlib import Path
        from unittest.mock import patch
        from urllib.request import Request, urlopen
        from urllib.error import HTTPError
        with tempfile.TemporaryDirectory() as directory, patch.object(app, 'DB', Path(directory) / 'test.db'):
            app.initialize()
            server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
            server.allow_demo = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}/api/audits'
                request = Request(base, data=json.dumps({'area':'Demo','finding':'Demo finding','actor':'Auditor'}).encode(), headers={'Authorization':'Bearer '+server.demo_token,'Content-Type':'application/json','X-Schooldesk-Request':'1'})
                with urlopen(request) as response:
                    record=json.load(response)
                request = Request(base+'/'+str(record['id']), method='PUT', data=json.dumps({'revision':1,'actor':'Auditor','finding':'Corrected'}).encode(), headers={'Authorization':'Bearer '+server.demo_token,'Content-Type':'application/json','X-Schooldesk-Request':'1'})
                with urlopen(request) as response:
                    self.assertEqual(json.load(response)['revision'],2)
                with self.assertRaises(HTTPError) as caught:
                    urlopen(request)
                self.assertEqual(caught.exception.code,409)
                with urlopen(Request(base+'/'+str(record['id'])+'/history',headers={'Authorization':'Bearer '+server.demo_token})) as response:
                    history=json.load(response)
                self.assertEqual(len(history),2)
                self.assertEqual(history[-1]['snapshot']['finding'],'Corrected')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
