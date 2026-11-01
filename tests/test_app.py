import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import app


class WorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.old_db = app.DB
        app.DB = Path(cls.temp.name) / 'test.db'
        app.initialize()
        cls.server = app.ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        cls.server.allow_demo = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        app.DB = cls.old_db
        cls.temp.cleanup()

    def test_all_modules_persist_records(self):
        examples = {
            'students': {'name': 'Demo Student', 'year': '8', 'guardian': 'Demo Guardian'},
            'attendance': {'student': 'Demo Student', 'date': '2026-10-31', 'status': 'Present'},
            'grades': {'student': 'Demo Student', 'subject': 'Math', 'grade': 'A'},
            'assets': {'tag': 'DEMO-001', 'device': 'Laptop', 'location': 'Library', 'status': 'Available'},
            'audits': {'area': 'Library', 'finding': 'Review updates', 'status': 'Draft', 'actor': 'Demo Auditor'},
            'tickets': {'title': 'Projector check', 'requester': 'Demo Teacher', 'priority': 'Low', 'status': 'Open'},
        }
        for resource, data in examples.items():
            with self.subTest(resource=resource):
                request = Request(self.base + '/api/' + resource, data=json.dumps(data).encode(), headers={'Content-Type': 'application/json', 'X-Schooldesk-Request':'1'})
                with urlopen(request) as response:
                    self.assertEqual(response.status, 201)
                    saved = json.load(response)
                app.initialize()  # Reinitialization must preserve existing records.
                with urlopen(self.base + '/api/' + resource) as response:
                    self.assertIn(saved, json.load(response))

    def test_invalid_record_rejected(self):
        request = Request(self.base + '/api/students', data=b'{}', headers={'Content-Type':'application/json','X-Schooldesk-Request':'1'})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 400)

    def test_cross_origin_write_rejected(self):
        request = Request(self.base + '/api/students', data=b'{}', headers={'Origin': 'https://example.com'})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request)
        self.assertEqual(caught.exception.code, 403)

    def test_ui_served(self):
        with urlopen(self.base + '/') as response:
            self.assertIn(b'Schooldesk', response.read())


if __name__ == '__main__':
    unittest.main()

