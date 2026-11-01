import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import app


class SecurityHTTPTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.environment = patch.dict(os.environ, {'SCHOOL_ACCESS_TOKEN':'T' * 48})
        cls.environment.start()
        cls.old_db = app.DB
        app.DB = Path(cls.temp.name) / 'school.db'
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
        cls.environment.stop()
        cls.temp.cleanup()

    def request(self, path='/api/audits', body=None, headers=None, method=None):
        defaults = {'Authorization':'Bearer '+('T' * 48), 'Content-Type':'application/json','X-Schooldesk-Request':'1'}
        if headers:
            defaults.update(headers)
        return urlopen(Request(self.base+path,data=body,headers=defaults,method=method))

    def denied(self, code, **kwargs):
        with self.assertRaises(HTTPError) as caught:
            self.request(**kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception.read()

    def test_optional_token_protects_reads_writes_and_history(self):
        for path, body in [('/api/audits',None),('/api/audits/1/history',None),('/api/audits',b'{}'),('/api/assistant/draft',b'{}')]:
            with self.subTest(path=path, write=bool(body)):
                self.denied(401,path=path,body=body,headers={'Authorization':'Bearer incorrect'})
        with self.request() as response:
            self.assertEqual(response.status,200)

    def test_no_token_mode_still_requires_browser_boundary(self):
        with patch.dict(os.environ, {'SCHOOL_ACCESS_TOKEN':''}):
            self.denied(403,body=b'{}',headers={'X-Schooldesk-Request':''})
            self.denied(403,headers={'Sec-Fetch-Site':'cross-site'})
            self.denied(403,headers={'Sec-Fetch-Site':'same-site'})
            self.denied(403,headers={'Origin':'https://untrusted.invalid'})

    def test_content_type_and_body_limits(self):
        self.denied(415,body=b'{}',headers={'Content-Type':'text/plain'})
        self.denied(413,body=b'x'*8193)
        self.denied(400,body=b'{}',headers={'Transfer-Encoding':'chunked'})

    def test_json_errors_do_not_echo_input(self):
        for body in (b'{PRIVATE-NOTE', b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'\xff', b'['*1500):
            with self.subTest(size=len(body)):
                result=self.denied(400,body=body)
                self.assertEqual(json.loads(result)['error'],'Invalid JSON object')
                self.assertNotIn(b'PRIVATE-NOTE',result)

    def test_only_explicit_static_files_are_served(self):
        for path in ('/../app.py','/%2e%2e/app.py','/.env','/static/','/security.py'):
            self.denied(404,path=path)
        self.denied(405,path='/index.html',method='HEAD')
        with urlopen(self.base+'/') as response:
            self.assertEqual(response.status,200)
            self.assertEqual(response.headers['X-Frame-Options'],'DENY')
            self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
            self.assertEqual(response.headers['X-Content-Type-Options'],'nosniff')

    def test_storage_errors_are_generic(self):
        with patch('app.connect',side_effect=sqlite3.OperationalError('PRIVATE-PATH')):
            result=self.denied(503)
        self.assertNotIn(b'PRIVATE-PATH',result)

    def test_unbounded_audit_ids_are_rejected(self):
        self.denied(404,path='/api/audits/'+('9'*100)+'/history')
        self.denied(404,path='/api/audits/'+('9'*100),body=b'{}',method='PUT')

    @unittest.skipUnless(os.name=='posix','POSIX filesystem permissions')
    def test_database_is_owner_only(self):
        self.assertEqual(app.DB.stat().st_mode & 0o777,0o600)

    def test_no_raw_request_logging(self):
        stream=io.StringIO()
        with patch('sys.stderr',stream):
            self.denied(404,path='/PRIVATE-QUERY?secret=PRIVATE-MARKER')
        self.assertNotIn('PRIVATE',stream.getvalue())

    def test_weak_configured_token_fails_startup(self):
        for token in ('','short',' '+('x'*40), 'x'*257):
            with patch.dict(os.environ,{'SCHOOL_ACCESS_TOKEN':token}):
                with self.assertRaises(ValueError):
                    app.initialize()
