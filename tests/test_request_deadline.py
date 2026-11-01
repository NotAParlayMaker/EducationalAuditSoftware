import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

import app


class RequestDeadlineTest(unittest.TestCase):
    def exercise_drip(self,body):
        class DeadlineServer(app.ThreadingHTTPServer):
            worker_limit=1
            request_deadline=0.4

        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'test.db'):
            app.initialize();server=DeadlineServer(('127.0.0.1',0),app.Handler);server.allow_demo=True
            serving=threading.Thread(target=server.serve_forever,daemon=True);serving.start()
            stopped=threading.Event();sender=None
            try:
                with socket.create_connection(server.server_address,timeout=2) as client:
                    client.settimeout(2)
                    host='Host: 127.0.0.1:'+str(server.server_port)+'\r\n'
                    if body:
                        prefix='POST /api/audits HTTP/1.0\r\n'+host+'Content-Type: application/json\r\nContent-Length: 200\r\nX-Schooldesk-Request: 1\r\nAuthorization: Bearer '+server.demo_token+'\r\n\r\n{'
                    else:prefix='GET /health HTTP/1.0\r\n'+host+'X-Slow: '
                    started=time.monotonic();client.sendall(prefix.encode())
                    def drip():
                        while not stopped.wait(0.04):
                            try:client.sendall(b'x')
                            except OSError:return
                    sender=threading.Thread(target=drip,daemon=True);sender.start()
                    try:
                        while client.recv(4096):pass
                    except ConnectionResetError:pass
                    self.assertLess(time.monotonic()-started,2)
                # A full worker pool must become available after the absolute
                # deadline even though the peer never stopped sending bytes.
                recovered=False
                for _ in range(50):
                    try:
                        with urlopen(f'http://127.0.0.1:{server.server_port}/health',timeout=2) as response:
                            self.assertEqual(response.status,200);recovered=True;break
                    except HTTPError as error:
                        self.assertEqual(error.code,503);error.close();time.sleep(0.02)
                self.assertTrue(recovered)
            finally:
                stopped.set()
                if sender:sender.join(timeout=2)
                server.shutdown();server.server_close();serving.join(timeout=2)

    def test_dripping_headers_cannot_hold_a_worker_indefinitely(self):self.exercise_drip(False)

    def test_dripping_body_cannot_hold_a_worker_indefinitely(self):self.exercise_drip(True)

    def test_timer_start_failure_does_not_leak_a_worker_slot(self):
        server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler)
        first,second=socket.socketpair()
        try:
            with patch('app.threading.Timer') as timer:
                timer.return_value.start.side_effect=RuntimeError('simulated thread failure')
                with self.assertRaises(RuntimeError):server.process_request(first,('127.0.0.1',1))
                timer.return_value.cancel.assert_called_once()
            self.assertEqual(server.deadlines,{})
            slots=[]
            for _ in range(server.worker_limit):slots.append(server.worker_slots.acquire(blocking=False))
            self.assertTrue(all(slots))
            for acquired in slots:
                if acquired:server.worker_slots.release()
        finally:first.close();second.close();server.server_close()
