import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app
import durable_files
import maintenance
import security_feed
import security_events


class DurablePublicationTest(unittest.TestCase):
    def test_complete_private_file_and_no_overwrite_even_for_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            destination=Path(directory)/'archive'
            durable_files.write_new(destination,b'complete')
            self.assertEqual(destination.read_bytes(),b'complete')
            if os.name=='posix':self.assertEqual(destination.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError):durable_files.write_new(destination,b'replacement')
            link=Path(directory)/'link';link.symlink_to(destination)
            with self.assertRaises(FileExistsError):durable_files.write_new(link,b'replacement')
            self.assertEqual(destination.read_bytes(),b'complete')
            self.assertFalse(list(Path(directory).glob('.schooldesk-*')))

    def test_publication_failure_leaves_no_partial_destination_and_retry_works(self):
        with tempfile.TemporaryDirectory() as directory:
            destination=Path(directory)/'archive'
            with patch('durable_files.os.link',side_effect=OSError('simulated disk failure')):
                with self.assertRaises(OSError):durable_files.write_new(destination,b'complete')
            self.assertFalse(destination.exists())
            self.assertEqual(list(Path(directory).iterdir()),[])
            durable_files.write_new(destination,b'complete')
            self.assertEqual(destination.read_bytes(),b'complete')

    def test_snapshot_is_hidden_until_verified_and_never_removes_existing_file(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'source.db'):
            app.initialize();destination=Path(directory)/'restore.db'
            original=maintenance.verify
            def reject(path):
                self.assertFalse(destination.exists())
                original(path)
                raise ValueError('simulated integrity failure')
            with patch('maintenance.verify',side_effect=reject):
                with self.assertRaises(ValueError):maintenance.copy_database(app.DB,destination)
            self.assertFalse(destination.exists())
            maintenance.copy_database(app.DB,destination)
            original_bytes=destination.read_bytes()
            with self.assertRaises(FileExistsError):maintenance.copy_database(app.DB,destination)
            self.assertEqual(destination.read_bytes(),original_bytes)
            self.assertFalse(list(Path(directory).glob('.schooldesk-copy-*')))

    def test_feed_retry_after_cursor_failure_reuses_complete_segment(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(app,'DB',Path(directory)/'source.db'):
            app.initialize()
            with app.connect() as db:security_events.append(db,'login_succeeded','fictional')
            feed=Path(directory)/'feed'
            with patch('security_feed.os.replace',side_effect=OSError('simulated cursor failure')):
                with self.assertRaises(OSError):security_feed.export(app.DB,feed)
            segment=next(feed.glob('events-*.jsonl'));original=segment.read_bytes()
            self.assertFalse((feed/'cursor.json').exists())
            self.assertEqual(security_feed.export(app.DB,feed),1)
            self.assertEqual(segment.read_bytes(),original)
            self.assertEqual(security_feed.export(app.DB,feed),0)
