"""Publish complete files without replacing an existing destination."""
import os
from pathlib import Path
import tempfile


def sync_directory(directory):
    if os.name != 'posix':
        return
    descriptor = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_new(temporary, destination):
    # Both paths must be on the same filesystem. Hard-link publication is atomic
    # and fails if the destination already exists, including a symlink.
    with open(temporary, 'rb') as source:
        os.fsync(source.fileno())
    os.link(temporary, destination)
    sync_directory(Path(destination).parent)


def write_new(destination, data, mode=0o600):
    destination = Path(destination)
    descriptor, temporary = tempfile.mkstemp(prefix='.schooldesk-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        publish_new(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
