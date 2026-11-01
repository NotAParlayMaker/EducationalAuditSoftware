"""Local clamd INSTREAM protocol. No shell commands or attacker-supplied paths."""
import os
import socket
import struct


def required():return os.environ.get('SCHOOL_PROFILE')=='cloud' or os.environ.get('SCHOOL_EVIDENCE_SCAN')=='clamd'


def scan(content):
    if not required():return 'unscanned'
    path=os.environ.get('SCHOOL_CLAMD_SOCKET')
    if not path:return 'unavailable'
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(5);client.connect(path);client.sendall(b'zINSTREAM\x00')
            for offset in range(0,len(content),65536):
                chunk=content[offset:offset+65536];client.sendall(struct.pack('>I',len(chunk))+chunk)
            client.sendall(struct.pack('>I',0));response=b''
            while b'\x00' not in response and len(response)<4096:
                chunk=client.recv(min(1024,4096-len(response)))
                if not chunk:break
                response+=chunk
        if response==b'stream: OK\x00':return 'clean'
        if response.endswith(b' FOUND\x00'):return 'infected'
    except (OSError,ValueError):pass
    return 'unavailable'


def released(status,media_type=None):
    if media_type=='application/pdf' and (os.environ.get('SCHOOL_ALLOW_PDF_EVIDENCE')!='1' or not required()):return False
    return status=='clean' or (not required() and status in ('unscanned','legacy_unscanned'))


def health():
    if not required():return False
    path=os.environ.get('SCHOOL_CLAMD_SOCKET')
    if not path:return False
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
            client.settimeout(1);client.connect(path);client.sendall(b'zPING\x00')
            return client.recv(128)==b'PONG\x00'
    except OSError:return False
