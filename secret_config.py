"""Read explicitly configured secrets without logging values or paths."""
import os
from pathlib import Path


def read(name,required=False):
    direct=os.environ.get(name);filename=os.environ.get(name+'_FILE')
    if direct and filename:raise ValueError('Configure only one source for '+name+'.')
    if filename:
        try:
            path=Path(filename)
            if not path.is_file() or (os.name=='posix' and path.stat().st_mode&0o027):raise ValueError()
            with path.open('rb') as source:data=source.read(4097)
            if len(data)>4096:raise ValueError()
            direct=data.decode('utf-8').strip()
        except (OSError,UnicodeError,ValueError):raise ValueError('Secret file is unavailable or insecure for '+name+'.') from None
    if required and not direct:raise ValueError('Missing required secret: '+name+'.')
    return direct


def fernet(name):
    try:
        from cryptography.fernet import Fernet
        return Fernet(read(name,required=True).encode('ascii'))
    except (ValueError,UnicodeError,ImportError):raise ValueError('Encryption key is unavailable or invalid for '+name+'.') from None
