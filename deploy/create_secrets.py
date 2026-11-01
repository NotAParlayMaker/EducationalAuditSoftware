"""One-time exclusive key files; never print keys or overwrite an existing secret."""
import argparse
import os
from pathlib import Path
import secrets
from cryptography.fernet import Fernet


def create(app_directory,backup_directory):
    app_directory=Path(app_directory);backup_directory=Path(backup_directory)
    if app_directory.resolve()==backup_directory.resolve() or app_directory.exists() or backup_directory.exists():raise ValueError('Use two new, separate secret directories.')
    app_directory.mkdir(parents=True,mode=0o700);backup_directory.mkdir(parents=True,mode=0o700)
    for path,value in [(app_directory/'proxy-token',secrets.token_urlsafe(32).encode()),(app_directory/'mfa-key',Fernet.generate_key()),(backup_directory/'backup-key',Fernet.generate_key())]:
        descriptor=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(descriptor,'wb') as output:output.write(value+b'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('app_directory');parser.add_argument('backup_directory');args=parser.parse_args()
    create(args.app_directory,args.backup_directory)
    print('Private secret files created. Configure separate ownership; no values were printed.')


if __name__=='__main__':main()
