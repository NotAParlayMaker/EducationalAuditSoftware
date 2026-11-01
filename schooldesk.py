"""Guided local setup and launch. No seeded users or default passwords."""
import argparse
import getpass
import json
import sqlite3

import accounts
import app
import maintenance
import runtime
import deployment


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['init','doctor','serve'])
    parser.add_argument('--username',default='school-admin',help='first administrator username for init')
    parser.add_argument('--allow-demo',action='store_true',help='explicitly allow serving without individual accounts')
    parser.add_argument('--port',type=int,default=None)
    args=parser.parse_args(argv)
    try:
        app.initialize()
        if args.command=='init':
            with app.connect() as db:
                if accounts.enabled(db):
                    print('Accounts already configured. Use manage.py for account maintenance.');return
                password=getpass.getpass('Administrator password (14–256 characters): ')
                if password!=getpass.getpass('Confirm password: '):raise ValueError('Passwords differ.')
                accounts.create_user(db,args.username,'administrator',password)
            print('Administrator created. Add auditor, remediation_owner, and reviewer accounts with manage.py, then run schooldesk.py doctor.')
        elif args.command=='doctor':
            maintenance.verify(app.DB)
            with app.connect() as db:result=runtime.status(db)
            print(json.dumps(result,indent=2,sort_keys=True))
        else:
            if deployment.cloud() and args.allow_demo:raise ValueError('Demo mode is forbidden in the cloud profile.')
            with app.connect() as db:
                if not accounts.enabled(db) and not args.allow_demo:
                    raise ValueError('Run python3 schooldesk.py init first, or explicitly choose --allow-demo for fictional data.')
            import os
            try:port=args.port if args.port is not None else int(os.environ.get('PORT','8000'))
            except ValueError:raise ValueError('PORT must be a valid integer.') from None
            if not 1<=port<=65535:raise ValueError('Port must be 1–65535.')
            server=app.ThreadingHTTPServer(('127.0.0.1',port),app.Handler)
            server.allow_demo=args.allow_demo
            print(f'Schooldesk ready at http://127.0.0.1:{port}',flush=True)
            try:server.serve_forever()
            except KeyboardInterrupt:pass
            finally:server.server_close()
    except (ValueError,OSError,sqlite3.Error) as error:
        if isinstance(error,ValueError):parser.exit(1,str(error)+'\n')
        parser.exit(1,'Operational check failed. Check database integrity, file permissions, and port availability.\n')


if __name__=='__main__':main()
