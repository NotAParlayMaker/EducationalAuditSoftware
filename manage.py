"""Local administrator setup. Passwords are never accepted as CLI arguments."""
import argparse
import getpass
import sqlite3
import accounts
import app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['create-user', 'reset-password', 'disable-user', 'list-users'])
    parser.add_argument('username', nargs='?')
    parser.add_argument('--role', choices=accounts.ROLES)
    args = parser.parse_args()
    app.initialize()
    if args.command != 'list-users' and not args.username:
        parser.error('username is required')
    try:
        with app.connect() as db:
            if args.command == 'list-users':
                for row in db.execute('SELECT username,role,active FROM users ORDER BY username'):
                    print(row['username'], row['role'], 'active' if row['active'] else 'disabled')
            elif args.command == 'create-user':
                if not args.role:
                    parser.error('--role is required')
                password = getpass.getpass('Password (14–256 characters): ')
                if password != getpass.getpass('Confirm password: '):
                    raise ValueError('Passwords differ.')
                accounts.create_user(db, args.username, args.role, password)
            else:
                row = db.execute('SELECT * FROM users WHERE username=?', (args.username,)).fetchone()
                if not row:
                    raise ValueError('Account not found.')
                if args.command == 'disable-user':
                    if row['role'] == 'administrator' and db.execute("SELECT count(*) FROM users WHERE role='administrator' AND active=1").fetchone()[0] <= 1:
                        raise ValueError('Cannot disable the last active administrator.')
                    db.execute('UPDATE users SET active=0 WHERE username=?', (args.username,))
                else:
                    password = getpass.getpass('New password: ')
                    if password != getpass.getpass('Confirm password: ') or not 14 <= len(password) <= 256:
                        raise ValueError('Use matching passwords of 14–256 characters.')
                    salt = accounts.secrets.token_hex(16)
                    db.execute('UPDATE users SET salt=?,password_hash=? WHERE username=?', (salt, accounts.password_hash(password, salt), args.username))
                db.execute('DELETE FROM sessions WHERE username=?', (args.username,))
    except (ValueError, sqlite3.IntegrityError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
