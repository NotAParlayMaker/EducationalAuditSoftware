# Schooldesk

A dependency-free starter workspace for school administration and IT operations.

## Run

Requires Python 3.12 or newer. From this repository:

```sh
python3 app.py
```

Open your browser at `http://127.0.0.1:8000`. Set `PORT` to change the port or
`SCHOOL_DB` to select a different SQLite database file. The database is created
automatically under `data/`. Stop the server with Ctrl+C.

## Included

- Student enrollment records and guardian details
- Daily attendance records
- Subject grades
- IT equipment inventory
- IT audit findings
- Support requests
- Dashboard totals, record creation, search, and persistent SQLite storage

The initial database is empty. Use fictional records to explore the app.
Student names in attendance and grades are free text; relational enrollment,
editing, deletion, grade calculations, and audit history are future work.

## Validation

```sh
python3 -m unittest discover -s tests -v
```

## Development scope

This is a local prototype, bound to loopback. It has no user authentication,
roles, encryption management, or production deployment configuration. Use
fictional data only. Before handling real school records, add authenticated
access, authorization, retention rules, backups, and appropriate privacy controls.
No external services or credentials are required.
