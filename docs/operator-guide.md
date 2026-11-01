# Local operator guide

Schooldesk is a local, fictional-data prototype. This guide makes setup and daily
work repeatable; it is not a network deployment or a certification for real school
records. Python 3.12+ is required; normal operation has no third-party dependencies.

## First launch

From the repository, choose a protected local database location using `SCHOOL_DB`
if desired. The default is `data/school.db`. Then run:

```sh
python3 schooldesk.py init --username school-admin
python3 manage.py create-user school-auditor --role auditor
python3 manage.py create-user equipment-owner --role remediation_owner
python3 manage.py create-user audit-reviewer --role reviewer
python3 schooldesk.py doctor
python3 schooldesk.py serve
```

Every creation prompts for a password without echo; no password appears in command
arguments. Initialization is repeatable and will not overwrite an existing account
setup. `serve` requires provisioned accounts unless `--allow-demo` is deliberately
selected. Use `--port 8001` if the default port is busy. The service remains bound
to `127.0.0.1`; stop it with Ctrl+C. Existing `python3 app.py` behavior remains for
compatibility, but the guided launcher is the recommended entry point.

Open `http://127.0.0.1:8000` and sign in. Passwords, keys, and session tokens must
not be stored in repository files. Keep separate owner and reviewer accounts;
software can distinguish accounts, not prove they belong to different people.

## Daily routine

1. Review the work queue. Owners see assigned Open/In progress findings; reviewers
   see their assigned Awaiting verification findings. Auditors/administrators see
   all active findings. Tasks are ordered by severity, then earliest deadline;
   overdue labels compare date-only deadlines against UTC today. At most 50 are
   shown; use the audit filters and pagination for the rest.
2. Open a task directly from its queue card. Review the finding and assigned people.
   Assignment controls offer active accounts with compatible roles. Legacy names
   are marked and must be reconciled with active accounts before progression.
3. Owners document remediation and upload fictional evidence, then request
   verification. Reviewers verify independently and close or return the finding.
   Save creates a revision; Cancel editing discards unsaved changes. The main audit
   table shows the key status, assignment, severity, and deadline columns; full
   details remain in the editor and history.
4. Administrators review Workspace readiness: account-role coverage, assistant
   configuration, and the last recorded successful backup. Security controls are
   collapsed under Account security until needed.
5. Take a backup and periodically test restoration. Review security events and save
   independent checkpoints as described in the security activity guide.

## Checks and troubleshooting

`python3 schooldesk.py doctor` verifies SQLite integrity and the security-event
chain, then reports active role counts, assistant readiness, and backup warnings.
Secret values, model names, credentials, database paths, and record content are not
included in its JSON report. Missing workflow roles or an old/unrecorded backup
are warnings, not proof that the database is unusable. Integrity/configuration
failures return a nonzero exit status. A healthy check does not establish encrypted
storage, off-site recovery, production readiness, or clinical/education compliance.

`GET /health` is an unauthenticated local liveness check with Host/Origin protections.
It reports only service identity and database connectivity, not account/configuration
details. The administrator-only readiness API is `/api/operations/status`; it checks
connectivity and operational metadata, not a full integrity scan on every request.

- First launch refused: run `schooldesk.py init`, or explicitly opt into demo mode.
- Missing owner/reviewer in selector: provision an active account with the needed role.
- No tasks in My work: confirm assignment, status, and exact username. Completed
  tasks and owner tasks awaiting reviewer action are intentionally absent.
- AI configuration warning: use offline mode or configure the supported provider
  environment; no provider call is made by the doctor.
- Backup warning: run a snapshot and check the protected backup folder. A recorded
  timestamp records a successful verified command, not proof the file still exists
  or that a scheduler is running. A restored older DB may contain an older timestamp.
- Busy port or database access: select an unused port, check file ownership, and
  confirm another process is not holding the database. Do not expose the server
  publicly as a workaround.

## Backups and restart

```sh
python3 maintenance.py snapshot backups
python3 maintenance.py verify backups/ACTUAL-SNAPSHOT-FILENAME.db
```

Snapshot output now includes its generated filename; successful backup/snapshot
commands record completion time in the source database. Failed commands do not
advance that time. A warning appears if no timestamp exists or it is over 48 hours
old. This is a suggested local operational signal, not a legal retention requirement.
Configure the host scheduler separately for unattended backups. Follow
[operations and retention](operations.md) for restoration and preview-first pruning,
and [security activity](security-activity.md) for trusted checkpoints.

Before upgrading, stop the server and take a verified backup. On restart the schema
migrates in place. Provisioned accounts, audit revisions, and existing history are
preserved. Never replace a running database or silently discard failed integrity
checks. Use a restored copy and inspect account state when recovery is necessary.
