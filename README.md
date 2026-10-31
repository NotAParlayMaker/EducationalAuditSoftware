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
student editing, deletion, and grade calculations are future work. Audit findings support editing and revision history.

## Validation

```sh
python3 -m unittest discover -s tests -v
```

## Development scope

This is a local prototype, bound to loopback. It has optional shared-token API access, and optional individual accounts with server-enforced roles, but no
encryption management or production deployment configuration. Use
fictional data only. Before handling real school records, add authenticated
access, authorization, retention rules, backups, and appropriate privacy controls.
No external services or credentials are required.


## Audit drafting assistant

The assistant panel prepares a draft IT audit finding, proposed priority, and a
remediation checklist. Choose **Review in audit form**, edit the finding, then
**Save record** to persist it. The assistant cannot write records, resolve findings,
access the database, or run tools. Recommendation and priority are displayed for
review and are not persisted in the current audit schema.

Default `SCHOOL_AI_MODE=offline` uses a deterministic generic template. It is not
model analysis and makes no external requests. Existing school modules still work
without configuration or dependencies.

For real model-generated suggestions, configure the server environment:

```sh
export SCHOOL_AI_MODE=openai
export SCHOOL_AI_MODEL=your-supported-chat-completions-model
# Set OPENAI_API_KEY through your server's secret configuration.
python3 app.py
```

Use a model supporting Chat Completions JSON-object responses. No SDK is required.
The fixed endpoint is `https://api.openai.com/v1/chat/completions`; keys stay on the
server. Each request requires the external-processing checkbox. Only the entered
note and fixed instructions are sent, never database records. Requests set
`store: false`; this does not guarantee zero provider retention. Review your
provider's data terms. A configured external mode without confirmation fails closed;
it does not silently send data or switch modes.

Use fictional notes only. Remove names, student details, credentials, and other
sensitive content. A narrow contact/identifier guard is not general de-identification.
The assistant is for IT audit drafting, not student evaluation, discipline,
compliance certification, or automated decisions. See [the threat model](docs/ai-safety.md).

Provider responses are size-bounded, validated against exact fields, and displayed
as text. Timeouts and invalid responses leave records unchanged. Credentials and
raw provider errors are never returned to the browser. Existing unauthenticated
local-prototype limitations still apply; do not expose this service publicly.

## Audit lifecycle

Audits now support **Draft → Open → In progress → Awaiting verification → Closed**.
A reviewer can return a finding to In progress; closed findings can be reopened to
Open with a reason. Use **Edit / transition** on a row, choose the next status, and
save the revision. Use **History** to inspect timestamped snapshots and actors.

- Draft: area, finding, and change actor are required.
- Open: also requires owner, severity, and an ISO due date.
- In progress: requires a remediation plan.
- Awaiting verification: requires evidence text/reference and a reviewer different
  from the owner. Evidence can reference the controlled attachments available from the Evidence action.
- Closed: requires verification notes, a closure reason, and the reviewer as actor.
- Reopened: requires a reopen reason; current closure/verification notes are cleared,
  while previous snapshots remain available in history.

Updates use revision numbers and return HTTP 409 for stale saves. Record updates
and their history entries commit atomically. History is append-only through the
application API, not tamper-proof against someone with database access. Actors in demo mode are
self-reported. Provisioned account mode uses authenticated actors and reviewer
roles as described below.

Startup migrates existing databases in place without removing findings. Legacy
Resolved findings become Awaiting verification because prior verification evidence
was not recorded. Legacy Open/In progress rows retain their status and must satisfy
the new required fields when next saved. Migration records a baseline history event,
not reconstructed historical activity. Back up your SQLite file before upgrading.

The AI assistant remains unable to save or close findings. AI drafts enter the
form in Draft status. Evidence, recommendations, and decisions require human review.


## Local cybersecurity controls

Configure `SCHOOL_ACCESS_TOKEN` in the server environment to protect all API reads,
writes, history, and assistant requests. Use a randomly generated secret of 32–256
printable ASCII characters without spaces, for example generated with
`python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. Keep it in a
password manager or secret configuration, never source control, a URL, or an issue.
Enter it in the Workspace access panel; it is held in tab memory, not browser
storage. Lock / clear tab reloads the page and clears in-memory data and the token.
Rotate by changing the server environment and restarting; all old tokens stop working.

Without the variable, the service retains local demo access. An explicitly empty or
weak configured token fails startup. A shared token does not identify individual
users or enforce reviewer roles. Keep the server bound to loopback. This prototype
has no TLS and must not be exposed on a network or used with real student data.

All API requests enforce Host, Origin, and browser Fetch Metadata checks. POST/PUT
clients must send `Content-Type: application/json` and `X-Schooldesk-Request: 1`.
If token protection is enabled, also send `Authorization: Bearer <token>` on every
API request. The custom header is a browser CSRF defense, not a secret or login.
Ordinary request bodies are capped at 8192 bytes (the evidence-upload route has
a separate bounded 360,000-byte JSON envelope) and parsed as JSON objects; duplicate keys,
non-finite constants, transfer encoding, and malformed bodies are rejected.

Responses include a restrictive Content Security Policy, clickjacking protection,
no-sniff, no-referrer, and no-store headers. Only the four UI resources are served;
HEAD and arbitrary filesystem paths are unavailable. Request/body reads time out.
Database errors return a generic response, raw request logging is disabled, and
POSIX database permissions are restricted to the owner. Existing parent directory
permissions, host security, backups, and disk encryption remain operator concerns.

See [the security model](docs/security.md) for scope and remaining work.


## Individual accounts and verified review

Provision accounts from the local terminal; the first must be an administrator:

```sh
python3 manage.py create-user school-admin --role administrator
python3 manage.py create-user school-auditor --role auditor
python3 manage.py create-user equipment-owner --role remediation_owner
python3 manage.py create-user audit-reviewer --role reviewer
python3 app.py
```

Passwords are prompted without echo and never supplied as command arguments. Use
unique passwords of 14–256 characters, preferably generated by a password manager.
Password hashes use PBKDF2-HMAC-SHA256 with 600,000 iterations and random per-account
salts. There are no seeded accounts or default credentials. The browser sign-in
returns a random bearer session held only in tab memory. The database stores its
hash; sessions expire after one hour. **Lock / clear tab** revokes the current session.
Restarting the server does not revoke existing sessions; they retain their expiry.

Creating the first administrator permanently enables account mode for that database.
Missing, expired, or disabled-account sessions are rejected. Legacy shared workspace
tokens cannot bypass account mode, and disabling all users never restores demo access.
Databases without provisioned accounts retain the prior local demo/token behavior.

| Role | Permissions |
|---|---|
| Administrator | All school modules; create and manage findings and assignments; close only when already assigned as independent reviewer |
| Auditor | Read IT records; create findings, assign active owner/reviewer accounts, update details, reopen; no student records or closure |
| Remediation owner | Read IT records; update remediation/evidence and progress of findings assigned to them; no reassignment or closure |
| Reviewer | Read IT records; verify assigned findings, return them for remediation, or close with notes; no changes to evidence or assignment |

All account roles can read all IT records and audit history, and use the assistant.
This is role-level access, not per-school or per-record read isolation. Only
administrators can read/write student, attendance, and grade data or change assets
and tickets. Assignment fields must contain exact active usernames with compatible
roles. Reconcile legacy free-text assignments before progressing old findings.
Historical demo actors remain unverified; account mode does not retroactively
establish their identities. New API history actors always come from the session,
regardless of browser-supplied names. Closure requires a previously assigned reviewer
who differs from the owner, preventing self-assignment-and-closure in one request.

Local account maintenance:

```sh
python3 manage.py list-users
python3 manage.py reset-password equipment-owner
python3 manage.py disable-user equipment-owner
```

Password reset and disabling revoke that account's sessions. The CLI prevents
disabling the last active administrator. Protect terminal/filesystem access: these
commands are trusted local maintenance, not remote account-management endpoints.

Login attempts have a database-backed global budget of ten per minute, including
failed attempts, unknown names, and successes. Credential failures use the same
message and password-hash work. The global budget limits username/IP rotation but
can temporarily block legitimate logins; wait a minute or investigate locally.
No MFA, password recovery email, network deployment, or per-user quotas are included.


## Evidence, usage limits, and recovery

The audit table now includes **Evidence** for controlled text/PDF attachments,
with uploader identity, SHA-256 integrity checking, and authenticated downloads.
Uploads create a new audit revision. Owner, severity, status, and overdue filters,
pagination, severity summaries, and aggregate dashboard totals support larger lists.
AI requests have persistent global/per-user budgets and a two-request concurrency
cap. Backup, restore verification, timestamped snapshots, and preview-first backup
retention are available through `maintenance.py`.

See [operations and retention](docs/operations.md) for limits, commands, scheduling,
and remaining restrictions. Backup scheduling requires configuring your host's task
scheduler; no schedule is installed automatically. Live-record deletion and a
school-approved retention policy remain required before handling real school data.

## Session controls and security activity

Signed-in users can review their own active sessions, revoke one session, or sign
out all sessions. Session lists expose public identifiers and times, never bearer
tokens or stored token digests. At most ten sessions per account are retained after
a successful login; oldest sessions are evicted. The current session is marked in
the interface. Cross-account session revocation is rejected by the server.

Password changes require the current password and a different new password of
14–256 characters. Success revokes every session and requires a new sign-in.
Password-change attempts are limited to five per account per fifteen minutes.
Passwords are cleared from form fields after submission. Reset/disable races are
rechecked before a successful login can issue a session.

Administrators can review paginated security activity and check its event chain.
Only fixed event codes, UTC timestamps, and validated account handles are stored;
unknown failed-login names, passwords, tokens, student data, request paths, and
record contents are excluded. The chain detects internal edits/reordering, but
requires an independently saved checkpoint to detect tail truncation or a full
rewrite. See [security activity and checkpoints](docs/security-activity.md).
