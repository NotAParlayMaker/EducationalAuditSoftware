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

This is a local prototype, bound to loopback. It has optional shared-token API access, but no individual user accounts,
roles, encryption management, or production deployment configuration. Use
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
  from the owner. Evidence is a reference or description, not an uploaded file.
- Closed: requires verification notes, a closure reason, and the reviewer as actor.
- Reopened: requires a reopen reason; current closure/verification notes are cleared,
  while previous snapshots remain available in history.

Updates use revision numbers and return HTTP 409 for stale saves. Record updates
and their history entries commit atomically. History is append-only through the
application API, not tamper-proof against someone with database access. Actors are
self-reported; separate names do not prove independent authenticated review.

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
Request bodies are capped at 8192 bytes and parsed as JSON objects; duplicate keys,
non-finite constants, transfer encoding, and malformed bodies are rejected.

Responses include a restrictive Content Security Policy, clickjacking protection,
no-sniff, no-referrer, and no-store headers. Only the four UI resources are served;
HEAD and arbitrary filesystem paths are unavailable. Request/body reads time out.
Database errors return a generic response, raw request logging is disabled, and
POSIX database permissions are restricted to the owner. Existing parent directory
permissions, host security, backups, and disk encryption remain operator concerns.

See [the security model](docs/security.md) for scope and remaining work.
