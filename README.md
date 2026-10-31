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
