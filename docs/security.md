# Schooldesk security model

This change hardens a loopback-only fictional-data prototype. It is not an internet
hosting configuration, a penetration-test certification, or a compliance claim.

## Boundaries and implemented defenses

| Boundary | Threat | Defense |
|---|---|---|
| Browser to local server | CSRF, cross-site access, DNS rebinding | Exact single Host allowlist; same-origin Origin and Fetch Metadata checks; custom write header; strict JSON content type; no CORS opt-in |
| API access | Unauthorized local requests | Optional high-entropy shared bearer token on all API routes; constant-time comparison; in-memory browser token |
| Rendering | Stored script injection, framing, resource injection | Existing text-only rendering; CSP; frame denial; no-sniff; no-referrer |
| Files | Arbitrary file reads and directory listings | Explicit UI path allowlist; HEAD disabled |
| Parsing | Large, ambiguous, malformed, or stalled bodies | Size/length checks; duplicate-key rejection; object-only JSON; finite constants; read timeout |
| Database | Accidental local disclosure, internal error leakage | Owner-only POSIX database mode; new parent directories owner-only; generic database failure responses |
| Logs and caches | Tokens or record data retained accidentally | No raw request logging; no-store responses; tokens excluded from persistent browser storage |
| Development | Regressions and accidental secret commits | Offline adversarial tests in CI; secret/database ignore patterns |

## Operational requirements

Set a randomly generated `SCHOOL_ACCESS_TOKEN` through a protected server environment
before enabling the optional access gate. Do not paste it in a URL or commit it.
Protect the machine, application source, parent directories, database, and backups.
Changing the variable and restarting rotates the token. Locking the browser tab
clears its in-memory state; it does not revoke a copied token at the server.

Token access is one shared workspace gate, not individual authentication. An owner
and reviewer typed into forms can still impersonate one another. All token holders
have the same API access. Same-origin script compromise or malicious browser
extensions can act with the user's access. Local processes can reach the service,
and without a configured token there is no credential gate. Loopback binding is
retained; never expose this plain-HTTP prototype publicly.

## Remaining risks and next work

- Individual accounts, authenticated reviewer identities, roles, and authorization.
- Request/AI quotas, connection concurrency limits, and broader denial-of-service defense.
- Pagination for record/history reads, encrypted storage, backup restore testing,
  retention/deletion policy, and protected security-event logging.
- Managed HTTPS deployment, session lifecycle, and security monitoring before any
  future network service. SQLite history is not tamper-proof against filesystem access.
- General PII detection is not implemented; AI provider processing still requires
  user confirmation and synthetic notes. No live model call is part of CI.

## Tests

Run `python3 -m unittest discover -s tests -v`. Security tests exercise token denial
and acceptance, cross-site requests, missing custom headers, content types, body
limits, malformed/duplicate JSON, unknown file paths, headers, generic storage
errors, invalid identifiers, database permissions, and secret-free request logging.
Browser interaction and a full penetration test are not covered by this suite.
