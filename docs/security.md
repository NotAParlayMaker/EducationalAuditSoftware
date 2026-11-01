# Schooldesk security model

This change hardens a loopback-only fictional-data prototype. It is not an internet
hosting configuration, a penetration-test certification, or a compliance claim.

## Boundaries and implemented defenses

| Boundary | Threat | Defense |
|---|---|---|
| Browser to local server | CSRF, cross-site access, DNS rebinding | Exact single Host allowlist; same-origin Origin and Fetch Metadata checks; custom write header; strict JSON content type; no CORS opt-in |
| API access | Unauthorized local requests | Mandatory high-entropy demo token or an individual account session on protected routes; constant-time comparison; in-memory browser token |
| Rendering | Stored script injection, framing, resource injection | Existing text-only rendering; CSP; frame denial; no-sniff; no-referrer |
| Files | Arbitrary file reads and directory listings | Explicit UI path allowlist; HEAD disabled |
| Parsing | Large, ambiguous, malformed, or stalled bodies | Size/length checks; duplicate-key rejection; object-only JSON; finite constants; read timeout |
| Database | Accidental local disclosure, internal error leakage | Owner-only POSIX database mode; new parent directories owner-only; generic database failure responses |
| Logs and caches | Tokens or record data retained accidentally | No raw request logging; no-store responses; tokens excluded from persistent browser storage |
| Development | Regressions and accidental secret commits | Offline adversarial tests in CI; secret/database ignore patterns |

## Operational requirements

Set a randomly generated `SCHOOL_ACCESS_TOKEN` through a protected server environment
to choose a stable demo token; otherwise startup generates one. Do not paste it in a URL or commit it.
Protect the machine, application source, parent directories, database, and backups.
Changing the variable and restarting rotates the token. Locking the browser tab
clears its in-memory state; it does not revoke a copied token at the server.

For unprovisioned databases, protected APIs are closed unless demo mode is explicitly enabled. In that deliberate demo mode, token access is one shared workspace gate, not individual authentication. An owner
and reviewer typed into forms can still impersonate one another. All token holders
have the same API access. Same-origin script compromise or malicious browser
extensions can act with the user's access. Local processes can reach the service,
and must present a demo token or individual account credentials. Loopback binding is
retained; never expose this plain-HTTP prototype publicly.

## Remaining risks and next work

- Account mode now provides individual accounts, authenticated actors, roles, and reviewer checks. TOTP MFA and recent-auth checks are implemented. Per-school isolation and self-service recovery remain future work.
- Login throttling is implemented. AI request budgets and a two-call concurrency cap are implemented. A 16-worker HTTP cap is implemented; broader denial-of-service defense and public hosting controls remain future work.
- Pagination and backup/restore testing are implemented. Encrypted storage,
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


## Account mode

After local administrator provisioning, every protected API route requires a valid
account session; the shared token is ignored. Passwords are salted PBKDF2 hashes,
sessions are stored as SHA-256 token digests, and expiry and active-account checks
run on every request. The public auth status endpoint exposes only whether account
mode is enabled. Sign-in retains the same browser/JSON request controls and a
per-identity exponential backoff and a 120-attempt-per-minute global backstop. Account names and roles are
available to signed-in users for assignment; password material is never exposed.

The authenticated username overrides client-supplied audit actor values. Server-side
permissions separate student administration, audit assignment, assigned remediation,
and assigned independent closure. Role checks apply to direct API calls, not just
navigation. Reviewer identity must already be assigned before closure. History
from demo mode is not retroactively authenticated. Account provisioning and resets
require trusted filesystem/terminal access; no network account administration exists.

Owners and reviewers now have assignment-scoped audit read access, including
history and evidence. Administrators/auditors retain workspace-wide audit access;
assets and tickets are restricted to those oversight roles. This is not multi-school
tenant isolation. The deployment remains loopback HTTP with synthetic data only.

Evidence, quota, backup, and retention controls are described in [operations](operations.md). File signature checks are not malware scanning; backups require protected storage.

## Security activity and session response

Account security now includes own-session inspection/revocation, all-session
sign-out, current-password-verified password changes, and administrator-only event
review. [Security activity and checkpoints](security-activity.md) documents the
bounded metadata, hash-chain verification, independent checkpoint requirement,
retention, and incident-response limitations. General HTTP logs remain disabled;
these typed events do not capture raw request or school-record content.

See [access boundaries](access-boundaries.md) for exact scope, reassignment behavior, and mandatory account-mode defaults.

MFA, evidence quarantine, encrypted backups, and reviewed deployment/monitoring examples are described in [the cloud security runbook](cloud-security-runbook.md). Actual provider rollout remains unconfigured.

Audit input fields are normalized before authorization and lifecycle checks.
Whitespace around a status cannot bypass fresh authentication, attachment
verification, or the requirement to save the independent reviewer assignment
before closure. Rejected updates leave the finding and its revision unchanged.

Current changes and operator prerequisites: [security audit response](security-audit-response.md). IT administrators no longer have student-record access; provision registrars before upgrading.
