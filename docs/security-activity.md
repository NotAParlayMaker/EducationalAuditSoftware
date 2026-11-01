# Security activity and account recovery

## User controls

The Account security panel appears after an individual account signs in. **Show
active sessions** lists up to ten sessions for that account, with creation/expiry
times and a current-session marker. IDs are random public references, not bearer
tokens or token digests. A user can revoke a single owned session or choose **Sign
out all sessions**. Cross-account IDs return a generic not-found response.
Revoking the current session clears local sensitive views and requires sign-in.
Other tabs lose access on their next request. Requests started before local
sign-out are discarded if their results arrive after the session changes.

Changing a password requires the current password and a different 14–256-character
new password. All account sessions are revoked transactionally with the password
update, including the current one. Attempts are budgeted per account at five per
fifteen minutes. Failure and throttle events never include passwords. This does
not replace the existing global login budget. A login rechecks stored credentials
and active state after hashing, so a concurrent reset cannot issue a new session
using stale credentials. Administrator CLI resets/disables remain available.

Session metadata is migrated in place for existing databases; no new bearer token
is reconstructed or exposed. Successful sign-in enforces ten retained sessions
per account, evicting older sessions. Existing one-hour absolute expiry remains.
Session expiry requires no browser timer or background cleanup to deny access.

## Event content and access

The administrator-only paginated viewer records account creation, disablement,
local password reset, login success/failure/throttling, password change attempts,
and session revocation/eviction. Demo mode and non-administrator accounts cannot
read the event API. Local CLI account maintenance uses the reserved actor label
`local-maintenance` as provenance, not as a remote authenticated identity.

The stream begins at this upgrade; earlier account activity is not reconstructed.
Each row contains an ID, UTC timestamp, fixed event code, validated actor/target
account handles, previous hash, and event hash. No arbitrary detail field exists.
Failed login inputs are deliberately not retained, even if they resemble known
usernames. Passwords, session tokens/digests, prompts, record values, evidence
contents, raw paths, network addresses, and browser fingerprints are excluded.
Account handles themselves are sensitive operational metadata; restrict database,
backup, and event-viewer access accordingly.

Ordinary login failures are recorded within the 120-attempt-per-minute global backstop and per-identity exponential backoff.
Repeated throttle requests add at most one throttle marker per budget window,
preventing unlimited event creation from that response. Password attempts likewise
record one throttle marker per exhausted per-account window. Malformed requests,
generic authorization denials, and every HTTP access are not logged by this change;
this is not a complete intrusion-detection or security-monitoring system.

## Chain verification and trusted checkpoints

Event insertion runs under the same SQLite transaction as successful account or
session changes. Canonical JSON hashes link each event to its predecessor. The
viewer checks internal continuity and hashes. There is no network API for modifying
or deleting events. This is append-only through the application, not tamper-proof
against direct filesystem/database access.

A database writer could truncate the tail or rewrite an unkeyed chain. With the
external-key HMAC policy, rewriting requires the signing key; detecting a valid
prefix truncation still requires an independently retained later checkpoint.
Detect this by preserving a checkpoint independently before an incident:

```sh
python3 maintenance.py security-checkpoint checkpoint-2026-10-31.json
python3 maintenance.py security-verify --checkpoint checkpoint-2026-10-31.json
```

Run after starting the upgraded app once so migration has created the event table.
The first command exclusively creates a new owner-only file containing the event
count and head hash. It does not overwrite an existing checkpoint. Save it in
separately protected storage; keeping it only beside a writable database does not
provide an independent trust anchor. Later events are allowed: verification matches
the saved checkpoint as a chain prefix. A shorter or rewritten prefix fails.

`security-verify` without a checkpoint checks internal consistency only. A checkpoint
with zero events cannot anchor real activity. There is no signature, remote witness,
external anchoring service, or claim of cryptographic nonrepudiation. Take a first
checkpoint after account provisioning and preserve newer checkpoints periodically.
On failure, preserve the original database and checkpoint before investigating.

Backup/restore tools now reject internally inconsistent event chains. Restoring an
older backup also restores older security history and may not match a newer trusted
checkpoint; document that recovery explicitly and retain the old checkpoint rather
than silently replacing it. Session tokens are still invalidated in backup copies.

## Retention and verification

Events are retained with the database. No automatic event pruning is introduced:
removing prefixes would require a reviewed archival/checkpoint protocol and a
school-approved retention policy. No background log shipping or external alerts
are configured.

The offline suite covers event privacy, administrator access, session ownership,
password rotation and throttling, ten-session limits, credential-reset races,
session schema migration, transactional rollback, edits and tail truncation relative
to a checkpoint. The optional browser test covers session controls, password change,
administrator history, and the full audit workflow using a temporary synthetic DB.

An external-key HMAC chain, explicit legacy sealing, automatic backup checkpoints, idle session expiry, and additional CLI events are described in [the security audit response](security-audit-response.md). That document supersedes earlier unkeyed-chain and optional-checkpoint deployment assumptions.
