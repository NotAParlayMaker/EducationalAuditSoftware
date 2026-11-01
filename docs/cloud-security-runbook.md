# Security controls and reviewed cloud rollout

Status: application controls and example deployment files are implemented. No cloud
account, domain, certificate, antivirus daemon, SIEM receiver, backup bucket, or host
scheduler has been provisioned by this change. Use fictional data. A real rollout
requires a chosen provider/domain, security review, load tests, and provider-specific
IAM, firewall, encrypted-volume, monitoring, and recovery configuration.

## Application controls

Install the pinned security dependency set in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: -r requirements-security.txt
```

The core local application can still run with standard-library features, but MFA,
authenticated encrypted backups, and the full test suite need `cryptography` and
its pinned dependencies. No custom encryption primitive or wallet SDK is used.

### MFA and fresh authentication

Accounts can enroll a standard six-digit, 30-second TOTP authenticator through
Account security. Enrollment requires the current password, expires after ten
minutes, and is verified before activation. The seed is encrypted using Fernet and
bound to the username. Only its encrypted form is stored in SQLite. Supply
`SCHOOL_MFA_KEY` or `SCHOOL_MFA_KEY_FILE` outside the database; never put a real key
in git. Direct and file sources cannot both be configured. Secret files must be
regular files without group-write or any world access; managed secret mounts and
read-only service groups are supported.

Activation revokes all sessions and shows eight recovery codes once. Store them
privately. Recovery hashes are stored, and every code is single use. TOTP counters
are consumed transactionally to reject replay across sessions. A code used to confirm
enrollment cannot immediately be reused to sign in: wait for a new code or use a
recovery code. Wrong/missing factors use generic credential failures. Confirmation
attempts are limited to five per fifteen minutes. Enabled-account factor failures
have a separate five-per-fifteen-minute budget, in addition to global login throttling;
lockout events identify the verified account target without retaining attempted codes.

`SCHOOL_REQUIRE_MFA=1` requires admins/reviewers to enroll locally. The cloud profile
requires every account role. The minimum MFA policy is persisted in SQLite and
cannot be weakened just by removing an environment flag. An unenrolled account gets
only a restricted enrollment session; it cannot fetch records, directory data,
exports, or administrative events. Already-enabled MFA always requires a factor,
even when optional enforcement flags are absent.

Audit closure, import commits, exports, password changes, and evidence rescan/rejection
require authentication within the last five minutes. Use Reauthenticate with the
current password and a fresh factor when enabled, then explicitly retry the action.
Reauthentication consumes the existing authentication budget, refreshes the current
session only, and does not extend its original one-hour absolute expiry. TOTP is not
phishing-resistant MFA; keep server/device time synchronized, and alert on drift. A future reviewed IdP/WebAuthn integration is stronger.

Trusted local operators can recover a lost authenticator:

```sh
python3 manage.py reset-mfa USERNAME
```

This resets enrollment/recovery material and revokes sessions, records an event,
and does not remove mandatory policy. The user must enroll again before data access
when enforcement applies. Perform identity verification outside the application.
Do not casually replace the MFA encryption key: preserve key versions independently
for recovery, or plan an explicit reset/reenrollment migration. Password resets alone
do not bypass MFA.

### Evidence quarantine

Local fictional-data mode defaults to scanning disabled and clearly marks unscanned
files. `SCHOOL_EVIDENCE_SCAN=clamd` enables local clamd INSTREAM scanning via
`SCHOOL_CLAMD_SOCKET`. The cloud profile requires that configuration. No filename,
command, or external destination is passed from uploaded input to a shell or scanner
path; only bounded bytes go to the fixed local Unix socket.

A clean scanner response releases the attachment. Infection, an unavailable scanner,
unknown responses, or integrity failures remain quarantined and cannot be downloaded.
Turning scanning off does not release previously quarantined files. Rescanning
requires an active scanner, an oversight role, and fresh authentication. Scanning
runs outside the SQLite write lock; permissions and content identity are rechecked
when results are committed. Scans do not grant workflow approval.

Verification/closure checks every active attachment's release status, SHA-256, and
byte length. Oversight staff may reject an attachment with a recorded reason;
rejected bytes remain retained and blocked, and the rejected item no longer blocks
subsequent review. Rejected files cannot be rescanned into released status. A rescan
that quarantines evidence on a closed finding reopens it and clears current closure
notes, preserving history. Rejection of closed-finding evidence requires reopening
first. No silent deletion is added.

ClamAV is an external daemon, not bundled malware definitions. Run it as a separate
restricted user, update its signatures, alert on update failures, and restrict the
socket (for example group `clamav`, mode 0660). Do not enable an exposed TCP listener.
Review engine limits such as StreamMaxLength, MaxScanSize, MaxFileSize, MaxRecursion,
MaxScanTime, and AlertExceedsMax. The app bounds uploads to 256 KiB but a scanner
still needs parser isolation and decompression limits. Antivirus is not a guarantee
of benign content or PDF sanitization.

## Separate service identities and keys

The examples target a Linux host with systemd, nginx, and ClamAV packages. Review
every path/account before installing anything. Use separate service users/groups:

- Request service: user `schooldesk`, primary group `schooldesk-data`, supplementary
  `schooldesk` and `clamav`. Source/venv are root-owned read-only under `/opt/schooldesk`.
- Database directory: `/var/lib/schooldesk`, owner `schooldesk:schooldesk-data`,
  setgid mode 2750. Cloud DB files are 0640 so a dedicated backup identity can read
  them; local default DB files remain 0600. Do not add ordinary users to the data group.
- Backup worker: user/group `schooldesk-backup`, supplementary `schooldesk-data`.
  It has read-only source access, its own key/archives, and no MFA encryption key.
- Backup archives: `/var/lib/schooldesk-backups`, owner backup worker, mode 0700,
  preferably a separate encrypted volume. The request service has no access.
- Receipt directory: `/var/lib/schooldesk-backup-status`, owner
  `schooldesk-backup:schooldesk-data`, setgid mode 2750. The worker atomically writes
  a 0640 receipt; the request service can read but not write it.
- Security feed: a separately provisioned setgid directory owned by `schooldesk`
  with a dedicated collector-reader group, mode 2750. Give the collector read access
  to segments, not the raw database or application secrets.

`deploy/create_secrets.py APP_SECRET_DIRECTORY BACKUP_SECRET_DIRECTORY` creates
new exclusive owner-only files and never prints their contents. It does not rotate
or overwrite existing secrets. Run it only in protected directories outside the
checkout, then configure these separate permissions:

- App secrets directory/root-owned files: group `schooldesk`, directory 0750,
  files 0640 (`proxy-token`, `mfa-key`, optional provider key).
- Backup secrets directory/root-owned files: group `schooldesk-backup`, directory
  0750, files 0640 (`backup-key`).

The request service rejects a cloud environment containing backup-key configuration.
Use [service.env.example](../deploy/service.env.example) and a separate
[backup.env.example](../deploy/backup.env.example). Environment files contain secret
paths and operational settings, not committed credentials. Managed secret mounts
can replace these example files. Live SQLite storage is still plaintext at the
application layer; require provider volume encryption and appropriate host access.

## HTTPS gateway and application startup

Review [nginx.conf.example](../deploy/nginx.conf.example). Replace the reserved
example hostname, install a real certificate/key, and generate a private header
include with `deploy/render_gateway_token.py NEW_INCLUDE_PATH` using the protected
`SCHOOL_PROXY_TOKEN_FILE` configuration. The output is exclusive and 0600; never
print or commit it. Run `nginx -t` with actual paths before enabling the gateway.

The gateway example terminates TLS 1.2/1.3, redirects HTTP, limits login/general
request rates and concurrent connections, bounds bodies/timeouts, returns fixed
JSON limit errors, and overwrites a shared proxy-authentication header. The backend
remains on 127.0.0.1. In cloud mode it accepts only loopback peers with that token,
the configured public Host, and matching HTTPS Origin. Client forwarded headers do
not establish scheme, identity, roles, or trust. Direct backend calls without the
gateway are rejected. MFA is still required after passing the gateway.

The request service refuses root execution, missing gateway/MFA secrets, invalid
origins, or missing scanning configuration. `--allow-demo` is forbidden in cloud
mode. Provision accounts as the service identity using the protected service
environment, not as root owning the database. One possible operator-managed
interactive setup on the target Linux host is:

```sh
systemd-run --pty --wait --collect --uid=schooldesk --gid=schooldesk-data \
  -p 'SupplementaryGroups=schooldesk clamav' \
  -p WorkingDirectory=/opt/schooldesk \
  -p EnvironmentFile=/etc/schooldesk/service.env \
  /opt/schooldesk/.venv/bin/python schooldesk.py init --username school-admin
```

Create the remaining accounts through `manage.py` under the same service identity.
Review [schooldesk.service](../deploy/schooldesk.service) before installation.
It applies filesystem hardening and defaults to loopback-only egress. External AI
needs a separately reviewed local egress proxy with a provider allowlist; the example
does not silently grant general Internet access. Keep AI offline until that path
and provider retention/spending controls are configured.

Bind/firewall only the gateway's intended public ports. Use a managed, MFA-protected
administrative access path rather than public password SSH. TLS renewal, DNS, cloud
IAM, instance patching, provider firewall/WAF policies, host capacity, and account
lifecycle remain provider-specific work. Rate limits are conservative examples;
load-test school/NAT scenarios before changing them. These templates have not been
run on a real cloud host or validated against real certificates in this chat.

## Encrypted backups and recovery

Use a separate backup-worker environment for:

```sh
python3 secure_backup.py backup NEW_FILE.db.enc
python3 secure_backup.py restore FILE.db.enc --destination NEW_RESTORE.db
```

Encryption uses authenticated Fernet with a separately supplied backup key. It is
bounded to 64 MiB databases; larger deployments need reviewed streaming/managed
backup tooling rather than disabling limits. Corrupt/wrong-key ciphertext fails
before a destination is created. Existing destinations are never overwritten.
Private temporary snapshots use restricted permissions and are removed afterward;
that is not secure erasure, so use an encrypted temporary volume as needed.

Review the backup service/timer and `deploy/run_backup.py`. The job creates an
archive in a private temporary file and publishes it only after the complete file
has been flushed. Restored database copies remain private until their integrity
checks pass. Publication never overwrites an existing destination. On POSIX hosts,
the containing directory is synced before success is reported. Security-feed
segments use the same publication rules, and become durable before their cursor
advances; a failed cursor update can be retried without duplicating the segment.
These guarantees require a local filesystem supporting hard links and directory
fsync. A failed operation can leave a complete published artifact; preserve it
and use a new destination rather than overwriting it. Forced process termination
may leave hidden temporary files in the protected directory. Investigate failed
jobs before removing leftovers; these changes do not provide off-site durability.

The scheduled job creates an
encrypted snapshot, tests restoration, anchors the exact recovery copy, and writes
an independent success receipt only after all steps succeed. No backup key is given
to HTTP workers. The timer example is daily at 04:00 UTC; select the deployment's
actual schedule and recovery objectives. Plaintext backup/snapshot/restore CLI
commands are refused in cloud profile; trusted internal copies remain necessary
inside the encryption/recovery process.

Session tokens and recovery-code hashes are removed from backup copies. Restoring
an old database must not reactivate a used recovery code; existing recovery codes
will not work after restore. TOTP counters are advanced to at least the copy's current
window, so wait for a fresh code. Preserve the matching MFA encryption key separately;
use trusted reset/reenrollment if an authenticator/key is lost. Review restored
roles, password changes, and disabled state before reopening access.

Copy archives, opening bundles, and checkpoints to a separately administered,
encrypted, versioned destination with retention locks. Give the backup producer
append-only storage permissions and keep delete/admin powers separate. Neither
cloud storage nor off-site transfer is configured by these files. Monitor timer
failures, storage capacity, backup age, and restore tests; keep encrypted-archive
retention under an approved policy. Existing plaintext pruning commands do not
prune `.db.enc` archives or anchor bundles.

## Independent security monitoring

`security_feed.py DIRECTORY` exports up to 1000 new allowlisted events per run into
bounded JSONL segments. It verifies the prior prefix, rejects a conflicting segment,
flushes output before advancing the cursor, and can resume without duplicating
committed segments. The feed contains account handles/action metadata, not passwords,
MFA seeds/codes, model notes, rejected source values, or request bodies.

Review the feed systemd service/timer and [Fluent Bit example](../deploy/fluent-bit.conf.example).
The collector needs its own protected environment for a real TLS receiver and
submit-only token; the request application must not receive that credential. The
example hostname is reserved and does not send data anywhere until configured.
Require the receiver to retain prior hashes, detect gaps/conflicts, alert on failures,
and prevent overwrite/deletion by the application principal. Monitor agent buffering:
the example 256 MiB cap can fill during an outage and is not lossless indefinitely.

A local feed, cursor, backup receipt, or private anchor bundle is not independent
protection against host compromise. Off-site retention/witnesses and alerts complete
that boundary. No SIEM message, cloud deployment, certificate, or public-chain
transaction has been sent or created by this implementation.

## Validation and release gate

The test suite covers RFC TOTP vectors, encrypted/bound seeds, setup-only sessions,
recovery/OTP replay, throttling, step-up approval/export, scanner framing/outages,
quarantine/rejection, secret-file/gateway checks, encrypted backup authentication,
scheduler recovery/anchor matching, protected receipts, and incremental-feed tampering.
The real browser smoke test exercises MFA enrollment, recovery-code login, and
step-up export in addition to audit/evidence/pipeline flows. Model responses are
mocked. Real nginx/certificates, provider IAM/firewalls, real ClamAV signatures,
off-site collectors, and production load/penetration tests require the chosen target.
