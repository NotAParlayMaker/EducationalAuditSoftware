# Security audit response and upgrade steps

The local OS account, database operator, service identity, and host administrator
remain trusted. Loopback restricts network reachability; it does not authenticate
local software. Never use fictional-data demo mode for real school records.

## Application boundaries

1. **Demo access:** every server instance creates a random 256-bit bearer token
   unless a valid `SCHOOL_ACCESS_TOKEN` is configured. An explicit demo launcher
   prints that token once to its private terminal; the UI unlock form accepts it.
   Static UI and minimal liveness/authentication status remain public. Data reads,
   writes, history, and AI requests require the token. It is not stored in SQLite
   or browser persistent storage. Treat terminal/session recordings as sensitive.
   Local processes cannot gain data access merely by copying browser headers.
   A Unix socket/proxy has not been added. Software running as the service user or
   a privileged OS user can still steal credentials or modify the application.
2. **Login pressure:** failures are tracked using a digest of the supplied username,
   including unknown usernames. The first two failures do not delay a retry; the
   third introduces a one-second delay, doubling to five minutes. After fifteen
   minutes without a new failure the sequence resets. Rejected early retries do
   not consume the 120-per-minute global backstop. That ceiling still limits
   rotating-username CPU exhaustion and can still be exhausted by a sustained
   attacker; the gateway and worker cap provide additional bounds. Known and
   unknown identities both use password hashing on unthrottled attempts. MFA has
   a separate account budget. Operators should monitor lockouts, not assume this
   makes denial of service impossible.
3. **Least privilege:** `administrator` now means IT administrator and has **no**
   student, attendance, or grade access, including summaries, exports, and imports.
   A separate `registrar` role owns those three modules and cannot access IT
   findings, equipment, tickets, evidence, or security-event administration. No
   existing administrator is silently granted registrar access. Before upgrading,
   provision separate registrar credentials with `manage.py create-user NAME
   --role registrar`. Cloud MFA covers all roles; the optional local privileged
   policy includes registrars. This permission model is not a FERPA determination.
4. **Evidence:** UTF-8 text is the default. PDF upload requires both
   `SCHOOL_ALLOW_PDF_EVIDENCE=1` and the mandatory-scanning policy. Previously stored PDFs are also blocked while the PDF policy is disabled; the UI warns that neither a hash
   nor a clean antivirus result makes a document safe. Open permitted PDFs only in
   a sandboxed, patched viewer. Server-side PDF rendering/flattening is not included.
5. **Sessions:** account sessions have a fifteen-minute idle timeout and a one-hour
   absolute expiry. Activity updates idle time without extending absolute expiry.
   `schooldesk.py serve --revoke-sessions`, or
   `SCHOOL_REVOKE_SESSIONS_ON_START=1`, revokes every session before serving and
   records a typed event. Normal restarts preserve sessions within those limits.
   The server already caps active workers at 16, with ten-second socket timeouts.
6. **AI privacy:** external AI requires local mode and an additional operator
   opt-in, `SCHOOL_EXTERNAL_AI_FICTIONAL_ONLY=1`, plus the per-request consent.
   Cloud profile requires offline AI. Email/identifier matching is an extra guard,
   not de-identification: names, context, and indirect identifiers are not reliably
   detected. Use only fictional notes for the external experiment.

## HMAC history and checkpoint migration

Security events retain the SHA-256 chain for compatibility with existing
checkpoints. An additional HMAC-SHA256 chain authenticates each event hash and the
previous MAC with an external, random 32-byte key. A database-only writer cannot
recompute valid MACs without that key. This does not protect against an attacker
who controls the application identity, signing key, or trusted verification tool.

Set `SCHOOL_EVENT_KEY_FILE` to an operator-controlled file containing 64 lowercase
hexadecimal characters. `deploy/create_secrets.py` creates an `event-key` for new
installations. Never put the key in SQLite, a checkpoint, a shell argument, or Git.
Cloud startup requires the key. Signed histories fail startup verification if the
key is missing/wrong, a MAC is removed, or a chain is inconsistent. Automatic key
rotation and an OS-keychain backend are not implemented; retain the matching key
for every recovery point.

For an existing installation:

1. Stop the service. Preserve the original DB and independently trusted
   checkpoints; verify the old history against those checkpoints and investigate
   any mismatch before establishing a baseline.
2. Provision the key outside the DB and configure its file path in the service
   environment. Run the following as the trusted maintenance identity, with that
   environment loaded and the service still stopped:

   ```sh
   .venv/bin/python manage.py seal-events --trust-existing-history
   ```

3. The command verifies the old chain, signs its reviewed baseline, and adds a
   sealing event. It cannot prove the earlier unkeyed history was authentic. It
   refuses to reseal an already signed history. Restart only after verification.
4. Give the backup verifier a separately protected copy of the matching event
   key, readable by its service identity but not by unrelated OS accounts. The
   example uses `/etc/schooldesk/verification-secrets/event-key`, root owned with
   directory 0750 and file 0640, group `schooldesk-backup`. Keep backup encryption
   keys separate from the request service as before.

CLI backup and snapshot operations now create a no-overwrite checkpoint
automatically before recording backup success. The scheduled encrypted backup
does the same after a restore check. Local default: a `checkpoints` directory
beside the archive. Cloud backup workers require `SCHOOL_CHECKPOINT_DIR`; the
example uses a sibling of the database directory, owned by the backup identity.
An existing destination causes failure rather than replacing a checkpoint.

These files are **not** made immutable by Python. Configure append-only or
retention-locked storage and forward checkpoints off-host through an independently
administered collector. A same-host directory is not an independent trust anchor.
HMAC also cannot detect truncation to a valid signed prefix without a later
independently retained checkpoint. Previously exported unkeyed events remain
unkeyed historical evidence; migration does not rewrite external copies.

## Host encryption and maintenance authority

The live SQLite file is still plaintext. Use verified full-disk/volume encryption
for the database, swap, temporary files, and OS backups before entering real
records. Cloud startup now requires `SCHOOL_ENCRYPTED_STORAGE_ACK=1`; the example
defaults to `0`. This is an explicit operator attestation, **not** automated proof
of disk encryption, protection from an unlocked host, or database encryption.
Cloud recovery archives already use authenticated encryption with a separate key.
Local plaintext maintenance copies are for fictional data or an already encrypted
operator-controlled volume. They still contain password hashes and other private
records; even encrypted archives require protected retention and keys.

Provisioning, password/MFA resets, disabling users, user listings, startup session
revocation, doctor checks, and maintenance invocations emit typed security events.
Failed account/maintenance operations are recorded when the live DB and signing
history remain usable. Storage/key failures cannot guarantee a local event, so
collect service-manager failures independently. Shell access under the service
identity remains full administrative power. A second-admin prompt in that same
process would not prevent an OS-level attacker from bypassing it. Use separate OS
identities, restricted sudo/terminal access, monitored break-glass procedures, and
independent approval for privileged operator actions. Web MFA is already supported.

## Repository owner actions

The PR adds pinned CodeQL analysis for Python and JavaScript and weekly Dependabot
updates for Python requirements and GitHub Actions. These are configurations;
repository settings are separate. The current GitHub integration cannot read or
modify branch protection (GitHub returns 403, resource not accessible).

An owner must configure a ruleset for `main`: require pull requests, at least one
independent approval, dismiss stale approvals, require the regression and CodeQL
checks, and restrict bypasses/direct pushes, including automation. Enable secret
scanning and push protection in repository security settings. Availability depends
on repository visibility and the GitHub plan. Verify the controls with a test PR;
adding workflow YAML alone does not require human review or enable push protection.
