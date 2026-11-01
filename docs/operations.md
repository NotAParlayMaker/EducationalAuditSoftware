# Schooldesk operations and retention

These tools support a local fictional-data prototype, not a managed production
service. Use protected local storage and review the account setup in README first.

## Evidence and AI boundaries

Signed-in auditors/administrators and assigned remediation owners may upload evidence
to an open finding. Reviewers can download, but cannot upload or replace evidence.
Owners/reviewers can read evidence only for their currently assigned findings.
Administrators/auditors retain workspace-wide audit oversight. Multi-school tenant
isolation is not implemented.
Uploads are limited to 256 KiB per file, 20 per finding, and simple ASCII filenames.
Only UTF-8 text and PDF-signature files are accepted. This is not malware scanning
or PDF sanitization. Treat downloaded files as untrusted and keep viewers updated.

Evidence is stored as immutable BLOBs with uploader, timestamp, byte length, and
SHA-256. Downloads recheck the checksum, require API access, use generated filenames,
and are forced attachments rather than browser-embedded documents. Uploading bumps
the audit revision and records a history event, so reviewers cannot close a stale
revision from before an attachment changed. Closed findings reject new attachments.
No evidence content is sent automatically to an AI provider.

External AI requests have global and per-user fixed-window budgets of ten per
minute and 100 per UTC day. Budgets persist in SQLite and count attempts, including
provider failures. At most two external requests execute concurrently per process;
quota or concurrency exhaustion returns HTTP 429 without calling the provider.
Offline templates make no provider calls. Request limits are not dollar spending
limits: configure billing/project spending controls with the provider as well.
The local HTTP server also caps concurrent workers at 16; this is not a full public-facing denial-of-service defense.

## Backup, verify, and restore

Initialize the application database and then run from the repository:

```sh
python3 maintenance.py snapshot backups
python3 maintenance.py verify backups/schooldesk-TIMESTAMP-RANDOM.db
python3 maintenance.py restore backups/schooldesk-TIMESTAMP-RANDOM.db --destination restored-school.db
```

Use the actual timestamped filename produced in the backup directory, not the
placeholder. `backup PATH` can also create a specifically named snapshot. SQLite's
online backup API produces a consistent copy while the application is running.
Integrity and required-table checks run before success is reported. Destination
files are created exclusively with owner-only permissions and never overwrite
existing files. Backups contain school records, password hashes, and evidence;
protect them as sensitive files and use encrypted storage. They are not encrypted
by this tool. Session tokens are invalidated in backup copies.

Restoration always targets a new file. Verify and inspect the restored database,
stop the server, point `SCHOOL_DB` at it, then restart and sign in again. Review restored account roles and disabled states,
and reset credentials that changed since the snapshot; backups contain older
account state as well as older records. Do not
replace a live database file. Retain the old file until recovery is confirmed.
The automated test suite performs backup/restore checks, including data preservation
and session invalidation; this does not replace testing your chosen storage medium.

For unattended backups, configure the operating system's task scheduler to run
`python3 maintenance.py snapshot /protected/path/backups` from the repository with
the same `SCHOOL_DB` environment. Use a protected service account and absolute
Python/repository paths. Daily is a starting interval for a demo; choose an interval
and recovery target appropriate to the deployment. No host scheduler is installed
by this PR, and this chat environment is not a persistent backup service.

## Retention and deletion

A backup retention tool defaults to a 30-day age and previews deletions:

```sh
python3 maintenance.py prune-backups backups --older-than-days 30
python3 maintenance.py prune-backups backups --older-than-days 30 --apply
```

Only regular, non-symlink files matching the tool's timestamped snapshot naming
pattern are candidates. Arbitrarily named databases and manually named backups are
not deleted. Review a preview before scheduling the applied command. Keep a verified
recovery copy before removing older snapshots. File deletion is not secure erasure.

Live audit findings, evidence, and revision history are retained until an explicit
school-approved retention/deletion policy is implemented; closing a finding never
deletes evidence. Do not invent a legal retention period. Prototype fixtures can
be retired by stopping the app and securely disposing of the entire disposable
database and its backups. Selective student-data deletion and evidence holds remain
future work before real school records are introduced.

## Lists and summaries

List APIs accept `limit` (1–100, default 50) and `offset` (0–1,000,000). Audit lists
also accept exact `owner`, `severity`, and `status`, plus `overdue=1`. SQL uses bound
parameters. The browser has owner/severity/status/overdue filters and Previous/Next
controls; free-text search applies to the current page. History pages contain up
to 100 revisions. Dashboard totals use aggregate queries and omit student totals
for non-administrator accounts. Overdue compares date-only deadlines with UTC today.


## Optional browser smoke test

With Playwright and Chromium installed in a development environment, run
`python3 tests/browser_smoke.py`. Set `SCHOOL_TEST_CHROMIUM` to an existing Chromium
executable if using a system browser. The script uses a temporary fictional database
and local ephemeral port, verifies sign-in and the auditor/owner/reviewer workflow,
attachment upload/download, verified closure, history, and logout, and removes its
database afterward. Browser dependencies are optional and are not required by the
default offline unit suite. The development run used system Chromium successfully.

For first launch, daily queues, and readiness checks, use [the operator guide](operator-guide.md).
