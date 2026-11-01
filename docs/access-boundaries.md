# Assignment access and safe startup defaults

## Who can read what

| Role | Audit findings, history, and attachments | Other modules |
|---|---|---|
| IT administrator | All findings in this workspace | IT inventory/tickets; no student modules |
| Registrar | None | Student, attendance, and grade modules; learning roster and review oversight |
| Teacher | None | Learning evidence and reviews for currently assigned classes/current enrollments; no general student/guardian or IT access |
| Auditor | All findings in this workspace | IT assets/tickets read; no student modules |
| Remediation owner | Only findings whose current owner equals the signed-in username | No assets, tickets, or student modules |
| Reviewer | Only findings whose current reviewer equals the signed-in username | No assets, tickets, or student modules |

Assignment visibility is independent of workflow status: an owner can still read an
assigned finding awaiting review or after closure. The daily queue is narrower and
shows only actionable statuses. Unassigned findings are visible to oversight roles,
not to arbitrary owners/reviewers. Write permissions and independent closure checks
remain in addition to these read rules.

The same scope applies before audit filtering/pagination, history retrieval,
attachment metadata/downloads, attachment uploads, audit changes, daily queues,
and dashboard totals/severity/overdue counts. Scope never comes from a request field.
A caller cannot change an owner filter or guess a numeric ID to expand permissions.
The account directory for assignee roles includes only self and active co-assignees
on currently accessible findings; oversight roles can list all active accounts.

Missing and unauthorized findings return the same HTTP 404 message. Attachment
IDs likewise do not reveal inaccessible files or filenames. Attachment downloads
join the parent finding's current assignment before reading content. Reassigning a
finding removes the former assignee's access on subsequent requests, including
existing attachment IDs and historic revision URLs. Information already legitimately
seen or downloaded cannot be recalled. Current assignment grants the full history
of that finding; revisions are not separately compartmentalized.

Audit write authorization, revision checks, and saving now share a write-locked
transaction. This prevents concurrent reassignment from opening a gap between
permission checks and mutation. These controls do not prevent a trusted database
administrator from modifying files directly.

## One workspace, not tenant isolation

This version has no school ID or tenant membership model. Administrators and
auditors are trusted for the entire database. Use separate protected databases
for unrelated organizations; do not interpret assignment checks as protection
between schools sharing one database. Full tenancy, MFA, encryption, and managed
HTTPS deployment remain separate work before introducing real school records.

## Account mode is the default everywhere

`schooldesk.py serve` and `app.py` both refuse normal startup until an administrator
is provisioned. Run `python3 schooldesk.py init` first. The HTTP handler also denies
protected APIs for unprovisioned databases, so constructing a different server does
not accidentally restore anonymous access. Minimal `/health`, account-mode status,
and the static sign-in page remain available; no records are returned through them.

An intentional fictional-data demo requires `--allow-demo` at server startup:

```sh
python3 schooldesk.py serve --allow-demo
```

The flag is process-local, not stored in SQLite or inferred from an environment
secret. It does not bypass account authentication when account mode is already
provisioned. `SCHOOL_ACCESS_TOKEN` can add a shared gate to an explicit demo, but
cannot turn one on or replace individual accounts. Demo-only tests explicitly opt
in; ordinary server construction defaults to closed protected APIs. A banner marks
active demo mode. Shared demos still have no individual identity or assignment
privacy and must contain only fictional data.

## Verification

The offline suite covers owner/reviewer isolation, query filters/pagination,
counts, history, attachments and filenames, uploads, reassignment, directory data,
other-module restrictions, and all default startup paths. The real Chromium smoke
test verifies that the assigned auditor/owner/reviewer workflow remains usable.
Tests use independent fixture accounts and invented records, with no external
model calls or real school data.

[Security audit upgrade steps](security-audit-response.md) document the registrar migration and mandatory demo token.

See [learning evidence](learning-evidence.md) for teacher assignment/enrollment revocation, minimal student fields, and immutable educational history.
