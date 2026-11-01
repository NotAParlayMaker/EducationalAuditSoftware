# Reviewed data imports and scoped exports

The pipeline is a bounded, synchronous local batch processor, not a background
ETL platform or backup replacement. It uses existing deterministic record validators,
SQLite transactions, account permissions, and audit revision history. No model or
external service is called. Continue using fictional data only.

## Browser workflow

Sign in, open **Data imports and exports**, choose a record type, and select a CSV
or JSON file. Choose **Validate and preview**, expand the normalized rows, and
review the duplicate count. Check the review confirmation, then **Import reviewed
batch**. Nothing is inserted until commit succeeds. Invalid input reports row
positions and fixed error codes without echoing rejected cell values. Row numbers
count data records, not physical CSV lines when a quoted cell contains newlines.

Administrators can import all six record types. Auditors can import audit drafts
only. Owners/reviewers cannot import. Audit imports cannot set approval, closure,
verification, actor, IDs, or revisions. Imported findings always start Draft and
must pass the existing human-reviewed lifecycle afterward. Assignment usernames,
when supplied, must identify compatible active accounts.

Original files and preview rows are not stored in batch metadata. Validated preview
content is returned to the authorized browser for review. Batch metadata stores the
actor, resource, normalized-content digest, timestamps, status, and counters. Actual
records are persisted only on commit. Digests are not anonymization and must be
protected with the database. Browser preview/file state is cleared on sign-out.

## Formats and examples

- [Asset CSV](../examples/import-assets.csv): `tag,device,location,status`.
- [Audit draft CSV](../examples/import-audits.csv): at least `area,finding`;
  optional `owner,reviewer,severity,due_date,remediation,status`. Omit status or use
  exactly `Draft`. Empty owner/reviewer fields are valid for a draft.
- [Student JSON array](../examples/import-students.json): administrator-only.

Other exact headers are attendance `student,date,status`, grades
`student,subject,grade`, and tickets `title,requester,priority,status`. Existing
choice values and 500-character field bounds apply. Missing/extra columns and
invalid choices fail validation; values are never coerced to fit. Existing date
validation is reused. Current student/attendance/grade relationships remain free
text; this change does not infer enrollment links or resolve identities.

CSV supports UTF-8 BOM, quoted commas/newlines, and CRLF. Duplicate headers, extra
cells, missing cells, invalid UTF-8, or malformed quoting are rejected. Browser JSON
files contain an array of objects; duplicate keys and non-finite constants are
rejected by the server, not silently overwritten by browser parsing. Files are
limited to 256 KiB and batches to 200 records. The JSON request envelope is capped
at 512,000 bytes, including escaping/metadata; a file near the limit may need splitting.
All cells must be strings, and unsafe binary control characters are rejected.

## Retry, duplicates, and transactions

A valid preview creates an account-bound prepared batch with a 24-hour expiry.
The digest covers normalized records, resource, and schema version. CSV and JSON
that normalize to the same data can share a prepared batch. Changed normalized
content requires a new preview. Each account can have at most 20 unexpired prepared
batches. Recent imports show only that account's batch metadata, including expiry.

Commit revalidates current permissions, assignments, and input. All inserted
records, audit history, duplicate tracking, batch completion, and typed security
events commit in one transaction. Any row/database failure rolls the whole batch
back. A retry of a committed batch with the same data returns its original counters
and does not insert again. If a network failure leaves the result uncertain, retry
the retained reviewed batch; do not assume failure means no database commit occurred.

Duplicate detection is exact, not fuzzy identity matching. Identical normalized
rows in a batch, prior imports, or existing manual records are skipped. Prior
import fingerprints remain associated with their record even after later edits,
so replaying an old source does not overwrite reviewed changes. No upsert or
silent merge is performed. If a tracked target was removed outside the application,
commit fails for operator review. Legitimately identical real-world entities cannot
be distinguished without future unique identifiers. Preview counts are estimates;
commit reports actual inserted/skipped counts after checking current data.

## Exports

Choose JSON or CSV and **Export first page**. Export is limited to the selected
resource and current account permissions: owners/reviewers receive only assigned
audit findings; broader school/IT access follows existing roles. Export does not
include accounts, credentials, sessions, raw attachments, or security history.

Pages contain up to 200 rows in the browser, with explicit Next page controls.
The API supports 1–1000 rows. Stable ascending IDs and `after_id` prevent offset
shifts from repeating earlier IDs. Permissions are rechecked on every page;
reassignment or concurrent edits mean a multi-page export is not a point-in-time
snapshot. Use the SQLite backup tools for a complete consistent recovery copy.

JSON exports use `schooldesk.export.v1` and preserve authorized stored values.
CSV quotes cells and prefixes spreadsheet-formula-like cells with an apostrophe,
including leading-whitespace cases. This is a safety transformation, not a
byte-preserving export; review files before opening them in external tools. Exports
include IDs and potentially workflow state and are not directly accepted as import
arrays. Build a reviewed import file using supported fields if transferring data;
never use the import endpoint to restore audit approvals or revision history.

## API contract

All routes require an individual account session and existing browser request
controls. No explicit demo can bypass pipeline authentication.

`POST /api/pipeline/preview` accepts schema version 1:

```json
{"schema_version":1,"resource":"audits","format":"json","rows":[{"area":"Fictional lab","finding":"Fictional review concern"}]}
```

A CSV source uses `format: "csv"` and `data` containing CSV text. A raw JSON file
uses `format: "json"` and `data` containing its text instead of `rows`. Envelopes
are exact: do not include both. Preview returns normalized rows, validation status,
row/duplicate counts, and, when valid, a batch ID and digest.

`POST /api/pipeline/commit` accepts `batch_id`, `digest`, and the unchanged `source`
envelope. Missing/other-account batches return 404; changed or expired previews
return 409. Invalid batches never partially write. A successful result contains
`inserted`, `skipped`, and `replayed`.

`GET /api/pipeline/batches?limit=50&offset=0` lists only the caller's metadata.
`POST /api/pipeline/export` accepts exactly `resource`, `format` (`json` or `csv`),
`after_id`, and `limit`. It returns authorized rows, `has_more`, `next_after_id`, and
CSV text when requested. Rejected values and source filenames are absent from
security events; only fixed pipeline action codes and authenticated actors are logged.

No selective pipeline-metadata pruning or background job scheduler is installed.
Prepared/committed metadata is retained with the database under the operator's
retention policy. No source file is shipped to an AI provider.
