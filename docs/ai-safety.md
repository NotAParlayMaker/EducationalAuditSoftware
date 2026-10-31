# Audit assistant workflow and threat model

Status: local prototype. Use synthetic notes only.

## Workflow and boundaries

A user enters a fictional IT concern, selects whether external processing is
permitted, requests a suggestion, reviews the draft, and copies selected fields
into an editable audit form. Only the existing Save record action writes the
finding. New audit drafts start Open. Editing the source note discards its draft;
responses for changed input are discarded. No automated closure or execution exists.

The browser, local server, SQLite store, and optional provider are separate trust
boundaries. The assistant has no database handle. It receives only the submitted
note, not enrollment, guardian, attendance, grades, audit history, or tickets.
Provider output is untrusted data. Valid output is still an unverified suggestion.

## Threats and controls

| Threat | Control | Limitation |
|---|---|---|
| Accidental disclosure | Explicit per-request external consent; no automatic record retrieval | Basic contact guard cannot detect all personal data; fictional data only |
| Prompt injection or excessive agency | No tools, database access, or execution; drafts require separate save | Models can still produce misleading text; humans must verify evidence |
| Malicious output | Exact bounded schema; text-only rendering; no unknown fields | Valid wording may still be incorrect or biased |
| Credential leakage | Server environment only; generic provider errors | Operator must secure the host and environment |
| Browser attacks on localhost | Exact Host allowlist and same-origin POST checks | Not authentication; malicious local processes remain a risk |
| Provider outage or oversized output | Timeout, bounded read, validation, no automatic retries | Provider calls may incur cost; rate limits and quotas are future work |
| False audit closure | Only draft area/finding copied; status starts Open | Existing manual records remain editable only through future workflow work |

## Data lifecycle and next work

Assistant notes and drafts are not persisted by the application. They remain in
browser memory until discard, editing, or reload; provider processing is governed
by the provider's policies. `store: false` is not a zero-retention guarantee.
Audit findings deliberately saved by a human persist in the local SQLite database.
Default HTTP logs record request metadata, not request or response bodies.

Before real school use, add authenticated roles, retention/deletion policy,
protected backups, review history, provider quotas, and deployment hardening.
A future audit workflow should distinguish assignment, remediation, independent
verification, closure, and reopening, with immutable revision history. This change
does not implement or claim that workflow or regulatory compliance.

## Verification

Run `python3 -m unittest discover -s tests -v`. Tests cover deterministic offline
behavior, no offline network calls, required external consent, provider schema and
failure handling, origin/host rejection, and no audit write from suggestion requests.
All provider tests use mocks; no credentials or live model calls are required.
