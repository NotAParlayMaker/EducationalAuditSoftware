# AI abuse defenses and optional external integrity anchoring

## What “AI attacks” means here

Prompt injection is malicious instruction text supplied to an AI model, directly
or embedded in documents or another model's output. The source could be a person,
Claude, OpenAI, or any other system. There is no special provider-specific defense
that makes all such content trustworthy. This application currently has an OpenAI
adapter, not a Claude integration. Cloud infrastructure attacks are a separate
problem involving hosting, accounts, networks, and secrets.

The application keeps AI capability narrow rather than relying on detecting every
malicious phrase. Supplied notes are serialized as an explicitly untrusted JSON
value under a user message; they cannot replace the fixed system message. The
request has no tools, functions, database handle, filesystem interface, attachment
retrieval, or record-writing protocol. The model receives only the confirmed note,
never account sessions, server keys, or automatically retrieved records.

The provider adapter now:

- Rejects redirects, so an Authorization header cannot be forwarded to another host.
- Uses only the fixed HTTPS provider endpoint, existing TLS/proxy trust, and bounded
  response reads with a timeout; no endpoint supplied in a note is contacted.
- Rejects duplicate JSON keys, non-finite values, incomplete/refused responses,
  function/tool requests, incorrect message roles, and extra or invalid draft fields.
- Applies a derived Unicode comparison form to narrow contact/identifier checks;
  it does not rewrite the original reviewed text or provide general PII detection.
- Rejects binary controls, invalid text, contact/identifier examples, and URL-bearing
  draft output. Results remain unverified text even when structurally valid.

These checks do not prove that a valid-looking recommendation is correct or free
of manipulation. Human review, server-side permissions, Draft status, independent
closure, and the absence of executable model tools remain the main controls. No
automatic imports, approval transitions, shell commands, or external writes are
granted by any prompt. Provider errors and rejected output are not echoed to users.
No raw prompts or hidden model reasoning are added to logs.

## Local request exhaustion

The HTTP server now allows at most 16 concurrent request workers per process.
Excess requests receive a bounded HTTP 503 with Retry-After, without starting another
worker. Existing connection read timeouts, body limits, AI concurrency limits,
request budgets, login throttling, and access checks still apply. Worker limits
recover after requests finish.

This is local hardening, not a public cloud hosting solution. Keep loopback binding.
MFA, encrypted backup tools, and HTTPS gateway/monitoring templates are now included
in the cloud security runbook; actual provider configuration and verification are
still needed before any reviewed network deployment. No cloud
account or infrastructure was configured by this change.

## Should Schooldesk use a blockchain?

A blockchain can serve as an independently witnessed publication point for a hash.
It cannot prevent prompt injection, stop account compromise, validate false source
data, recall disclosed records, or prove that a reviewer did a good job. A private
ledger controlled by the same operator as the database adds little independent
assurance. Protected off-site checkpoints or immutable storage may be simpler.

For a future external witness, this version prepares a compact commitment without
submitting transactions or adding wallet/RPC dependencies:

```sh
python3 maintenance.py anchor-create private-anchor.json
python3 maintenance.py anchor-verify private-anchor.json
```

The private bundle contains a random nonce, the security-event checkpoint, a salted
Merkle root, table counts, and a SHA-256 public commitment. It does not contain raw
records, filenames, individual record hashes, passwords, tokens, or attachments.
The dataset covers students, attendance, grades, assets, audit findings, support
tickets, audit history, and evidence content/metadata. Credentials, sessions,
configuration, pipeline tracking tables, and filesystem backups are not covered.
Evidence hashes and byte lengths are checked before committing the snapshot.

The snapshot is read within one SQLite transaction. Merkle construction uses
separate leaf/node domains and a streaming frontier, keeping memory bounded by
one record plus logarithmic tree state. A random private nonce changes commitments
even for identical datasets and reduces guessability; this is not a legal claim
of anonymization. Preserve the private bundle securely with the matching recovery
snapshot and independent checkpoint storage. The file is created owner-only and
cannot overwrite an existing file.

Only the 32-byte public commitment is a candidate for independent publication.
Do not publish the private bundle, rows, attachment hashes, account handles, or
school identifiers. Even a hash transaction exposes wallet/timing metadata, and
public chains have permanence, cost, governance, and privacy implications.

## Verifying an independently published commitment

If an operator separately publishes the printed hash to a reviewed witness or
blockchain and obtains it independently, compare it using:

```sh
python3 maintenance.py anchor-verify private-anchor.json --published-commitment ACTUAL_64_HEX_HASH
```

A `0x` prefix is accepted. This command verifies the supplied hash, private opening,
security-event prefix, and current dataset. It does not query a chain, verify a
transaction receipt/contract, establish chain finality, sign a message, or prove
who published it. The caller must independently verify the witness, issuer,
network, contract, transaction, and finality. No blockchain transaction has been
created or submitted by the application.

A modified private bundle can be recomputed by a database writer, but it will not
match a genuinely independent previously published commitment. Keeping the bundle
and hash only beside a writable database is not independent protection. Losing the
private nonce/opening prevents rechecking the published commitment.

Later security events are allowed when the anchored prefix still matches. Later
business-record changes alter the dataset root and yield `dataset_matches: false`;
that may be legitimate, not proof of an attack. Verify against the corresponding
protected backup to check historical state. The command reports security-prefix,
dataset, and published-hash comparisons separately. It does not certify record
truth, transaction legitimacy, or compliance.

## Verification

Offline tests cover hostile instructions, structured tool requests, malformed and
incomplete model output, redirect refusal, obfuscated contact markers, unchanged
records after a malicious model response, worker exhaustion/recovery, private bundle
contents, matching recovery copies, snapshot changes, independent commitments, and
an independent recursive reference for odd-sized Merkle trees. Tests use synthetic
inputs and mocked model responses. No live model or blockchain call is required.

## Learning dataset coverage

New bundles use `schooldesk.anchor.v2` and include the seven learning-evidence tables in addition to the original dataset. Verification still accepts legacy v1 bundles and explicitly reports `learning_records_covered: false` for them. Old commitments do not retroactively cover the new module. See [learning evidence](learning-evidence.md) for record scope and restore validation.
