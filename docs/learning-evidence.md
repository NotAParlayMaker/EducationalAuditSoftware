# Learning evidence and revisable formative review

This module applies the design commitments in *Knowing a Mind in Motion*: separate
observations from interpretations, retain a learner's opportunity to show change,
make evidence gaps visible, and preserve accountable human judgment. It does not
implement the essay's companion manuscript, its minimax rates, a calibrated mastery
probability, or an automated placement decision. No learning records are sent to
an external model or added to the existing IT drafting assistant.

## Start using it

After normal account setup, provision distinct accounts through the trusted local
operator interface (passwords are prompted, never command arguments):

```sh
.venv/bin/python manage.py create-user school-registrar --role registrar
.venv/bin/python manage.py create-user ecology-teacher --role teacher
```

Use an existing registrar account if one is already provisioned. Teacher accounts
are covered by mandatory cloud MFA and the optional local privileged-MFA policy.
The existing host encryption, session, key, backup, and deployment prerequisites
still apply; use fictional records while validating a deployment.

1. A registrar creates student records in **Students**, then opens **Learning
   evidence**, creates a class, assigns an active teacher, finds students by name,
   and enrolls them using their stable student IDs.
2. The assigned teacher signs in to **Learning evidence** and defines skill codes,
   criteria, and rubric versions. A new version retires the previous current
   version without changing its evidence or judgments.
3. Open a learner and record an assessment date, format, observed outcome, context,
   factual observation, and unique source reference. The browser generates a
   source reference; ingestion clients should retain their own stable source IDs.
4. Record a human formative judgment, rationale, and supporting observations.
   The interface requires acknowledgement that the evidence was reviewed.
5. Record a reassessment request or challenge, including an optional student
   explanation. Later resolve it with a reason and optional supporting evidence.
   Review the class's opportunity report and the learner's activity timeline.

Roster changes, teacher reassignment, rubric changes, teacher reviews, and
reassessment resolution require authentication within the last five minutes.
Use the existing Account security reauthentication form when prompted, then retry.

## Evidence and judgments

The new schema references `students.id`, not free-text student names. It does not
guess links from the older attendance/grade name fields or import those grades as
mastery evidence. Each observation records its own skill-version ID, assessment
date, recording timestamp, source reference, and authenticated educator.

Observation formats are written, oral, diagram, transfer, and practice. Outcomes
are demonstrated, developing, incorrect, not assessed, absent, and inaccessible.
The last three represent missing opportunities and never count as incorrect
answers or completed evidence for a judgment. Notes should describe the relevant
task/access conditions without collecting unrelated diagnoses or personal data.

Judgments are **insufficient evidence**, **developing**, and **demonstrated across
contexts**. Only educators can record them. Nonempty rationale is always required.
Judgments other than insufficient evidence require cited, completed observations
for that learner and exact skill version. Demonstrated across contexts requires
demonstrated observations on at least two dates, in two formats and contexts.
That is a conservative workflow minimum, not a scientifically validated scoring
rule, proof of mastery, or substitute for professional judgment.

The 30-day window is a transparent operational default, not an optimized window
derived from the essay. Older evidence remains visible. The system flags a lack
of recent completed evidence, limited formats, recent missing opportunities,
mixed recent observations, old reviews, old supporting evidence, and evidence
changed since review. Flags do not silently replace a teacher's judgment.

The opportunity report includes every active roster member, including learners
with no recorded evidence. It shows recent completed observations, skill coverage,
missing opportunities, format variety, open reassessments, and fewer observations
than the class median. These counts describe visibility and opportunity; they do
not rank ability or establish demographic fairness. No protected characteristics
are inferred or collected for this report.

## Revision, history, and safeguards

Observations and reviews are append-only through the API. Corrections name the
current observation they supersede, supply a new source reference and a reason,
and retain the original. Superseded observations no longer support current review
or coverage calculations. Repeating an identical observation source ID returns
the existing record; conflicting reuse returns 409. A completed historical source
can still be replayed after its rubric version retires, without creating new
evidence under the old rubric.

Teacher-review revisions name the prior review ID, preventing a stale page from
overwriting another judgment. Earlier judgments remain in the timeline. New
rubric versions do not inherit evidence or judgments automatically. Reassessment
resolution similarly checks a revision and retains opening/resolution events,
the educator identity, timestamps, explanation, and evidence link.

A student/guardian request source is explicitly **reported**, not authenticated:
there is no student or guardian login or self-service appeal portal in this
release. The signed-in educator records the request. Placement, advanced-course
eligibility, and lasting educational classifications require a separate reviewed
process; this module cannot apply those decisions.

Registrars manage all learning rosters and assignments. Teachers can see and write
only their currently assigned classes and current enrollments. They see student
IDs, names, and years; guardian details remain outside their learning access.
Removing an enrollment or transferring the class revokes subsequent teacher API
access, including history and observations. Registrars retain inactive enrollment
history for correction and oversight. IT administrators, auditors, remediation
owners, reviewers, and shared-token demo users have no learning-module access.

All writes acquire a SQLite write lock before checking current authorization.
Relationships are checked against the class, learner, and skill; foreign keys
prevent orphaned references. Raw observation text, judgments, and student IDs stay
out of the security-event feed. The class-scoped learning history contains full
snapshots and is subject to the same educational-record privacy requirements.

## API and operational limits

All endpoints require individual account authentication and existing request
boundary headers. The root is `/api/learning`:

| Endpoint | Use |
|---|---|
| `GET /classes`, `POST /classes` | List assigned classes; registrar creates classes |
| `GET /teachers`, `GET /students?search=...` | Registrar-only teacher/student lookup |
| `POST /classes/C/assignment` | Registrar reassigns the teacher with a revision |
| `GET/POST /classes/C/enrollments` | Read scoped roster; registrar enrolls/removes/re-enrolls |
| `GET/POST /classes/C/skills` | Read immutable versions; add a current rubric version |
| `GET /classes/C/coverage` | Descriptive opportunity report |
| `GET /classes/C/students/S` | Learner summaries, reassessments, and activity |
| `GET/POST /classes/C/students/S/observations` | Read or append evidence/corrections |
| `POST /classes/C/students/S/reviews` | Record a cited human review |
| `POST /classes/C/students/S/reassessments` | Open a recorded request |
| `POST /classes/C/students/S/reassessments/R/resolve` | Resolve with revision and rationale |

Observations and learner activity support `limit` (1–100) and `before_id` cursors;
observations optionally filter by `skill_id`. Other lists have explicit bounds.
The browser shows up to 100 observations for citation and correction; older
records remain in paginated activity/API access. No learning bulk export or CSV
batch importer is added; the legacy pipeline's resource permissions are unchanged.

Prototype bounds: 200 classes, 200 distinct enrolled learners per class, 30 current
skill codes/200 rubric versions per class; per learner/class, 2,000 observations,
500 reviews, and 200 reassessment requests. Capacity errors preserve existing
records rather than deleting history. An operator must review capacity and
retention before increasing limits. The existing 64 MiB encrypted-backup limit
still applies; these record bounds do not guarantee the DB stays below it.

New private integrity bundles use `schooldesk.anchor.v2` and include all seven
learning tables. Legacy v1 bundles still verify their original dataset scope and
explicitly report `learning_records_covered: false`. New data is not retroactively
covered by an old commitment. Verified backups preserve the full SQLite learning
dataset; database verification now also checks foreign-key integrity.

Validation covers role/class/enrollment isolation, transfer revocation, immutable
corrections, source replay/conflicts, missing-evidence semantics, review revisions,
rubric changes, reassessment resolution, pagination, freshness, bounded writes,
security-feed privacy, restore preservation, and v1/v2 integrity coverage. The
standalone browser check exercises the actual registrar/teacher workflow with
fictional data and no model calls:

```sh
SCHOOL_TEST_CHROMIUM=/usr/bin/chromium python3 tests/learning_browser_smoke.py
```
