# Availability, transport, and dependency follow-up

## Targeted username backoff

A valid password plus an enabled MFA factor can now authenticate during username
backoff. Both authenticator codes and single-use recovery codes are supported.
Only a syntactically plausible factor can enter this verification path; unknown
identities take the same dummy password-hash path. A wrong password or wrong
factor during backoff returns the same throttle response, does not clear backoff,
and does not reveal through its status whether the password was correct.

Password-only accounts still wait out backoff. The global 120-per-minute CPU
ceiling and existing MFA guessing budget still apply. An attacker knowing only
the username cannot consume the MFA budget: factor verification occurs only after
password verification. This does not remove denial-of-service risk from global
capacity exhaustion or an attacker who already possesses the password. Cloud MFA
enrollment remains required; local privileged accounts should enroll too.

The application does not trust a new client-IP header. The gateway continues to
erase forwarded addresses, and source rate limits remain enforced by nginx.

## Connection deadline

Every admitted connection gets a fifteen-second deadline before its worker starts.
The timer shuts down both socket directions when it expires, interrupting blocked
header/body reads and response writes even if bytes arrive more frequently than
the ten-second idle timeout. Normal completion cancels the timer; worker-start
failure cancels it and returns the slot. Each of the sixteen workers has at most
one deadline timer. Excess connections still receive bounded 503 responses.

This bounds client socket occupancy, not arbitrary Python execution. It does not
forcibly terminate a thread doing database work or a provider call. Those operations
retain their own bounds. Public hosting still needs the trusted gateway and
provider-level capacity controls. Regression tests continuously drip both headers
and bodies and verify the worker becomes available again.

## HSTS rollout

The nginx example now uses `max-age=31536000`, including named error locations that
otherwise override inherited headers. It does not opt into `includeSubDomains` or
preloading. This is a template change, not a live HTTPS validation or deployment.
Before applying the one-year policy, verify the real hostname, all HTTPS paths,
redirects, certificate renewal, and certificate-recovery procedure. During initial
TLS validation an operator may retain a shorter policy, then promote it once
HTTPS is confirmed reliable. Browsers retain an HSTS policy after configuration
rollback until its lifetime expires or it is deliberately cleared over HTTPS.

## Hash-verified runtime dependencies

`requirements-security.in` contains the existing version pins. The generated
`requirements-security.txt` includes SHA-256 hashes for binary distributions;
versions are unchanged. CI and installation instructions require both
`--require-hashes` and `--only-binary=:all:`. Supported Python/platform combinations
without an approved wheel fail installation instead of compiling an unreviewed
source distribution.

The lock was generated with Python 3.12 and pip-tools 7.6.2 against PyPI over TLS:

```sh
pip-compile --generate-hashes --no-emit-index-url --no-emit-trusted-host \
  --index-url=https://pypi.org/simple --pip-args=--only-binary=:all: \
  --output-file=requirements-security.txt requirements-security.in
```

Use an isolated, trusted maintainer environment for regeneration. Review changes
to input pins and hashes together; do not regenerate accepted hashes automatically
during deployment. Hashes protect previously reviewed bytes from mirror replacement;
they do not establish that a package was safe before its hashes were accepted.
Validation includes a clean installation of freshly downloaded, verified wheels
and rejection of a deliberately modified wheel without installing it.

## Repository settings: observed state and owner action

On 2026-11-01 the accessible ruleset listing contained one ruleset,
[EdIT](https://github.com/NotAParlayMaker/Scholivex/rules/26324121), with enforcement
**disabled**. Its rules did not require PRs, approvals, or CI/CodeQL. Reading classic
branch protection returned GitHub 403, and the integration did not expose secret
scanning/push-protection status. Those controls cannot be represented as enabled
or verified. No settings were changed by this PR.

The reviewable [main ruleset configuration](../deploy/github-main-ruleset.json)
targets `refs/heads/main`, requires one independent approval, dismisses stale
approvals, requires approval of the latest push and resolution of review threads,
blocks force pushes/deletion, and requires an up-to-date branch with both `test`
and `Analyze Python and JavaScript` passing. Those check names and GitHub Actions
integration ID 15368 were verified against actual check runs. No bypass actors are
included. An independent human reviewer must be available; the author cannot
satisfy their own approval requirement.

An owner with repository-administration permission can import this reviewed JSON
in [Settings → Rules](https://github.com/NotAParlayMaker/Scholivex/settings/rules),
or use an authenticated administrator CLI:

```sh
gh api --method POST repos/NotAParlayMaker/Scholivex/rulesets \
  --input deploy/github-main-ruleset.json
```

Then confirm enforcement is **Active** and exercise it with a test PR: an
unapproved PR, a failing required check, and a direct push should be rejected.
Enable **Secret scanning** and **Push protection** under repository security
settings and verify their enabled state. These settings are separate from the
ruleset JSON. Review GitHub plan/visibility requirements and restricted bypasses.
Passing automated checks are evidence for a human reviewer, not a substitute for
review of authentication, cryptography, or deployment changes. This follow-up is
left as a draft PR for that review.
