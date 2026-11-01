# Uniform lockouts and factor-first backoff recovery

Application account lockouts return the same status and JSON body:

```http
HTTP/1.0 429 Too Many Requests
Content-Type: application/json

{"error": "Authentication temporarily unavailable. Try again later."}
```

This applies to username backoff, the global login ceiling, normal MFA throttling,
backoff-factor throttling, enrollment throttling, and password-change throttling.
Neither a wrong password during backoff nor a correct password with a rejected
factor changes that response. Invalid request formats remain validation errors;
ordinary invalid credentials outside lockout remain generic 401 responses.
Gateway/AI capacity limits are separate from account lockouts.

An exhausted normal MFA budget is now checked before password hashing, even
outside username backoff. A caller cannot distinguish wrong from correct
passwords by observing a 401 versus an MFA-throttle 429 for that locked account.
This standardizes responses, not whole-request execution time.

## Authentication order

| Path | Before PBKDF2 | After a correct, rechecked password |
|---|---|---|
| Normal login | Check normal MFA throttle and global CPU ceiling | Verify and consume the normal MFA factor |
| Username backoff | Check global CPU ceiling, reserve an independent backoff-factor attempt, verify a valid factor without consuming it | Revalidate the same account-bound factor and consume it atomically before issuing a session |

Fake, expired, or replayed factors, or inactive MFA enrollments, cannot trigger
PBKDF2 during backoff. Both TOTP and single-use recovery codes use the factor-first
path. No client-IP header is trusted or used to change the authentication boundary.

The initial proof is bound to the encrypted enrollment state and the specific
TOTP counter or recovery-code digest. It is internal only: it is never returned
to the browser or recorded in security events. Final consumption occurs under
the same write lock as fresh credential checks and session issuance. An MFA reset
or concurrent factor consumption invalidates the proof; it cannot fall back to
password-only authentication. A valid factor submitted with a wrong password is
not consumed, while a fully successful authentication consumes it exactly once.

## Independent budgets and limits

The backoff path has its own five-attempt/fifteen-minute budget. It never calls
the normal MFA budget verifier or increments normal MFA failures. Malformed or
absent codes are rejected without entering the factor-guessing path. Failed
factor guesses also do not spend the PBKDF2/global login budget. A valid factor
followed by a wrong password still spends a backoff attempt and CPU budget.

The recovery budget uses a digest of the supplied identity, bounds stored entries
to 4,096, expires stale entries, and emits at most one throttle event per window.
Successful authentication clears its recovery/password backoff state. Fully
verified backoff recovery also clears the account's normal MFA throttle. Trusted
CLI MFA reset clears both budgets.

Exhausting the recovery budget can temporarily block this emergency path. It
does not poison normal MFA: after username backoff ends, normal password-first
MFA remains usable even if the recovery budget is exhausted. Separate budgets do
not eliminate deliberate exhaustion of recovery or global capacity, and this
change does not claim complete denial-of-service protection.

Regression coverage compares actual HTTP status/body bytes across lockout paths,
proves fake factors never invoke PBKDF2, exercises TOTP/recovery replay and budget
isolation/expiry, and simulates MFA reset and concurrent consumption while the
password hash runs.
