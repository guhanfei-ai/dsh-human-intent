# Threat Model

Assets:

1. The integrity of the **authorization decision** — what the human saw and
   approved is what executes.
2. Credentials (WebAuthn public keys, counters).
3. The audit log.

Trust boundaries:

- Agent / LLM — **untrusted proposer**. It may be prompt-injected, buggy,
  or adversarial.
- Browser UI — semi-trusted renderer; must be same-origin and loopback.
- Platform authenticator — trusted hardware/software credential holder.
- Host service — trusted computing base for this protocol.
- Local filesystem — trusted for v0.1 persistence (see Limitations).

---

## Attacker: malicious or injected agent

The agent proposes actions and holds receipts between request and
execution.

- **Action mutation (swap arguments after approval)** — the human approved
  `rm -rf ./test-data`; the agent submits `rm -rf ./production-data`.
  Defense: consumption re-hashes the *submitted* action with the receipt's
  context; different arguments ⇒ different hash ⇒ `action_mismatch`.
  Tested: `tests/service.test.js` (scenario B, tool/target variants).
- **Tool/target substitution** — same defense; tool and target are hashed
  fields.
- **Receipt replay** — reuse a consumed receipt. Defense: one-shot
  consumption set, persisted through the audit log so restarts don't help.
  Tested: scenario C.
- **Receipt forgery** — fabricate a self-consistent receipt without a
  genuine signature. Defense: the embedded WebAuthn assertion is
  re-verified against the stored public key; the attacker has no private
  key. Tested: "a forged receipt without a valid signature cannot be
  consumed".
- **Blind blanket grant** — obtain one approval and spend it on anything.
  Defense: there are no session-level grants in this protocol; every
  execution consumes a receipt bound to an exact action. (The predecessor's
  30-second grant is gone by design.)
- **Bogus risk/reason text ("safe cleanup") over dangerous arguments** —
  the UI renders raw arguments and the intent hash, not just the reason
  string; reason is displayed as secondary context. Residual risk: a human
  who only skims the reason (see "approval of misleading summary").
- **Request flooding / DoS** — pending requests are bounded by TTL
  (default 120s); request bodies are size-limited; canonicalization enforces
  depth/size limits.

## Attacker: network / page attacker

- **Challenge substitution** — swap the challenge served to the browser so
  the human signs a different action. Defense: the challenge is derived
  from the request's intentHash server-side; the verification recomputes
  it. A swapped challenge fails verification.
- **Wrong origin (phishing page driving WebAuthn)** — assertions from
  foreign origins are rejected (origin allowlist, enforced by
  `verifyAuthenticationResponse`).
- **Wrong RP ID** — enforced the same way.
- **XSS in the approval page** — the page is static, dependency-free, served
  with `Content-Security-Policy: default-src 'self'`, `X-Frame-Options:
  DENY`, `nosniff`, no inline scripts.
- **CSRF / cross-site POST to the loopback API** — requests with
  `sec-fetch-site: cross-site`, foreign `Origin`, or non-loopback hosts are
  rejected before any state change.
- **Open redirect** — no redirect endpoints exist; static file serving
  resolves inside `public/` only (traversal tested).
- **Credential exposure** — private keys never leave the authenticator; the
  host stores only public keys. The audit log stores a salted hash
  reference, not credential ids.

## What You See Is What You Sign

The central human-factor property: the displayed action and the signed
action must be the same bytes.

- The approval UI renders tool, operation, target, risk, reason, the
  **raw arguments JSON**, the nonce and the intent hash.
- The browser signs a challenge equal to the intentHash of exactly that
  request (fetched server-side by request id).
- The server verifies the signature over that hash, and consumption
  re-verifies again.

Residual risks:

- A malicious *host* could render different text than the hashed action —
  out of scope: the host is the trusted computing base.
- A UI bug could summarize arguments instead of showing them; the
  implementation deliberately prints the full JSON to make the "safe
  summary" anti-pattern hard.

## Attacker: receipt thief

- **Stolen receipt file** — replays fail (one-shot); expiry bounds the
  window; the receipt without the action's host credential store is
  unverifiable elsewhere (and signatures are origin/RP-bound).

## Race conditions / TOCTOU

- **Double consumption** — consumed markers are set before success is
  reported (check-then-act is closed by marking first and rolling back on
  counter-store failure).
- **Approve-after-deny** — settlement is one-shot; second decisions fail
  with "unknown or settled request".
- **Concurrent approvals of one request** — first assertion settles the
  request; later ones find no pending entry.

## Malicious tool output

Out of scope for the authorization protocol itself: once the human
authorizes the exact action, what the *tool* returns is not attested. A
compromised tool can still lie in its output — v0.1 authorizes invocations,
not results.

## Expired intent

Requests expire (`expired` settlement); receipts inherit the same window
and are rejected after it. Tested (scenario D).

## Explicit limitations (honesty section)

- Local credential JSON is not an encrypted keystore; a host compromise
  defeats everything (the host signs the "truth").
- The audit log is append-only by convention, not cryptographically
  tamper-evident.
- No identification of *which* human: WebAuthn proves a registered
  credential holder verified, not a specific natural person. Multi-party /
  quorum approval is v0.3 scope.
- Clock skew: windows use the host clock; a hostile clock is a host
  compromise.
- The DSH plugin's pre-execute gate depends on the DSH host calling the
  hook for every tool; a hostile DSH build could skip it. The protocol's
  guarantees are about *authorization artifacts*, not about bypassing the
  runtime that consumes them.
