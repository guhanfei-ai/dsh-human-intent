# Architecture

## Overview

```
Agent (LLM tool call or skill)
  ↓
IntentRequest            src/intent/request.js
  ↓
Canonicalizer           src/intent/canonicalize.js   (RFC 8785 JCS)
  ↓ CanonicalIntent
Hasher                   src/intent/hash.js           (SHA-256 → intentHash)
  ↓ IntentHash
IntentService            src/service.js               (lifecycle, one-shot state)
  ↓
Human Intent UI          public/  +  src/client/index.js
  ↓ WebAuthn ceremony (challenge = intentHash)
AuthenticatorProvider    src/auth/provider.js         (abstraction)
  └ WebAuthnAuthenticator  src/auth/webauthn.js        (@simplewebauthn/server)
  ↓ verified assertion
IntentReceipt            src/intent/receipt.js
  ↓
Verifier / Consumption   src/service.js#consumeReceipt
  ↓ (re-hash action · re-verify signature · one-shot · expiry)
Policy                   src/policy/policy.js         (protected tools)
  ↓
Tool Execution           exactly the authorized action
Audit                    src/audit/audit.js           (append-only JSONL)
```

## Modules

| Module | Responsibility |
| --- | --- |
| `src/intent/canonicalize.js` | Deterministic JSON (JCS), depth/size limits, undefined pruning. |
| `src/intent/hash.js` | Intent hashing payload definition, SHA-256, nonce generation. |
| `src/intent/request.js` | IntentRequest construction + untrusted-input validation. |
| `src/intent/receipt.js` | Receipt construction, parsing, structural validation. |
| `src/auth/provider.js` | `AuthenticatorProvider` contract (method, challenge, verify). |
| `src/auth/webauthn.js` | Full server-side WebAuthn verification; challenge = intentHash. |
| `src/auth/credential-store.js` | Atomic file-backed credential persistence (public keys only). |
| `src/policy/policy.js` | protectedTools / rules compilation, dot-glob matching. |
| `src/audit/audit.js` | Append-only JSONL events; consumed-receipt reload on startup. |
| `src/service.js` | `IntentService`: lifecycle orchestration and the consumption gate. |
| `src/server/routes.js` | Loopback API (same-origin enforced), SSE events. |
| `src/server/demo-server.js` | Standalone server: static UI + `/api` + security headers. |
| `src/plugin/index.js` | DSH host plugin: tools, pre-execute gate, web API, prompts. |
| `src/client/index.js` | DSH web client: settings slot + sidebar approval panel. |
| `bin/dsh-human-intent.js` | CLI: serve / register / demo / inspect / audit. |

## Key design decisions

### 1. The challenge is the intentHash

WebAuthn challenges are normally random bytes. Here the challenge is
`base64url(SHA-256(canonical intent))`. Randomness comes from the per-request
`nonce` and `requestId`, which are hashed inputs, so every request still has
an unpredictable challenge while the signature is **semantically bound to
the action**. Verification recomputes the expected challenge from the
request's own intentHash, so an assertion made for one action can never
verify against another.

### 2. Receipts carry their proof

An approved receipt embeds the full IntentRequest and the raw WebAuthn
assertion. Consumption re-verifies the assertion against the stored
credential public key. A forged receipt — even one with self-consistent
hashes — fails unless the authenticator actually signed that intentHash.

### 3. Counter advancement at consumption time

The WebAuthn signature counter is advanced in the store only when a receipt
is consumed. This lets the same assertion be re-verified during consumption
(counter still greater than stored) while keeping clone detection intact.

### 4. Fail-closed consumption

`consumeReceipt` rejects with machine-readable codes —
`decision_denied`, `receipt_expired`, `tampered_intent`, `hash_mismatch`,
`action_mismatch`, `already_consumed`, `credential_unknown`,
`verification_failed` — and every rejection is audited before the throw.

### 5. Authenticator abstraction

Nothing in the intent core knows about fingerprints or platforms. v0.1
ships `WebAuthnAuthenticator`; the `AuthenticatorProvider` contract
(method / registrationOptions / authorizationChallenge / verifyAuthorization)
is where passkeys, hardware keys, mobile push and multi-party approval plug
in.

### 6. What is deliberately NOT migrated

The predecessor's native platform-presence helper (Swift/C#) returned only
`{status: "verified"}` with no action binding and no signature. Keeping it
as a runtime fallback would create a silent downgrade path from
cryptographic authorization to "trust me" — that violates the project's
security principles. It is not part of this codebase. See
`docs/MIGRATION.md`.

## Data flow: consumption gate

```
consumeReceipt(receipt, action)
  1. parseReceipt            → structure
  2. decision === approved   → else decision_denied
  3. window open             → else receipt_expired
  4. validateIntentRequest   → embedded intent integrity (tampered_intent)
  5. hash(intent+action) === intentHash → else action_mismatch
  6. not consumed before     → else already_consumed (a per-requestId
     single-flight slot is claimed before the first await, so concurrent
     submissions of one receipt resolve to exactly one success; failed
     verifications release the slot without consuming)
  7. WebAuthn re-verification → else verification_failed / credential_unknown
  8. mark consumed + advance counter + audit
  → authorized
```

## Storage

- `data/credentials.json` — registered credential public keys + counters
  (atomic write). Private keys never leave authenticators.
- `data/audit.jsonl` — append-only event log; `consumed` entries are
  reloaded at startup so restarts cannot be used to replay receipts.
- In-memory mode (no `dataDir`) is used by tests and ephemeral demos.
