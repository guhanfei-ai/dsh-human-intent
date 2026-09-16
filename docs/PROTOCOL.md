# Human Intent Protocol v0.1

> Status: working draft implemented by dsh-human-intent v0.1.
> This is not a standard. It is a precise, testable definition of the
> semantics this project commits to.

## 1. Concepts

- **Agent** — an AI system that proposes actions.
- **Action** — a concrete tool invocation: `{ tool, operation?, target?, arguments }`.
- **Human** — the operator whose authorization is required.
- **Authenticator** — a WebAuthn credential holder (platform
  authenticator, passkey, security key).
- **Host** — the machine running the verification service and tool
  execution.

Core principle: **capability is not authority.** An agent may be *able* to
run a tool; only a human can *authorize* the exact run.

## 2. IntentRequest

Created by the host on behalf of an agent.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `version` | `"0.1"` | yes | protocol version. |
| `requestId` | string | yes | unique; echoed in the receipt. |
| `nonce` | hex string | yes | 256-bit random, one per request. |
| `action.tool` | string | yes | tool identifier. |
| `action.operation` | string | no | optional operation name. |
| `action.target` | string | no | resource/path/recipient identifier. |
| `action.arguments` | JSON object | yes | exact arguments. |
| `context.reason` | string | no | shown to the human. |
| `context.risk` | enum | no | `low` \| `medium` \| `high` \| `critical`. |
| `agent.id` | string | no | originating agent. |
| `session.id` | string | no | originating session. |
| `issuedAt` | ISO 8601 | yes | host clock at creation. |
| `expiresAt` | ISO 8601 | yes | `issuedAt + ttl`; 5s–600s window. |
| `intentHash` | hex | yes | computed at creation (below). |

## 3. CanonicalIntent

The canonical form of the hashing payload, using RFC 8785 JSON
Canonicalization Scheme (sorted keys, no whitespace, ECMAScript number
formatting):

```json
{
  "v": "dsh-human-intent/0.1",
  "requestId": "req_...",
  "nonce": "<hex>",
  "issuedAt": "2026-09-17T00:00:00.000Z",
  "expiresAt": "2026-09-17T00:02:00.000Z",
  "action": {
    "tool": "shell.exec",
    "operation": "exec",
    "target": "./important-data",
    "arguments": { }
  },
  "agent": { "id": "..." },
  "session": { "id": "..." },
  "context": { "reason": "...", "risk": "high" }
}
```

Empty optional fields are **omitted** (not `null`), so absent and blank are
identical intents. Non-representable values (BigInt, `undefined`, cycles,
non-finite numbers) are rejected at creation.

Key-order independence: `{"a":1,"b":2}` and `{"b":2,"a":1}` are the same
canonical intent and hash identically.

## 4. IntentHash

```
intentHash = lowerhex( SHA-256( canonicalJson(hashingPayload) ) )
```

The hashing payload contains **every** semantic field: protocol tag,
requestId, nonce, issuedAt, expiresAt, the full action, agent, session and
context. Any change to tool, operation, target, arguments, nonce,
requestId or the window produces a different hash.

## 5. IntentChallenge

The WebAuthn authentication challenge for a request is exactly the
intentHash bytes:

```
challenge = base64url( bytes(intentHash) )
```

Consequences:

- The authenticator signature covers the exact action.
- An assertion for one action cannot verify for another (the verifier
  recomputes the expected challenge from the request's own intentHash).
- Challenge entropy derives from the 256-bit nonce inside the hashed
  payload.

## 6. IntentReceipt

Issued after the human decides.

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | `"IntentReceipt"` | discriminator. |
| `version` | `"0.1"` | protocol version. |
| `requestId`, `intentHash`, `nonce` | string | echoed from the request. |
| `decision` | enum | `approved` \| `denied`. |
| `intent` | IntentRequest | the embedded, integrity-checked request. |
| `authenticator.type` | `"webauthn"` | provider used. |
| `authenticator.credentialId` | string | base64url credential id. |
| `verification.method` | `"webauthn"` | for approvals. |
| `verification.userVerified` | boolean | must be `true` for approvals. |
| `signedAt` | ISO 8601 | decision time. |
| `expiresAt` | ISO 8601 | same window as the request. |
| `assertion` | object | raw WebAuthn assertion (approvals only). |
| `deniedReason` | string | optional, denials only. |

**Denied receipts carry no signature** and can never authorize execution.

## 7. IntentVerification

Server-side checks performed when a human approves (and re-performed at
consumption):

1. challenge equals the request's intentHash (base64url)
2. origin is in the allowlist
3. RP ID matches configuration
4. assertion is signed by the stored credential public key
5. signature counter advances (clone detection)
6. `userVerified` flag is set (the human performed verification)

All checks use `@simplewebauthn/server`. No client-side claim is trusted.

## 8. ReceiptConsumption

Before executing the authorized action, the consumer must present the
receipt **and** the action it intends to run. The gate:

1. **Structure** — receipt parses; approved decision.
2. **Window** — `now < expiresAt`.
3. **Integrity** — embedded intent validates and hashes to `intentHash`.
4. **Binding** — hashing `(embedded request fields, submitted action)`
   yields the same `intentHash`. Mutated tool/target/arguments fail here.
5. **One-shot** — `requestId` not previously consumed.
6. **Signature** — WebAuthn re-verification of the embedded assertion
   against the stored credential.

Only then is the action authorized, the consumption recorded (audited),
and the credential counter advanced. Any failure yields a machine-readable
code and an audit entry.

### Error codes

| Code | Meaning |
| --- | --- |
| `invalid_receipt` | malformed structure. |
| `decision_denied` | receipt is a denial. |
| `receipt_expired` | window elapsed. |
| `tampered_intent` | embedded request fails integrity validation. |
| `hash_mismatch` | receipt hash ≠ embedded intent hash. |
| `action_mismatch` | submitted action hashes differently (mutation). |
| `already_consumed` | replay of a consumed receipt. |
| `credential_unknown` | credential no longer registered. |
| `verification_failed` | cryptographic verification failed. |

## 9. Audit events

`request-created`, `approved`, `denied`, `expired`, `cancelled`,
`consumed`, `consumption-rejected`, `assertion-rejected`,
`credential-registered`, `policy-denied`.

Audit entries never contain raw argument values; they carry the intentHash,
tool/operation/target labels, decision, verification method, a hashed
credential reference and timestamps.

## 10. Versioning

This is v0.1. Breaking changes bump the protocol tag inside the hashing
payload (`dsh-human-intent/0.1`), which changes every hash by construction —
receipts never silently cross versions.
