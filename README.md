# dsh-human-intent

**Human intent verification and cryptographic action authorization for AI agents.**

> AI can propose an action.
> Only a human can authorize it.

```
Agent proposes Action
        ↓
Canonicalize Action
        ↓
Hash Exact Intent
        ↓
Human sees exact Action
        ↓
Human verifies (WebAuthn: Touch ID / Windows Hello / passkey)
        ↓
Cryptographically sign Intent
        ↓
Generate Intent Receipt
        ↓
Verify exact Action binding
        ↓
Execute
```

## Why

AI agents can increasingly execute real-world actions: delete data, deploy
services, spend money, send messages. An agent having the **capability** to
run a tool does not mean a human granted the **authority** to run it.

`Capability != Authority.`

Existing human-in-the-loop mechanisms usually verify a fuzzy fact — "a human
touched the sensor" — and then hand the agent a blanket `verified = true`,
often valid for a window of time. Nothing binds the approval to the exact
action. An approval obtained for `rm -rf ./test-data` silently authorizes
`rm -rf ./production-data`.

dsh-human-intent closes that gap. Every authorization is:

- **Exact-action-bound** — the approval is hashed and signed over the precise
  tool, target and arguments; any mutation invalidates it.
- **Cryptographically signed** — WebAuthn (platform authenticator, passkey,
  or security key) with full server-side verification.
- **One-shot** — an authorization authorizes exactly one execution.
- **Expiring** — requests and receipts carry a short validity window.
- **Auditable** — every transition is recorded in a local append-only log.

This project is **not** a fingerprint-identification system and does not
identify a specific natural person. WebAuthn platform authenticators
(Touch ID / Windows Hello / passkeys) prove that *the holder of a registered
credential* performed a user-verification gesture. That proof is what gets
bound to the action. See [Security Model](#security-model).

## How It Works

1. The agent (or a `tools/pre-execute` policy hook) proposes an
   **IntentRequest**: tool, operation, target, arguments, risk, reason.
2. The request is canonically serialized (RFC 8785 JCS) and hashed:
   `intentHash = SHA-256(canonical intent)`.
3. The human opens the approval page and sees the **exact action**.
4. Approving triggers a WebAuthn ceremony whose **challenge is the
   intentHash itself** — the authenticator signs the bytes of the action.
5. The server fully verifies the assertion (challenge, origin, RP ID,
   public key signature, counter, user-verification flag) and issues an
   **IntentReceipt**.
6. Before execution, the receipt is consumed: the action is re-hashed and
   must match, the signature is re-verified against the stored credential,
   and the one-shot consumption marker is checked. Only then does the tool
   run — exactly once, for exactly that action.

## Quick Start

Requirements: Node.js ≥ 20.11.

```bash
npm install
npm run verify        # build + lint + tests + http smoke test
npm run demo          # interactive acceptance scenarios A–E
```

Demo walkthrough (the part you show people):

```bash
npm run demo
```

- No passkey yet? The browser opens and you register one (Touch ID on macOS,
  Windows Hello on Windows).
- Pick a scenario; the agent proposes a destructive command, the browser
  shows the exact action, you approve or deny, and the terminal prints the
  cryptographic outcome — including the mutation, replay and expiry attacks
  being rejected.

Run the approval server standalone:

```bash
npm run serve                       # http://localhost:8787
node bin/dsh-human-intent.js serve --port 9000 --data-dir ./data
```

Inspect a receipt (validates structure, integrity and signature):

```bash
node bin/dsh-human-intent.js inspect receipt.json
```

Read the audit log:

```bash
node bin/dsh-human-intent.js audit
```

## DSH Plugin

Inside DeepSeek Harness (DSH), the plugin provides:

- `human_intent_request` — propose an action, wait for the human, receive
  an IntentReceipt (or an explicit denial).
- `human_intent_verify` — verify a receipt authorizes one exact action
  before executing it.
- `human_intent_status` — enforcement status.
- `tools/pre-execute` policy enforcement for `protectedTools`.
- A settings slot and a Better Sidebar approval panel (WebAuthn in the DSH
  web UI), plus a loopback API under `/human-intent/api`.

```json
{
  "protectedTools": ["shell.exec", "kubectl.*"],
  "rules": [{ "tool": "shell.exec", "risk": "high" }]
}
```

Glob semantics: `shell.*` matches one dot-segment (`shell.exec`, not
`shell.exec.sub`); `shell.**` spans segments. Exact names always work.

Local development:

```bash
npm install
npm run build:client
dsh plugin --profile web add link:/Users/you/dsh-human-intent
```

> The DSH client UI must be served from `localhost` for WebAuthn to be
> available, and the DSH host origin must be listed in `allowedOrigins`.

## Configuration

| Option | Default | Meaning |
| --- | --- | --- |
| `enabled` | `true` | Enforce human intent for protected tools. |
| `protectedTools` | `[]` | Tool names / dot-globs requiring authorization. |
| `rules` | `[]` | `{ tool, risk }` rules combining protection and risk level. |
| `rpID` | `localhost` | WebAuthn relying-party ID. |
| `allowedOrigins` | `http://localhost:<port>` | WebAuthn origin allowlist. |
| `requestTtlMs` | `120000` | Human decision window. |
| `dataDir` | (memory) | Directory for `credentials.json` + `audit.jsonl`. |

## IntentRequest

```ts
interface IntentRequest {
  version: "0.1"
  requestId: string          // unique per request
  intentHash: string         // SHA-256 over the canonical intent
  nonce: string              // 256-bit unguessable, one per request
  action: {
    tool: string             // e.g. "shell.exec"
    operation?: string
    target?: string          // e.g. "namespace/prod/pod/foo"
    arguments: object        // exact arguments
  }
  context?: {
    description?: string
    reason?: string
    risk?: "low" | "medium" | "high" | "critical"
  }
  agent?: { id?: string; name?: string }
  session?: { id?: string }
  issuedAt: string           // ISO 8601
  expiresAt: string          // ISO 8601
}
```

## IntentReceipt

```ts
interface IntentReceipt {
  kind: "IntentReceipt"
  version: "0.1"
  requestId: string
  intentHash: string          // the action this receipt authorizes
  decision: "approved" | "denied"
  intent: IntentRequest       // embedded, integrity-checked
  authenticator: { type: "webauthn"; credentialId: string }
  verification: { method: "webauthn"; userVerified: boolean }
  signedAt: string
  expiresAt: string           // same window as the request
  nonce: string
  assertion?: { /* raw WebAuthn assertion for re-verification */ }
  deniedReason?: string
}
```

Receipts serialize, verify and audit (`docs/PROTOCOL.md`).

## Security Model

What this project guarantees, precisely:

1. **Action binding.** Approving `tool=A, args=X` produces a receipt that
   cannot authorize `tool=A, args=Y` or `tool=B, args=X`. The intentHash
   covers tool, operation, target, arguments, nonce, requestId and the
   validity window.
2. **Signature coverage.** The WebAuthn challenge *is* the intentHash, so
   the authenticator's signature covers the exact action bytes.
3. **Full server-side verification.** Challenge, origin allowlist, RP ID,
   credential public key (COSE/ES256 or RS256), signature, signature
   counter (clone detection) and the user-verification flag are all
   verified with `@simplewebauthn/server`. No client-provided
   `verified: true` is ever trusted.
4. **One-shot consumption.** A consumed receipt is rejected on reuse — in
   memory and, when a data dir is configured, across restarts via the
   audit log.
5. **Expiry.** Requests and receipts share a short window; after it, only a
   fresh human authorization works.
6. **Explicit denial.** Denials are first-class outcomes the agent can read.

What this project does **not** claim:

- It does not identify which natural person is enrolled on the device.
  WebAuthn proves a registered credential holder verified — see
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full model.
- It cannot stop a human from approving a misleading *reason* string if the
  arguments are honest; the UI shows raw arguments and the hash, never just
  a summary.
- The local audit log is append-only JSONL; it is not tamper-proof against
  a host compromise (future work: signed logs).

## Architecture

```
Agent
  ↓ IntentRequest
Canonicalizer (RFC 8785 JCS)
  ↓ CanonicalIntent
Hasher (SHA-256)
  ↓ IntentHash
Human Intent UI (exact action, risk, arguments, expiry)
  ↓ WebAuthn ceremony (challenge = intentHash)
Verifier (@simplewebauthn/server: origin, RP, key, signature, counter, UV)
  ↓ IntentReceipt
Policy / Consumption Gate (action re-hash, one-shot, expiry)
  ↓
Tool Execution (exactly the authorized action)
```

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
Protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md) ·
Threats: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## Demo

`npm run demo` runs the five acceptance scenarios:

| Scenario | Demonstrates |
| --- | --- |
| **A** | Destructive command → human approves → exact action executes once. |
| **B** | Human approves `./test-data`; agent swaps to `./production-data` → **rejected** (`action_mismatch`). |
| **C** | Approved receipt replayed a second time → **rejected** (`already_consumed`). |
| **D** | Request window elapses → **expired**, nothing executes. |
| **E** | Human presses Deny → agent receives an explicit `denied` decision. |

## Migration from dsh-fingerprint-signature

dsh-human-intent **evolved from dsh-fingerprint-signature**, which gated
protected tools behind a platform user-verification popup and granted a
30-second blanket pass. That design verified *human presence* but nothing
about *which action* the human was approving.

This project keeps the plugin structure and the loopback-API pattern that
worked there, and replaces the security model:

| | dsh-fingerprint-signature | dsh-human-intent |
| --- | --- | --- |
| Verified fact | "a human is present" | "a human authorized this exact action" |
| Binding | none (blanket grant) | intentHash (tool + target + arguments) |
| Proof | helper exit code | WebAuthn signature (server-verified) |
| Validity | 30s window | one-shot, request-window-bounded |
| Denial | timeout only | explicit denied receipt |
| Audit | none | append-only audit log |

The signature-variable feature (names, identity IDs, custom variables
injected into the agent context) is not migrated: it is a different use
case. Keep using dsh-fingerprint-signature for it; both plugins can be
installed side by side.

See [docs/MIGRATION.md](docs/MIGRATION.md).

## Roadmap

- **v0.1** — WebAuthn human intent, exact action binding, intent receipts,
  protected tools, audit log, DSH plugin, CLI + demo.
- **v0.2** — passkey sync/hardware-key profiles, richer policy rules, MCP
  adapter.
- **v0.3** — multi-party approval, organization policies, remote approval,
  receipt transparency.
- **Future** — cross-agent human-intent protocol, SDKs, browser and
  infrastructure integrations.

## Limitations

- v0.1 stores credentials in a local JSON file; there is no per-user
  account model or encrypted keystore yet.
- The DSH client approval panel requires a `localhost`-served UI and a
  WebAuthn-capable browser.
- Single-host enforcement: receipts are consumed on the host that issued
  them (no distributed consumption ledger).
- Tests use a software authenticator with real EC P-256 keys; physical
  authenticator behavior (resident keys, hybrid transport) is exercised in
  the demo, not the test suite.

## License

MIT — see [LICENSE](LICENSE).
