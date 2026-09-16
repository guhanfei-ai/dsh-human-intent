# Migration: dsh-fingerprint-signature → dsh-human-intent

## Why a new project

dsh-fingerprint-signature asked the operating system "is a human present?"
and, on success, granted a 30-second blanket pass for protected tools. That
is *presence verification*. It never bound the approval to the action being
executed:

- the human saw a generic popup (or a free-text reason), never the exact
  arguments;
- any protected tool could run within the grant window;
- the proof was a helper exit code, not a signature;
- denial was indistinguishable from timeout.

dsh-human-intent upgrades the security model to *intent authorization*:
approval is cryptographically bound to the exact action, one-shot, expiring,
and auditable.

## What was reused

From the predecessor (with thanks to its working DSH integration):

- DSH plugin structure: host entry (`index.js` + `cordis.patch.yml`),
  `tools`/`systemPrompt`/`webServer`/`settings` injection pattern.
- Loopback API hardening: same-origin / `sec-fetch-site` checks, JSON body
  limits, `no-store` + `nosniff` headers.
- SSE event pattern for the client panel; the client sidebar/settings
  skeleton (React `createElement` style, Better Sidebar integration).
- Test architecture: fake web-server harness, route-level tests.

## What was replaced

| Before | After |
| --- | --- |
| Native helper (Swift `LocalAuthentication` / C# `UserConsentVerifier`) returning `verified` | WebAuthn with **full server-side verification** (`@simplewebauthn/server`) |
| 30-second session grant | Per-action one-shot receipt |
| Free-text reason popup | Exact-action approval UI (tool, target, raw arguments, hash) |
| No action binding | `intentHash = SHA-256(JCS(intent))`, challenge = intentHash |
| No receipts | `IntentReceipt` with embedded intent + signature |
| Timeout-only refusal | explicit `denied` decision returned to the agent |
| No audit | append-only JSONL audit log |

## What was deliberately not migrated

- **The native platform-presence helper.** It cannot sign an intentHash or
  bind to an action. Keeping it as a runtime fallback would create a
  silent downgrade path from cryptographic authorization to "trust a
  boolean" — explicitly forbidden by this project's security rules. Future
  versions may reintroduce platform helpers **only** as additional
  authenticator *evidence*, never as a replacement for the signature.
- **Signature variables** (zh/en name, identity ID, binding UUID, custom
  context variables). That is a different feature: injecting human-attested
  context into the agent. It remains available in the old plugin; both
  plugins can coexist in one DSH profile.
- **The `dsh_fingerprint_signature` tool.** Renaming it would fake
  continuity; its semantics (grant + variable injection) do not exist here.
  The new tools are `human_intent_request`, `human_intent_verify`,
  `human_intent_status`.

## Config changes

| dsh-fingerprint-signature | dsh-human-intent |
| --- | --- |
| `signatureEnabled` | `enabled` (default true; enforcement can be disabled) |
| `protectedTools: string[]` | `protectedTools: string[]` (same semantics + globs) — unchanged migration |
| — | `rules: [{ tool, risk }]` |
| — | `rpID`, `allowedOrigins`, `requestTtlMs`, `dataDir` |
| `zhName`/`enName`/`identityId`/`customVariables`/`bindingUuid` | removed (see above) |

Migration steps for DSH users:

1. Install this plugin alongside (or instead of) the old one.
2. Move `protectedTools` entries over; optionally add `rules` with risk
   levels.
3. Set `allowedOrigins` to your DSH web UI origin (e.g.
   `http://localhost:5600`).
4. Register a passkey once (settings panel or `npm run register`).
5. Update agent prompts/skills from `dsh_fingerprint_signature` to
   `human_intent_request` (+ `human_intent_verify` when the agent wants to
   demonstrate a valid receipt before executing manually).

## Naming / brand

All user-visible naming is `dsh-human-intent` / `Human Intent` /
`IntentReceipt` / `action authorization`. The word "fingerprint" appears
only in migration history: the project verifies *human intent*, and
platform authenticators (Touch ID, Windows Hello) are implementation
details of the `AuthenticatorProvider`.
