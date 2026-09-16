# Changelog

## 0.1.0 — 2026-09-17

First release: the Human Intent authorization protocol, evolved from
dsh-fingerprint-signature.

### Added

- Intent core: RFC 8785 canonicalization, SHA-256 intent hashing,
  IntentRequest / IntentReceipt with structural validation.
- WebAuthn authenticator with full server-side verification
  (`@simplewebauthn/server`): challenge (= intentHash), origin allowlist,
  RP ID, public key + signature, counter clone detection, user-verification
  flag; atomic file-backed credential store.
- IntentService: request lifecycle, approval, explicit denial,
  cancellation, expiry, and the consumption gate (exact-action binding,
  one-shot, replay protection, signature re-verification).
- Protected-tool policy: exact names, dot-globs (`shell.*`, `shell.**`),
  risk-tagged rules.
- Append-only audit log (no raw argument values; hashed credential refs);
  consumed receipts reloaded at startup.
- Loopback HTTP API with same-origin enforcement + SSE; standalone demo
  server with a hardened static approval UI (exact action, risk, raw
  arguments, intent hash, expiry countdown).
- DSH plugin: `human_intent_request` / `human_intent_verify` /
  `human_intent_status` tools, `tools/pre-execute` enforcement, system
  prompt guidance, settings slot + Better Sidebar approval panel.
- CLI: `serve`, `register`, `demo` (scenarios A–E), `inspect`, `audit`.
- Test suite (83 tests) using a software authenticator with real EC P-256
  keys, including mutation / replay / expiry / denial / forgery coverage;
  end-to-end HTTP smoke test.

### Security model

- Approvals are bound to the exact action (tool, operation, target,
  arguments, nonce, requestId, window).
- Receipts are one-shot and expire with the request window.
- Denials are explicit outcomes, not timeouts.

### Removed vs predecessor

- Native platform-presence helper (no action binding — would create a
  silent downgrade path).
- 30-second blanket grants; signature-variable injection.
