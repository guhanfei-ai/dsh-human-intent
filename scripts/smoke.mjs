/**
 * End-to-end smoke test for the standalone server: real HTTP, real crypto
 * emulator, full approval and consumption flow through the network stack.
 * Not part of `npm test` (it binds a port); run via `npm run smoke`.
 */
import assert from 'node:assert/strict'
import { WebAuthnAuthenticator } from '../src/auth/webauthn.js'
import { CredentialStore } from '../src/auth/credential-store.js'
import { AuditLog } from '../src/audit/audit.js'
import { compilePolicy } from '../src/policy/policy.js'
import { IntentService } from '../src/service.js'
import { createDemoServer } from '../src/server/demo-server.js'
import { WebAuthnEmulator } from '../tests/helpers/webauthn-emulator.js'

const PORT = 8899
const BASE = `http://127.0.0.1:${PORT}`
const ORIGIN = `http://localhost:${PORT}`

const service = new IntentService({
  authenticator: new WebAuthnAuthenticator({ expectedOrigins: [ORIGIN], expectedRPID: 'localhost' }),
  credentialStore: new CredentialStore({ inMemory: true }),
  audit: new AuditLog({ inMemory: true }),
  policy: compilePolicy({ protectedTools: ['shell.*'] }),
})
await service.init()
const emulator = new WebAuthnEmulator({ origin: ORIGIN, rpId: 'localhost' })
const { server, listen, close } = createDemoServer({ service, port: PORT, host: '127.0.0.1' })
await listen(PORT)
const base = `http://127.0.0.1:${PORT}`

async function api(path, options = {}) {
  const response = await fetch(base + path, {
    method: options.method ?? 'GET',
    headers: options.body ? { 'content-type': 'application/json' } : {},
    body: options.body ? JSON.stringify(options.body) : undefined,
  })
  return { status: response.status, headers: response.headers, payload: await response.json().catch(() => null) }
}

try {
  // 1. approval page serves as HTML with a restrictive CSP
  const page = await fetch(`${base}/`)
  assert.equal(page.status, 200)
  assert.match(page.headers.get('content-type'), /text\/html/)
  assert.ok(page.headers.get('content-security-policy').includes("default-src 'self'"))
  const appjs = await fetch(`${base}/app.js`)
  assert.equal(appjs.status, 200)
  assert.match(appjs.headers.get('content-type'), /javascript/)

  // 2. cross-origin is rejected
  const evil = await api('/api/state')
  assert.equal(evil.status, 200)
  const evilOrigin = await fetch(`${base}/api/state`, { headers: { origin: 'https://evil.example' } })
  assert.equal(evilOrigin.status, 403)

  // 3. registration through HTTP
  const options = (await api('/api/register/options', { method: 'POST', body: {} })).payload.options
  const attestation = await emulator.register(options)
  const registered = await api('/api/register/verify', { method: 'POST', body: { attestation } })
  assert.equal(registered.payload.ok, true)

  // 4. create an intent, approve it over HTTP, consume it over HTTP
  const { request, result } = await service.createIntent({
    action: { tool: 'shell.exec', operation: 'exec', target: './important-data', arguments: { command: 'rm -rf ./important-data' } },
    context: { risk: 'critical', reason: 'smoke test' },
  })
  const intentPage = await fetch(`${base}/intent/${request.requestId}`)
  assert.equal(intentPage.status, 200)
  assert.match(intentPage.headers.get('content-type'), /text\/html/)
  const authOptions = (await api(`/api/intent/${request.requestId}/options`)).payload.options
  const assertion = await emulator.sign(authOptions)
  const approval = await api(`/api/intent/${request.requestId}/approve`, { method: 'POST', body: { assertion } })
  assert.equal(approval.payload.ok, true)
  const settled = await result
  assert.equal(settled.status, 'approved')
  const consumed = await api('/api/verify', {
    method: 'POST',
    body: { receipt: settled.receipt, action: { tool: 'shell.exec', operation: 'exec', target: './important-data', arguments: { command: 'rm -rf ./important-data' } } },
  })
  assert.equal(consumed.payload.ok, true)
  const replay = await api('/api/verify', {
    method: 'POST',
    body: { receipt: settled.receipt, action: { tool: 'shell.exec', operation: 'exec', target: './important-data', arguments: { command: 'rm -rf ./important-data' } } },
  })
  assert.equal(replay.status, 403)

  // 5. denial over HTTP
  const second = await service.createIntent({
    action: { tool: 'shell.exec', arguments: { command: 'echo deny' } },
    context: { risk: 'low' },
  })
  const denial = await api(`/api/intent/${second.request.requestId}/deny`, { method: 'POST', body: { reason: 'smoke denial' } })
  assert.equal(denial.payload.ok, true)
  assert.equal((await second.result).status, 'denied')

  console.log('SMOKE OK: page, CSP, cross-origin rejection, registration, approval, consumption, replay rejection, denial — all verified over real HTTP.')
} finally {
  await close()
  server.closeAllConnections?.()
}
