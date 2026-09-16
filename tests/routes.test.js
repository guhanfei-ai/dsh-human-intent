import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { createApiRouter, trustedRequest } from '../src/server/routes.js'
import { makeTestService, registerCredential, shellSpec } from './helpers/context.js'

function fakeRes() {
  const res = {
    headers: {},
    body: '',
    status: 0,
    writeHead(status, headers) {
      this.status = status
      Object.assign(this.headers, headers)
    },
    write(text) { this.body += text },
    end(text) { if (text) this.body += text; this.finished = true },
  }
  return res
}

async function call(router, method, path, payload, headers = {}) {
  const chunks = payload === undefined ? [] : [Buffer.from(JSON.stringify(payload))]
  const req = new EventEmitter()
  req.method = method
  req.url = path
  req.headers = { host: 'localhost:8787', ...headers }
  req[Symbol.asyncIterator] = async function* () { yield* chunks }
  const res = fakeRes()
  const handled = await router.handler(req, res)
  let body = res.body
  try { body = JSON.parse(res.body) } catch { /* not json */ }
  return { handled, status: res.status, body, res }
}

test('trustedRequest accepts loopback without origin header', () => {
  assert.equal(trustedRequest({ headers: { host: '127.0.0.1:5600' } }), true)
  assert.equal(trustedRequest({ headers: { host: 'localhost:8787' } }), true)
})

test('trustedRequest rejects cross-site and foreign origins', () => {
  assert.equal(trustedRequest({ headers: { host: 'localhost:8787', 'sec-fetch-site': 'cross-site' } }), false)
  assert.equal(trustedRequest({ headers: { host: 'localhost:8787', origin: 'https://evil.example' } }), false)
  assert.equal(trustedRequest({ headers: {} }), false)
  assert.equal(trustedRequest({ headers: { host: 'evil.example' } }), false)
})

test('api rejects untrusted requests before any state change', async () => {
  const { service } = await makeTestService()
  const router = createApiRouter({ service })
  const result = await call(router, 'GET', '/state', undefined, { origin: 'https://evil.example' })
  assert.equal(result.status, 403)
  assert.equal(result.body.ok, false)
})

test('state endpoint reports shape and pending requests', async () => {
  const { service } = await makeTestService()
  const router = createApiRouter({ service })
  const result = await call(router, 'GET', '/state')
  assert.equal(result.status, 200)
  assert.equal(result.body.ok, true)
  assert.equal(result.body.status.method, 'webauthn')
  assert.equal(result.body.pending.length, 0)
})

test('registration flows through the API', async () => {
  const { service, emulator } = await makeTestService()
  const router = createApiRouter({ service })
  const options = (await call(router, 'POST', '/register/options', {})).body.options
  const attestation = await emulator.register(options)
  const result = await call(router, 'POST', '/register/verify', { attestation })
  assert.equal(result.status, 200)
  assert.equal(result.body.ok, true)
  assert.match(result.body.credentialRef, /^sha256:/)
})

test('full approval flow through the API', async () => {
  const { service, emulator } = await makeTestService()
  const router = createApiRouter({ service })
  await registerCredential(service, emulator)
  const { request, result } = await service.createIntent(shellSpec({ command: 'echo hi' }))
  const intent = await call(router, 'GET', `/intent/${request.requestId}`)
  assert.equal(intent.body.request.intentHash, request.intentHash)
  const options = (await call(router, 'GET', `/intent/${request.requestId}/options`)).body.options
  const assertion = await emulator.sign(options)
  const approval = await call(router, 'POST', `/intent/${request.requestId}/approve`, { assertion })
  assert.equal(approval.status, 200)
  assert.equal(approval.body.ok, true)
  assert.equal((await result).status, 'approved')
  const consumed = await call(router, 'POST', '/verify', {
    receipt: (await result).receipt,
    action: shellSpec({ command: 'echo hi' }).action,
  })
  assert.equal(consumed.status, 200)
  assert.equal(consumed.body.ok, true)
  const replay = await call(router, 'POST', '/verify', {
    receipt: (await result).receipt,
    action: shellSpec({ command: 'echo hi' }).action,
  })
  assert.equal(replay.status, 403)
  assert.equal(replay.body.ok, false)
})

test('deny through the API settles the request as denied', async () => {
  const { service, emulator } = await makeTestService()
  const router = createApiRouter({ service })
  await registerCredential(service, emulator)
  const { request, result } = await service.createIntent(shellSpec({ command: 'rm -rf x' }))
  const denial = await call(router, 'POST', `/intent/${request.requestId}/deny`, { reason: 'not today' })
  assert.equal(denial.status, 200)
  assert.equal((await result).status, 'denied')
})

test('unknown intents return 404', async () => {
  const { service } = await makeTestService()
  const router = createApiRouter({ service })
  const result = await call(router, 'GET', '/intent/req_unknown')
  assert.equal(result.status, 404)
})

test('malformed bodies return 400', async () => {
  const { service } = await makeTestService()
  const router = createApiRouter({ service })
  const res = await call(router, 'POST', '/verify', null)
  assert.equal(res.status, 400)
})

test('SSE events announce new requests', async () => {
  const { service, emulator } = await makeTestService()
  const router = createApiRouter({ service })
  const stream = fakeRes()
  const req = new EventEmitter()
  req.method = 'GET'
  req.url = '/events'
  req.headers = { host: 'localhost:8787' }
  req[Symbol.asyncIterator] = async function* () { yield* [] }
  await router.handler(req, stream)
  const seen = []
  stream.write = (text) => seen.push(text)
  await service.createIntent(shellSpec({ command: 'echo sse' }))
  await service.createIntent(shellSpec({ command: 'echo sse2' }))
  const settled = (await call(router, 'GET', '/state')).body.pending
  assert.equal(settled.length, 2)
  const messages = seen.map((line) => JSON.parse(line.replace(/^data: /, '').trim()))
  assert.ok(messages.some((m) => m.type === 'request-created' && m.request.action.tool === 'shell.exec'))
})

test('prefix routing works for DSH-style mounting', async () => {
  const { service } = await makeTestService()
  const router = createApiRouter({ service, prefix: '/human-intent/api' })
  const ok = await call(router, 'GET', '/human-intent/api/state')
  assert.equal(ok.status, 200)
  const outside = await call(router, 'GET', '/state')
  assert.equal(outside.handled, false)
})
