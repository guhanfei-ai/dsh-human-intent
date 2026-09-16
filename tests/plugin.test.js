import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { apply } from '../src/plugin/index.js'
import { CredentialStore } from '../src/auth/credential-store.js'
import { AuditLog } from '../src/audit/audit.js'
import { WebAuthnEmulator } from './helpers/webauthn-emulator.js'
import { WebAuthnAuthenticator } from '../src/auth/webauthn.js'
import { IntentService } from '../src/service.js'
import { TEST_ORIGIN, TEST_RP_ID } from './helpers/context.js'

function makeCtx() {
  const routes = []
  const registered = []
  const handlers = {}
  const sections = []
  const ctx = {
    webServer: { register: (route) => routes.push(route) },
    tools: { register: (spec) => registered.push(spec) },
    systemPrompt: { section: (spec) => sections.push(spec) },
    on: (event, handler) => { handlers[event] = handler },
  }
  return { ctx, routes, registered, handlers, sections }
}

function toolByName(registered, name) {
  const tool = registered.find((spec) => spec.name === name)
  assert.ok(tool, `tool ${name} should be registered`)
  return tool
}

/** Create a pre-wired service with one emulator whose key pair both
 * registers and signs, so the crypto path is genuine. */
async function makeWiredService({ ttlMs = 5_000 } = {}) {
  const emulator = new WebAuthnEmulator({ origin: TEST_ORIGIN, rpId: TEST_RP_ID })
  const service = new IntentService({
    authenticator: new WebAuthnAuthenticator({ expectedOrigins: [TEST_ORIGIN], expectedRPID: TEST_RP_ID }),
    credentialStore: new CredentialStore({ inMemory: true }),
    audit: new AuditLog({ inMemory: true }),
    requestTtlMs: ttlMs,
  })
  await service.init()
  const options = await service.registrationOptions({ userName: 'plugin-test' })
  const attestation = await emulator.register(options)
  await service.registerCredential(attestation)
  return { service, emulator }
}

test('plugin registers the three agent tools and the system prompt', () => {
  const { ctx, registered, sections } = makeCtx()
  apply(ctx, {})
  assert.deepEqual(registered.map((spec) => spec.name).sort(), ['human_intent_request', 'human_intent_status', 'human_intent_verify'])
  assert.equal(sections.length, 1)
  assert.ok(sections[0].text.includes('human_intent_request'))
})

test('human_intent_request returns a receipt on approval and explicit denial text on deny', async () => {
  const { ctx, registered } = makeCtx()
  const { service, emulator } = await makeWiredService({ ttlMs: 15_000 })
  apply(ctx, { requestTtlMs: 15_000 }, { service })
  const tool = toolByName(registered, 'human_intent_request')

  // approval path: intercept the created intent through the service
  const approval = (async () => {
    await new Promise((resolve) => setTimeout(resolve, 10))
    const pending = service.listPending()
    if (pending.length === 0) throw new Error('no pending request appeared')
    const options = await service.authenticationOptions(pending[0].requestId)
    const assertion = await emulator.sign(options)
    return service.approve(pending[0].requestId, assertion)
  })()
  const approved = JSON.parse(await tool.execute({ tool: 'shell.exec', arguments: { command: 'echo hi' }, risk: 'high' }, { agent: { id: 's1' } }))
  await approval
  assert.equal(approved.status, 'approved')
  assert.equal(approved.approved, true)
  assert.ok(approved.receipt.intentHash)

  // denial path
  const denial = (async () => {
    await new Promise((resolve) => setTimeout(resolve, 10))
    const pending = service.listPending()
    return service.deny(pending[0].requestId, { reason: 'no' })
  })()
  const denied = JSON.parse(await tool.execute({ tool: 'shell.exec', arguments: { command: 'echo bye' } }, { agent: { id: 's1' } }))
  await denial
  assert.equal(denied.status, 'denied')
  assert.equal(denied.decision, 'denied')
  assert.match(denied.message, /human denied/)
})

test('pre-execute hook blocks protected tools without authorization', async () => {
  const { ctx, handlers } = makeCtx()
  const { service } = await makeWiredService({ ttlMs: 1_000 })
  apply(ctx, { protectedTools: ['dangerous_tool'], requestTtlMs: 1_000 }, { service })
  const guard = handlers['tools/pre-execute']
  const allow = () => Promise.resolve({ kind: 'allow' })
  const decision = await guard({ name: 'dangerous_tool', arguments: { x: 1 }, agent: { id: 's1' } }, allow)
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /human authorization|human intent|human denied/)
})

test('pre-execute hook lets unprotected tools through', async () => {
  const { ctx, handlers } = makeCtx()
  apply(ctx, { protectedTools: ['dangerous_tool'] })
  const guard = handlers['tools/pre-execute']
  const allow = () => Promise.resolve({ kind: 'allow' })
  const decision = await guard({ name: 'harmless_tool', arguments: {}, agent: { id: 's1' } }, allow)
  assert.equal(decision.kind, 'allow')
})

test('glob-protected tools are blocked and policy risk is surfaced', async () => {
  const { ctx, handlers } = makeCtx()
  const { service } = await makeWiredService({ ttlMs: 1_000 })
  apply(ctx, { rules: [{ tool: 'kubectl.*', risk: 'critical' }], requestTtlMs: 1_000 }, { service })
  const guard = handlers['tools/pre-execute']
  const allow = () => Promise.resolve({ kind: 'allow' })
  const decision = await guard({ name: 'kubectl.delete', arguments: { ns: 'prod' }, agent: { id: 's1' } }, allow)
  assert.equal(decision.kind, 'deny')
})

test('disabled enforcement lets everything through', async () => {
  const { ctx, handlers } = makeCtx()
  apply(ctx, { enabled: false, protectedTools: ['dangerous_tool'] })
  const guard = handlers['tools/pre-execute']
  const allow = () => Promise.resolve({ kind: 'allow' })
  const decision = await guard({ name: 'dangerous_tool', arguments: {}, agent: { id: 's1' } }, allow)
  assert.equal(decision.kind, 'allow')
})

test('human_intent_verify rejects a mutated action receipt', async () => {
  const { ctx, registered } = makeCtx()
  const { service, emulator } = await makeWiredService({ ttlMs: 15_000 })
  apply(ctx, { requestTtlMs: 15_000 }, { service })
  const requestTool = toolByName(registered, 'human_intent_request')
  const verifyTool = toolByName(registered, 'human_intent_verify')

  const approval = (async () => {
    await new Promise((resolve) => setTimeout(resolve, 10))
    const pending = service.listPending()
    const options = await service.authenticationOptions(pending[0].requestId)
    const assertion = await emulator.sign(options)
    return service.approve(pending[0].requestId, assertion)
  })()
  const approved = JSON.parse(await requestTool.execute({ tool: 'shell.exec', arguments: { command: 'rm -rf ./test-data' } }, { agent: { id: 's1' } }))
  await approval
  const mutated = JSON.parse(await verifyTool.execute({ receipt: approved.receipt, tool: 'shell.exec', arguments: { command: 'rm -rf ./production-data' } }))
  assert.equal(mutated.status, 'rejected')
  assert.equal(mutated.code, 'action_mismatch')
  const genuine = JSON.parse(await verifyTool.execute({ receipt: approved.receipt, tool: 'shell.exec', arguments: { command: 'rm -rf ./test-data' } }))
  assert.equal(genuine.status, 'verified')
  const replay = JSON.parse(await verifyTool.execute({ receipt: approved.receipt, tool: 'shell.exec', arguments: { command: 'rm -rf ./test-data' } }))
  assert.equal(replay.status, 'rejected')
  assert.equal(replay.code, 'already_consumed')
})

test('plugin registers its loopback web API', async () => {
  const { ctx, routes } = makeCtx()
  apply(ctx, {})
  await new Promise((resolve) => setTimeout(resolve, 20))
  assert.equal(routes.length, 1)
  assert.equal(routes[0].path, '/human-intent/api')
  assert.equal(routes[0].kind, 'prefix')
})

test('human_intent_status reports enforcement shape', async () => {
  const { ctx, registered } = makeCtx()
  apply(ctx, { protectedTools: ['shell.exec'] })
  const tool = toolByName(registered, 'human_intent_status')
  const status = JSON.parse(await tool.execute({}, { agent: { id: 's1' } }))
  assert.equal(status.status, 'ok')
  assert.equal(status.enabled, true)
  assert.equal(status.method, 'webauthn')
  assert.equal(status.policy[0].tool, 'shell.exec')
})

test('human_intent_request reports invalid input without crashing', async () => {
  const { ctx, registered } = makeCtx()
  apply(ctx, {})
  const tool = toolByName(registered, 'human_intent_request')
  const result = JSON.parse(await tool.execute({ tool: '', arguments: {} }, {}))
  assert.equal(result.status, 'invalid')
  assert.equal(result.approved, false)
})
