import test from 'node:test'
import assert from 'node:assert/strict'
import { makeTestService, registerCredential, approvedIntent, shellSpec } from './helpers/context.js'
import { IntentConsumptionError } from '../src/service.js'

async function rejection(promise, code) {
  try {
    await promise
  } catch (error) {
    if (error instanceof IntentConsumptionError) {
      if (code instanceof RegExp) assert.match(error.code, code)
      else if (code) assert.equal(error.code, code)
      return error
    }
    throw error
  }
  assert.fail('expected IntentConsumptionError')
}

test('full flow: agent proposes, human approves, exact action executes once', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, receipt, settled } = await approvedIntent(service, emulator, shellSpec({ command: 'rm -rf ./important-data', flags: [] }))
  assert.equal(settled.status, 'approved')
  assert.equal(receipt.decision, 'approved')
  assert.equal(receipt.intentHash, request.intentHash)
  const consumption = await service.consumeReceipt(receipt, shellSpec({ command: 'rm -rf ./important-data', flags: [] }).action)
  assert.equal(consumption.ok, true)
  assert.equal(consumption.intentHash, request.intentHash)
})

// Scenario A complete.
test('scenario A: destructive command authorized and executed exactly', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const action = { tool: 'shell.exec', operation: 'exec', target: './important-data', arguments: { command: 'rm -rf ./important-data' } }
  const { receipt } = await approvedIntent(service, emulator, { action, context: { risk: 'critical', reason: 'agent asked to clean up' } })
  const consumption = await service.consumeReceipt(receipt, action)
  assert.equal(consumption.tool, 'shell.exec')
  assert.equal(consumption.authorizedAction.arguments.command, 'rm -rf ./important-data')
})

// Scenario B complete.
test('scenario B: mutating the arguments after approval is rejected', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'rm -rf ./test-data' }))
  await rejection(
    service.consumeReceipt(receipt, shellSpec({ command: 'rm -rf ./production-data' }).action),
    'action_mismatch',
  )
})

test('mutating the tool after approval is rejected', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  await rejection(
    service.consumeReceipt(receipt, { tool: 'kubectl.delete', arguments: { command: 'echo hi' } }),
    'action_mismatch',
  )
})

test('mutating the target after approval is rejected', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'deploy' }, { target: 'namespace/test/pod/foo' }))
  await rejection(
    service.consumeReceipt(receipt, { tool: 'shell.exec', target: 'namespace/production/pod/foo', arguments: { command: 'deploy' } }),
    'action_mismatch',
  )
})

test('semantically identical arguments still pass (canonical equivalence)', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'ls', flags: ['-la'] }))
  const consumption = await service.consumeReceipt(receipt, { tool: 'shell.exec', operation: 'exec', arguments: { flags: ['-la'], command: 'ls' } })
  assert.equal(consumption.ok, true)
})

// Scenario C complete.
test('scenario C: replaying a consumed receipt is rejected', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const action = shellSpec({ command: 'rm -rf ./important-data' }).action
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'rm -rf ./important-data' }))
  await service.consumeReceipt(receipt, action)
  await rejection(service.consumeReceipt(receipt, action), 'already_consumed')
})

test('consumption advances the stored credential counter', async () => {
  const { service, emulator, credentials } = await makeTestService()
  const { credentialId } = await registerCredential(service, emulator)
  const record = await credentials.get(credentialId)
  assert.equal(record.counter, 0)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'true' }))
  await service.consumeReceipt(receipt, shellSpec({ command: 'true' }).action)
  assert.equal((await credentials.get(credentialId)).counter, 1)
})

// Scenario D complete.
test('scenario D: an expired request settles as expired', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { result } = await service.createIntent(shellSpec({ command: 'echo late' }), { ttlMs: 5_000 })
  const settled = await new Promise((resolve) => {
    result.then(resolve)
    setTimeout(() => resolve('timeout'), 7_000)
  })
  assert.equal(settled.status, 'expired')
})

test('scenario D: an expired receipt cannot be consumed', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  const forgedExpired = { ...receipt, expiresAt: new Date(Date.now() - 1_000).toISOString() }
  await rejection(service.consumeReceipt(forgedExpired, request.action), 'receipt_expired')
})

// Scenario E complete.
test('scenario E: explicit denial produces a denied receipt the agent can read', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, result } = await service.createIntent(shellSpec({ command: 'rm -rf ./important-data' }))
  const denial = await service.deny(request.requestId, { reason: 'wrong directory' })
  assert.equal(denial.status, 'denied')
  assert.equal(denial.receipt.decision, 'denied')
  const settled = await result
  assert.equal(settled.status, 'denied')
  assert.equal(settled.receipt.decision, 'denied')
  // A denied receipt can never authorize execution.
  await rejection(service.consumeReceipt(settled.receipt, request.action), 'decision_denied')
})

test('a tampered embedded intent (nonce) is rejected', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  const tampered = { ...receipt, intent: { ...receipt.intent, nonce: 'f'.repeat(64) } }
  await rejection(service.consumeReceipt(tampered, shellSpec({ command: 'echo hi' }).action), 'tampered_intent')
})

test('a receipt whose intentHash does not match its embedded intent is rejected', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  const tampered = { ...receipt, intentHash: 'a'.repeat(64) }
  await rejection(service.consumeReceipt(tampered, shellSpec({ command: 'echo hi' }).action), /tampered|hash_mismatch|action_mismatch/)
})

test('approval fails when no credential is registered', async () => {
  const { service, emulator } = await makeTestService()
  const { request } = await service.createIntent(shellSpec({ command: 'echo hi' }))
  const options = await service.authenticationOptions(request.requestId).catch(() => null)
  assert.equal(options, null)
})

test('approval fails with an unknown credential and leaves the request pending', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request } = await service.createIntent(shellSpec({ command: 'echo hi' }))
  const forged = { id: 'unknown-credential-id', response: {} }
  await assert.rejects(() => service.approve(request.requestId, forged), /unknown credential/)
  assert.ok(await service.getIntent(request.requestId))
})

test('a failed verification attempt leaves the request retryable', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request } = await service.createIntent(shellSpec({ command: 'echo hi' }))
  const options = await service.authenticationOptions(request.requestId)
  const tampered = await emulator.sign(options, { tamperSignature: true })
  await assert.rejects(() => service.approve(request.requestId, tampered))
  const genuine = await emulator.sign(options)
  const outcome = await service.approve(request.requestId, genuine)
  assert.equal(outcome.status, 'approved')
})

test('a forged receipt without a valid signature cannot be consumed', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  // Forger attack: build a fully self-consistent intent for the target action
  // (hash checks all pass), then attach the human's signature from a
  // DIFFERENT action. Only the cryptographic verification stops it.
  const { createIntentRequest } = await import('../src/intent/request.js')
  const forgedAction = { tool: 'shell.exec', arguments: { command: 'rm -rf /' } }
  const forgedRequest = createIntentRequest({ action: forgedAction }, {
    now: new Date(request.issuedAt).getTime(),
    nonce: request.nonce,
    requestId: request.requestId,
  })
  const forged = { ...receipt, intent: forgedRequest, intentHash: forgedRequest.intentHash }
  await rejection(service.consumeReceipt(forged, forgedAction), 'verification_failed')
})

test('cancel settles a request without a human decision', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, result } = await service.createIntent(shellSpec({ command: 'echo hi' }))
  const outcome = await service.cancel(request.requestId)
  assert.equal(outcome.status, 'cancelled')
  assert.equal((await result).status, 'cancelled')
})

test('settlement is one-shot: approve then deny fails on a settled request', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request } = await service.createIntent(shellSpec({ command: 'echo hi' }))
  await service.deny(request.requestId, { reason: 'first' })
  await assert.rejects(() => service.approve(request.requestId, {}), /unknown or settled/)
})

test('audit records the full lifecycle without raw argument values', async () => {
  const { service, emulator, audit } = await makeTestService()
  await registerCredential(service, emulator)
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'secret-token-value-123', flags: [] }))
  const secretCommand = 'secret-token-value-123'
  await service.consumeReceipt(receipt, shellSpec({ command: secretCommand, flags: [] }).action)
  const entries = await audit.readAll()
  const events = entries.map((entry) => entry.event)
  assert.ok(events.includes('request-created'))
  assert.ok(events.includes('approved'))
  assert.ok(events.includes('consumed'))
  const raw = JSON.stringify(entries)
  assert.ok(!raw.includes('secret-token-value-123'), 'raw argument values must never reach the audit log')
  const consumed = entries.find((entry) => entry.event === 'consumed')
  assert.equal(consumed.executionStatus, 'authorized')
  assert.match(consumed.credentialRef, /^sha256:[0-9a-f]{16}$/)
})

test('status reports service shape', async () => {
  const { service } = await makeTestService()
  const status = await service.status()
  assert.equal(status.method, 'webauthn')
  assert.equal(status.pendingCount, 0)
  assert.equal(status.credentialCount, 0)
})

// --- Concurrent consumption (single-flight) ---

function tally(results) {
  const fulfilled = results.filter((result) => result.status === 'fulfilled')
  const rejected = results.filter((result) => result.status === 'rejected')
  return { fulfilled, rejected }
}

/** A structurally valid receipt carrying a signature over another action. */
async function forgedVariant(receipt, request) {
  const { createIntentRequest } = await import('../src/intent/request.js')
  const forgedAction = { tool: 'shell.exec', arguments: { command: 'rm -rf /' } }
  const forgedRequest = createIntentRequest({ action: forgedAction }, {
    now: new Date(request.issuedAt).getTime(),
    nonce: request.nonce,
    requestId: request.requestId,
  })
  return { forged: { ...receipt, intent: forgedRequest, intentHash: forgedRequest.intentHash }, forgedAction }
}

test('two concurrent consumptions of one receipt: exactly one succeeds', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const action = shellSpec({ command: 'rm -rf ./important-data' }).action
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'rm -rf ./important-data' }))
  const results = await Promise.allSettled([
    service.consumeReceipt(receipt, action),
    service.consumeReceipt(receipt, action),
  ])
  const { fulfilled, rejected } = tally(results)
  assert.equal(fulfilled.length, 1, `exactly one consumption must succeed, got ${fulfilled.length}`)
  assert.equal(rejected.length, 1)
  assert.ok(rejected[0].reason instanceof IntentConsumptionError)
  assert.equal(rejected[0].reason.code, 'already_consumed')
})

test('ten concurrent consumptions of one receipt: exactly one succeeds', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const action = shellSpec({ command: 'echo hi' }).action
  const { receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  const results = await Promise.allSettled(
    Array.from({ length: 10 }, () => service.consumeReceipt(receipt, action)),
  )
  const { fulfilled, rejected } = tally(results)
  assert.equal(fulfilled.length, 1, `exactly one consumption must succeed, got ${fulfilled.length}`)
  assert.equal(rejected.length, 9)
  for (const { reason } of rejected) {
    assert.ok(reason instanceof IntentConsumptionError)
    assert.equal(reason.code, 'already_consumed')
  }
})

test('a failed verification does not permanently consume the receipt', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  const { forged, forgedAction } = await forgedVariant(receipt, request)
  await rejection(service.consumeReceipt(forged, forgedAction), 'verification_failed')
  assert.equal(service.consumed.has(request.requestId), false)
  // The genuine receipt still authorizes exactly one execution afterwards.
  const consumption = await service.consumeReceipt(receipt, request.action)
  assert.equal(consumption.ok, true)
})

test('a concurrent waiter succeeds after the leading attempt fails verification', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  const { forged, forgedAction } = await forgedVariant(receipt, request)
  const results = await Promise.allSettled([
    service.consumeReceipt(forged, forgedAction),
    service.consumeReceipt(receipt, request.action),
  ])
  const { fulfilled, rejected } = tally(results)
  assert.equal(fulfilled.length, 1)
  assert.equal(rejected.length, 1)
  assert.ok(rejected[0].reason instanceof IntentConsumptionError)
  assert.equal(rejected[0].reason.code, 'verification_failed')
  // And the receipt is now consumed exactly once.
  await rejection(service.consumeReceipt(receipt, request.action), 'already_consumed')
})

test('no stale consumption locks survive success, failure or contention', async () => {
  const { service, emulator } = await makeTestService()
  await registerCredential(service, emulator)
  const { request, receipt } = await approvedIntent(service, emulator, shellSpec({ command: 'echo hi' }))
  assert.equal(service.consumptionLocks.size, 0)
  // Failure path releases its reservation.
  const { forged, forgedAction } = await forgedVariant(receipt, request)
  await rejection(service.consumeReceipt(forged, forgedAction), 'verification_failed')
  assert.equal(service.consumptionLocks.size, 0)
  // Contended success path releases its reservation.
  await Promise.allSettled([
    service.consumeReceipt(receipt, request.action),
    service.consumeReceipt(receipt, request.action),
  ])
  assert.equal(service.consumptionLocks.size, 0)
  // Plain success path releases its reservation too.
  const { receipt: fresh } = await approvedIntent(service, emulator, shellSpec({ command: 'echo again' }))
  await service.consumeReceipt(fresh, shellSpec({ command: 'echo again' }).action)
  assert.equal(service.consumptionLocks.size, 0)
})
