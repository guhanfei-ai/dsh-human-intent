/**
 * Test context builder: an in-memory IntentService wired to a software
 * authenticator emulator with real keys.
 */
import { WebAuthnAuthenticator } from '../../src/auth/webauthn.js'
import { CredentialStore } from '../../src/auth/credential-store.js'
import { AuditLog } from '../../src/audit/audit.js'
import { IntentService } from '../../src/service.js'
import { compilePolicy } from '../../src/policy/policy.js'
import { WebAuthnEmulator } from './webauthn-emulator.js'

export const TEST_ORIGIN = 'http://localhost:8787'
export const TEST_RP_ID = 'localhost'

export async function makeTestService({ policy = {}, origin = TEST_ORIGIN, rpId = TEST_RP_ID, requestTtlMs } = {}) {
  const authenticator = new WebAuthnAuthenticator({ expectedOrigins: [origin], expectedRPID: rpId })
  const credentials = new CredentialStore({ inMemory: true })
  const audit = new AuditLog({ inMemory: true })
  const service = new IntentService({ authenticator, credentialStore: credentials, audit, policy: compilePolicy(policy), ...(requestTtlMs ? { requestTtlMs } : {}) })
  await service.init()
  const emulator = new WebAuthnEmulator({ origin, rpId })
  return { service, authenticator, credentials, audit, emulator }
}

/** Register an emulator credential through the real registration flow. */
export async function registerCredential(service, emulator, { userName = 'test-operator' } = {}) {
  const options = await service.registrationOptions({ userName })
  const attestation = await emulator.register(options)
  return service.registerCredential(attestation)
}

/** Create a pending intent and resolve it with a genuine approval. */
export async function approvedIntent(service, emulator, spec, options = {}) {
  const { request, result } = await service.createIntent(spec)
  const authOptions = await service.authenticationOptions(request.requestId)
  const assertion = await emulator.sign(authOptions, options.sign ?? {})
  const outcome = await service.approve(request.requestId, assertion)
  const settled = await result
  return { request, assertion, authOptions, receipt: outcome.receipt ?? settled.receipt, settled }
}

/** Standard destructive-action spec used across scenarios. */
export function shellSpec(arguments_, extra = {}) {
  return {
    action: {
      tool: 'shell.exec',
      operation: 'exec',
      ...(extra.target ? { target: extra.target } : {}),
      arguments: arguments_,
    },
    context: {
      reason: extra.reason ?? 'cleanup task requested by the agent',
      risk: extra.risk ?? 'high',
    },
    agent: { id: 'test-agent' },
    session: { id: 'test-session' },
    ...extra.spec,
  }
}
