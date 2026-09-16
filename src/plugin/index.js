/**
 * dsh-human-intent — DeepSeek Harness host plugin.
 *
 * Exposes the human intent protocol to agents:
 *   - tools: human_intent_request / human_intent_verify / human_intent_status
 *   - protectedTools policy enforced via tools/pre-execute: matching tools
 *     execute only after a human authorized the EXACT action (tool +
 *     arguments), verified cryptographically at consumption time.
 *   - loopback web API for the approval UI and SSE events.
 *
 * This plugin follows the verified DSH plugin API surface used by its
 * predecessor (tools/webServer/systemPrompt/settings injection).
 */
import Schema from '@deepseek-ai/schemastery'
import { CredentialStore } from '../auth/credential-store.js'
import { WebAuthnAuthenticator } from '../auth/webauthn.js'
import { AuditLog } from '../audit/audit.js'
import { compilePolicy } from '../policy/policy.js'
import { IntentService, IntentConsumptionError } from '../service.js'
import { createApiRouter } from '../server/routes.js'

export const name = 'human-intent'
export const inject = ['tools', 'systemPrompt', 'settings', 'webServer', 'sessions']

export const SETTINGS_NAMESPACE = 'human-intent'

const DEFAULT_PORT = 8787
const REQUEST_TIMEOUT_GRACE_MS = 5_000
const WEB_API_PREFIX = '/human-intent/api'

export const Config = Schema.object({
  enabled: Schema.boolean().default(true).description('Enforce human intent authorization for protected tools.'),
  rpID: Schema.string().default('localhost').description('WebAuthn relying-party ID (hostname of the UI origin).'),
  allowedOrigins: Schema.array(Schema.string()).default([]).description('Origins allowed for WebAuthn ceremonies, e.g. http://localhost:5600. Empty = http://localhost:<port>.'),
  protectedTools: Schema.array(Schema.string()).default([]).description('Tool names (exact or dot-glob like shell.*) requiring human intent authorization.'),
  rules: Schema.array(Schema.object({
    tool: Schema.string().default(''),
    risk: Schema.string().default(''),
  })).default([]).description('Protected-tool rules with risk levels.'),
  dataDir: Schema.string().default('').description('Directory for credentials and audit storage; empty keeps everything in memory.'),
  requestTtlMs: Schema.number().default(120_000).description('How long a request stays open for the human decision.'),
  port: Schema.number().default(DEFAULT_PORT).description('Fallback port used to derive default allowed origins.'),
})

export function apply(ctx, entryConfig = {}, deps = {}) {
  const config = {
    enabled: entryConfig.enabled !== false,
    rpID: entryConfig.rpID ?? 'localhost',
    allowedOrigins: Array.isArray(entryConfig.allowedOrigins) && entryConfig.allowedOrigins.length > 0
      ? entryConfig.allowedOrigins
      : [`http://localhost:${entryConfig.port ?? DEFAULT_PORT}`],
    protectedTools: Array.isArray(entryConfig.protectedTools) ? entryConfig.protectedTools : [],
    rules: Array.isArray(entryConfig.rules) ? entryConfig.rules : [],
    dataDir: entryConfig.dataDir || null,
    requestTtlMs: entryConfig.requestTtlMs ?? 120_000,
    port: entryConfig.port ?? DEFAULT_PORT,
  }

  const authenticator = new WebAuthnAuthenticator({
    expectedOrigins: config.allowedOrigins,
    expectedRPID: config.rpID,
    rpName: 'dsh-human-intent',
  })
  const credentials = deps.credentialStore ?? new CredentialStore({
    file: config.dataDir ? `${config.dataDir}/credentials.json` : null,
    inMemory: !config.dataDir,
  })
  const audit = deps.audit ?? new AuditLog({
    file: config.dataDir ? `${config.dataDir}/audit.jsonl` : null,
    inMemory: !config.dataDir,
  })
  const policy = compilePolicy({ protectedTools: config.protectedTools, rules: config.rules })
  // deps.service allows tests (and embedders) to supply a pre-wired service.
  const service = deps.service ?? new IntentService({ authenticator, credentialStore: credentials, audit, policy, requestTtlMs: config.requestTtlMs })

  const textOut = (value) => [{ type: 'text', text: JSON.stringify(value) }]

  function sessionIdOf(exec) {
    return exec?.agent?.id ?? exec?.agent?.session?.id ?? 'local'
  }

  const GUIDANCE = `## Human intent authorization (dsh-human-intent)

Before executing a protected tool (deletion, deployment, spending, messaging on your behalf), the harness requires a human to authorize the EXACT action. Call human_intent_request with the action you propose: the human sees tool, target and full arguments, then approves or denies.

- On approved, the returned IntentReceipt authorizes exactly that action; it is one-shot and expires with the request window.
- On denied, the human explicitly refused. State that to the user and do not retry the action.
- On expired or cancelled, propose the action again only if the human asks.
- Never fabricate, cache, or reuse receipts. A receipt only authorizes the exact arguments it was issued for.`

  ctx.systemPrompt?.section({ name: 'tool:human-intent', order: 108, text: GUIDANCE })

  async function ensureReady() {
    if (!service.initialized) await service.init()
    return service
  }

  ctx.tools.register({
    name: 'human_intent_request',
    description: 'Request human authorization for one exact action before executing it. The human sees the full action and approves with a passkey (Touch ID / Windows Hello). Returns an IntentReceipt on approval.',
    parameters: {
      type: 'object',
      properties: {
        tool: { type: 'string', description: 'Tool the agent intends to execute.' },
        operation: { type: 'string', description: 'Optional operation name.' },
        target: { type: 'string', description: 'Optional target identifier (resource, path, recipient).' },
        arguments: { type: 'object', description: 'Exact arguments that will be passed to the tool.' },
        reason: { type: 'string', description: 'Short human-readable explanation shown to the approver.' },
        risk: { type: 'string', enum: ['low', 'medium', 'high', 'critical'] },
      },
      required: ['tool', 'arguments'],
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textOut(value) },
    timeoutMs: config.requestTtlMs + REQUEST_TIMEOUT_GRACE_MS,
    async execute(args, exec) {
      const active = await ensureReady()
      if (!config.enabled) {
        return JSON.stringify({ status: 'disabled', approved: false, message: 'human intent enforcement is disabled in plugin config' })
      }
      let created
      try {
        created = await active.createIntent({
          action: {
            tool: String(args.tool ?? ''),
            ...(args.operation ? { operation: String(args.operation) } : {}),
            ...(args.target ? { target: String(args.target) } : {}),
            arguments: args.arguments ?? {},
          },
          context: {
            reason: args.reason ? String(args.reason) : 'agent requests execution of this action',
            ...(args.risk ? { risk: args.risk } : {}),
          },
          agent: { id: sessionIdOf(exec) },
          session: { id: sessionIdOf(exec) },
        })
      } catch (error) {
        return JSON.stringify({ status: 'invalid', approved: false, error: error.message })
      }
      const settled = await created.result
      if (settled.status === 'approved') {
        return JSON.stringify({
          status: 'approved',
          approved: true,
          receipt: settled.receipt,
          message: 'human authorized this exact action; it is one-shot and bound to these arguments',
        })
      }
      if (settled.status === 'denied') {
        return JSON.stringify({
          status: 'denied',
          approved: false,
          decision: 'denied',
          message: 'human denied this action; do not execute it and do not retry without new instructions',
        })
      }
      return JSON.stringify({ status: settled.status, approved: false, message: `request ${settled.status}; no authorization was granted` })
    },
  })

  ctx.tools.register({
    name: 'human_intent_verify',
    description: 'Verify that an IntentReceipt authorizes one exact action before executing it. Rejects replayed, expired, denied, or mutated-action receipts.',
    parameters: {
      type: 'object',
      properties: {
        receipt: { type: 'object', description: 'IntentReceipt previously returned by human_intent_request.' },
        tool: { type: 'string' },
        operation: { type: 'string' },
        target: { type: 'string' },
        arguments: { type: 'object' },
      },
      required: ['receipt', 'tool', 'arguments'],
    },
    output: { schema: { type: 'string' }, render: (_args, value) => textOut(value) },
    async execute(args) {
      const active = await ensureReady()
      try {
        const result = await active.consumeReceipt(args.receipt, {
          tool: String(args.tool ?? ''),
          ...(args.operation ? { operation: String(args.operation) } : {}),
          ...(args.target ? { target: String(args.target) } : {}),
          arguments: args.arguments ?? {},
        })
        return JSON.stringify({ status: 'verified', authorized: true, ...result })
      } catch (error) {
        if (error instanceof IntentConsumptionError) {
          return JSON.stringify({ status: 'rejected', authorized: false, code: error.code, error: error.message })
        }
        return JSON.stringify({ status: 'error', authorized: false, error: error.message })
      }
    },
  })

  ctx.tools.register({
    name: 'human_intent_status',
    description: 'Report the human-intent enforcement status: pending requests, registered credentials, and protected tool rules.',
    parameters: { type: 'object', properties: {} },
    output: { schema: { type: 'string' }, render: (_args, value) => textOut(value) },
    async execute() {
      const active = await ensureReady()
      const status = await active.status()
      return JSON.stringify({ status: 'ok', enabled: config.enabled, ...status })
    },
  })

  ctx.on?.('tools/pre-execute', async (exec, next) => {
    const decision = await next()
    if (decision.kind !== 'allow') return decision
    const toolName = exec?.name
    if (toolName === 'human_intent_request' || toolName === 'human_intent_verify' || toolName === 'human_intent_status') {
      return decision
    }
    if (!config.enabled) return decision
    const rule = policy.match(toolName)
    if (!rule) return decision
    const active = await ensureReady()
    const action = {
      tool: toolName,
      ...(exec.operation ? { operation: String(exec.operation) } : {}),
      ...(exec.target ? { target: String(exec.target) } : {}),
      arguments: exec.arguments ?? exec.args ?? {},
    }
    let created
    try {
      created = await active.createIntent({
        action,
        context: {
          reason: `protected tool ${toolName} requires human authorization`,
          risk: rule.risk ?? 'high',
        },
        agent: { id: sessionIdOf(exec) },
        session: { id: sessionIdOf(exec) },
      })
    } catch (error) {
      return { kind: 'deny', reason: `human intent request could not be created: ${error.message}` }
    }
    const settled = await created.result
    if (settled.status !== 'approved') {
      const why = settled.status === 'denied'
        ? 'human denied this action'
        : `human authorization ${settled.status}`
      return { kind: 'deny', reason: `${why}; the tool call is not authorized` }
    }
    try {
      await active.consumeReceipt(settled.receipt, action)
      return decision
    } catch (error) {
      // SECURITY: an approved receipt that fails consumption is not a pass.
      return { kind: 'deny', reason: `intent consumption failed: ${error.message}` }
    }
  })

  if (ctx.webServer?.register) {
    let api = null
    const registerRoutes = async () => {
      await ensureReady()
      api = createApiRouter({ service, prefix: WEB_API_PREFIX })
      ctx.webServer.register({
        kind: 'prefix',
        path: WEB_API_PREFIX,
        handler: api.handler,
      })
    }
    if (typeof ctx.effect === 'function') {
      ctx.effect(() => {
        const promise = registerRoutes()
        return () => {
          api?.dispose()
          void promise
        }
      })
    } else {
      void registerRoutes()
    }
  }

  if (typeof ctx.inject === 'function') {
    try {
      ctx.inject(['settings'], (settingsCtx) => {
        if (!settingsCtx?.settings?.register) return
        const scope = settingsCtx.settings.register(SETTINGS_NAMESPACE, Config, { base: config })
        settingsCtx.effect?.(() => () => { scope?.dispose?.() })
      })
    } catch { /* settings unavailable; config stays as loaded */ }
  }

  return {
    service: () => service,
    policy,
    config,
  }
}
