#!/usr/bin/env node
/**
 * dsh-human-intent CLI.
 *
 * Commands:
 *   serve [--port N] [--data-dir DIR]   start the approval server + UI
 *   register [--port N]                 register a passkey (opens browser)
 *   demo [a|b|c|d|e]                   run acceptance scenarios A-E
 *   inspect <receipt.json|->            validate & summarize a receipt
 *   audit [--data-dir DIR]              print the audit log
 */
import { readFile } from 'node:fs/promises'
import { createInterface } from 'node:readline/promises'
import { WebAuthnAuthenticator } from '../src/auth/webauthn.js'
import { CredentialStore } from '../src/auth/credential-store.js'
import { AuditLog } from '../src/audit/audit.js'
import { compilePolicy } from '../src/policy/policy.js'
import { IntentService, IntentConsumptionError } from '../src/service.js'
import { createDemoServer, openBrowser } from '../src/server/demo-server.js'
import { parseReceipt } from '../src/intent/receipt.js'
import { validateIntentRequest } from '../src/intent/request.js'

const DEFAULT_PORT = 8787
const DEFAULT_ORIGIN = 'http://localhost:8787'

function parseArgs(argv) {
  const flags = { _: [] }
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--port') flags.port = Number(argv[++i])
    else if (arg === '--data-dir') flags.dataDir = String(argv[++i])
    else if (arg === '--no-open') flags.noOpen = true
    else flags._.push(arg)
  }
  return flags
}

async function buildService({ port = DEFAULT_PORT, dataDir = 'data' } = {}) {
  const origin = `http://localhost:${port}`
  const service = new IntentService({
    authenticator: new WebAuthnAuthenticator({ expectedOrigins: [origin], expectedRPID: 'localhost' }),
    credentialStore: new CredentialStore({ file: `${dataDir}/credentials.json` }),
    audit: new AuditLog({ file: `${dataDir}/audit.jsonl` }),
    policy: compilePolicy({}),
  })
  await service.init()
  return service
}

function printHeader(title) {
  console.log('')
  console.log('─'.repeat(64))
  console.log(title)
  console.log('─'.repeat(64))
}

async function ensureCredential(service, { serverUrl, noOpen }) {
  if (await service.credentials.size() > 0) return
  console.log('No passkey registered yet. Opening the registration page…')
  if (!noOpen) await openBrowser(`${serverUrl}/`)
  console.log('Register a passkey in the browser (Touch ID / Windows Hello), then come back.')
  while ((await service.credentials.size()) === 0) {
    await new Promise((resolve) => setTimeout(resolve, 500))
  }
  console.log('Passkey registered. Proceeding…')
}

async function cmdServe(flags) {
  const port = flags.port ?? DEFAULT_PORT
  const service = await buildService({ port, dataDir: flags.dataDir ?? 'data' })
  const { listen, close } = createDemoServer({ service, port })
  await listen(port)
  const url = `http://localhost:${port}`
  printHeader(`dsh-human-intent approval server — ${url}`)
  console.log('Approval UI:   ' + url)
  console.log('Data dir:      ' + (flags.dataDir ?? 'data'))
  console.log('Credentials:   ' + await service.credentials.size())
  console.log('Press Ctrl+C to stop.')
  if (!flags.noOpen) await openBrowser(url)
  await new Promise(() => {})
}

async function cmdRegister(flags) {
  const port = flags.port ?? DEFAULT_PORT
  const service = await buildService({ port, dataDir: flags.dataDir ?? 'data' })
  const { listen, close } = createDemoServer({ service, port })
  await listen(port)
  const url = `http://localhost:${port}`
  await ensureCredential(service, { serverUrl: url, noOpen: flags.noOpen })
  console.log('Done. A credential is now registered on this host.')
  await close()
}

async function runScenario(service, which, { serverUrl, noOpen }) {
  const say = (text) => console.log('  ' + text)
  const requestApproval = async (spec, { ttlMs } = {}) => {
    const { request, result } = await service.createIntent(spec, { ttlMs })
    say(`request ${request.requestId} created (intentHash ${request.intentHash.slice(0, 16)}…)`)
    if (!noOpen) await openBrowser(`${serverUrl}/intent/${request.requestId}`)
    say('waiting for the human decision in the browser…')
    return { request, result }
  }

  if (which === 'a') {
    printHeader('Scenario A — human authorizes a destructive command (happy path)')
    const action = { tool: 'shell.exec', operation: 'exec', target: './important-data', arguments: { command: 'rm -rf ./important-data' } }
    const { result } = await requestApproval({ action, context: { risk: 'critical', reason: 'agent wants to delete ./important-data' } })
    const settled = await result
    if (settled.status !== 'approved') {
      say(`outcome: ${settled.status} — no authorization granted.`)
      return
    }
    const consumption = await service.consumeReceipt(settled.receipt, action)
    say(`approved. consumption verified: ${consumption.ok === true}`)
    say(`EXECUTED (simulated): ${action.arguments.command}`)
    say('The exact action — and only the exact action — was authorized.')
    return
  }

  if (which === 'b') {
    printHeader('Scenario B — action mutation after approval is rejected')
    const action = { tool: 'shell.exec', operation: 'exec', arguments: { command: 'rm -rf ./test-data' } }
    const { result } = await requestApproval({ action, context: { risk: 'high', reason: 'approve cleanup of ./test-data' } })
    const settled = await result
    if (settled.status !== 'approved') {
      say(`outcome: ${settled.status} — nothing authorized.`)
      return
    }
    say('human approved: rm -rf ./test-data')
    say('agent now swaps the arguments to: rm -rf ./production-data')
    try {
      await service.consumeReceipt(settled.receipt, { tool: 'shell.exec', operation: 'exec', arguments: { command: 'rm -rf ./production-data' } })
      say('!! MUTATION ACCEPTED — this must never happen')
      process.exitCode = 1
    } catch (error) {
      say(`REJECTED [${error.code}]: ${error.message}`)
    }
    return
  }

  if (which === 'c') {
    printHeader('Scenario C — replaying a consumed receipt is rejected')
    const action = { tool: 'shell.exec', operation: 'exec', arguments: { command: 'echo one-shot' } }
    const { result } = await requestApproval({ action, context: { risk: 'medium', reason: 'replay-coverage demo' } })
    const settled = await result
    if (settled.status !== 'approved') {
      say(`outcome: ${settled.status} — nothing authorized.`)
      return
    }
    await service.consumeReceipt(settled.receipt, action)
    say('first use: consumed successfully (one authorization = one execution)')
    say('agent replays the same receipt a second time…')
    try {
      await service.consumeReceipt(settled.receipt, action)
      say('!! REPLAY ACCEPTED — this must never happen')
      process.exitCode = 1
    } catch (error) {
      say(`REJECTED [${error.code}]: ${error.message}`)
    }
    return
  }

  if (which === 'd') {
    printHeader('Scenario D — an expired intent is rejected (no interaction needed)')
    const action = { tool: 'shell.exec', operation: 'exec', arguments: { command: 'echo too late' } }
    const { request, result } = await service.createIntent(
      { action, context: { risk: 'low', reason: 'short-window demo' } },
      { ttlMs: 5_000 },
    )
    say(`request ${request.requestId} created with a 5s window (expires ${request.expiresAt})`)
    say('letting the window elapse…')
    const settled = await result
    say(`settled: ${settled.status}`)
    if (settled.status === 'expired') say('EXPIRED — a fresh human authorization is required. Nothing executed.')
    else process.exitCode = 1
    return
  }

  if (which === 'e') {
    printHeader('Scenario E — an explicit denial reaches the agent')
    const action = { tool: 'shell.exec', operation: 'exec', arguments: { command: 'rm -rf ./important-data' } }
    const { result } = await requestApproval({ action, context: { risk: 'critical', reason: 'agent asks again; deny it' } })
    const settled = await result
    if (settled.status === 'denied') {
      say('settled: denied')
      say('The agent receives: decision="denied" — the human refused, this is not a timeout.')
    } else {
      say(`outcome: ${settled.status} — expected "denied"`)
      process.exitCode = 1
    }
    return
  }

  throw new Error(`unknown scenario "${which}" (expected a, b, c, d or e)`)
}

async function cmdDemo(flags) {
  const port = flags.port ?? DEFAULT_PORT
  const service = await buildService({ port, dataDir: flags.dataDir ?? 'data' })
  const { listen, close } = createDemoServer({ service, port })
  await listen(port)
  const serverUrl = `http://localhost:${port}`
  printHeader('dsh-human-intent — acceptance scenarios')
  console.log(`  server:      ${serverUrl}`)
  console.log('  AI can propose an action. Only a human can authorize it.')

  const chosen = flags._[1]
  const letters = ['a', 'b', 'c', 'd', 'e']
  const titles = {
    a: 'A — approve destructive command',
    b: 'B — action mutation attack',
    c: 'C — receipt replay',
    d: 'D — expired intent',
    e: 'E — explicit denial',
  }
  const run = chosen && letters.includes(chosen) ? [chosen] : null
  let selection = run
  if (!selection) {
    console.log('')
    for (const letter of letters) console.log(`  ${letter}) ${titles[letter]}`)
    const rl = createInterface({ input: process.stdin, output: process.stdout })
    const answer = (await rl.question('\nchoose a scenario (a/b/c/d/e or all): ')).trim().toLowerCase()
    rl.close()
    selection = answer === 'all' ? letters : letters.filter((letter) => answer.startsWith(letter))
    if (selection.length === 0) selection = [answer[0]].filter((letter) => letters.includes(letter))
    if (selection.length === 0) {
      console.log('nothing selected; exiting.')
      await close()
      return
    }
  }
  // Scenario D (expiry) needs no human interaction, so no credential either.
  const needsCredential = selection.some((letter) => letter !== 'd')
  if (needsCredential) await ensureCredential(service, { serverUrl, noOpen: flags.noOpen })
  for (const letter of selection) {
    await runScenario(service, letter, { serverUrl, noOpen: flags.noOpen })
  }
  console.log('')
  console.log('demo finished. audit log: ' + (flags.dataDir ?? 'data') + '/audit.jsonl')
  await close()
}

async function cmdInspect(flags) {
  const target = flags._[1]
  if (!target) {
    console.error('usage: dsh-human-intent inspect <receipt.json | ->')
    process.exitCode = 1
    return
  }
  const raw = target === '-'
    ? await readFile(0, 'utf8')
    : await readFile(target, 'utf8')
  let receipt
  try {
    receipt = parseReceipt(raw)
  } catch (error) {
    console.error(`invalid receipt: ${error.message}`)
    process.exitCode = 1
    return
  }
  try {
    validateIntentRequest(receipt.intent)
  } catch (error) {
    console.error(`embedded intent failed integrity validation: ${error.message}`)
    process.exitCode = 1
    return
  }
  const action = receipt.intent.action
  printHeader('IntentReceipt')
  console.log(`  decision:      ${receipt.decision}`)
  console.log(`  requestId:    ${receipt.requestId}`)
  console.log(`  intentHash:   ${receipt.intentHash}`)
  console.log(`  tool:         ${action.tool}`)
  if (action.operation) console.log(`  operation:    ${action.operation}`)
  if (action.target) console.log(`  target:       ${action.target}`)
  console.log(`  arguments:    ${JSON.stringify(action.arguments)}`)
  console.log(`  signedAt:     ${receipt.signedAt}`)
  console.log(`  expiresAt:    ${receipt.expiresAt}`)
  console.log(`  verification: ${receipt.verification.method} (userVerified=${receipt.verification.userVerified})`)
  if (receipt.authenticator?.credentialId) console.log(`  credential:    ${receipt.authenticator.credentialId.slice(0, 16)}…`)
  if (receipt.deniedReason) console.log(`  deniedReason: ${receipt.deniedReason}`)

  // Full cryptographic re-verification when the credential store is available.
  const dataDir = flags.dataDir ?? 'data'
  const store = new CredentialStore({ file: `${dataDir}/credentials.json` })
  await store.load()
  const credential = await store.get(receipt.authenticator?.credentialId ?? '')
  if (!credential) {
    console.log(`  signature:    not re-verified (credential not found in ${dataDir})`)
    return
  }
  const authenticator = new WebAuthnAuthenticator({ expectedOrigins: [DEFAULT_ORIGIN], expectedRPID: 'localhost' })
  try {
    await authenticator.verifyAuthorization(receipt.intent, receipt.assertion, credential)
    console.log('  signature:    VERIFIED against stored credential public key')
  } catch (error) {
    console.error(`  signature:    FAILED — ${error.message}`)
    process.exitCode = 1
  }
}

async function cmdAudit(flags) {
  const dataDir = flags.dataDir ?? 'data'
  const audit = new AuditLog({ file: `${dataDir}/audit.jsonl` })
  const entries = await audit.readAll()
  if (entries.length === 0) {
    console.log(`no audit entries in ${dataDir}/audit.jsonl`)
    return
  }
  for (const entry of entries) {
    console.log([entry.ts, entry.event, entry.tool ?? '', entry.decision ?? '', entry.requestId ?? ''].filter(Boolean).join('  '))
  }
}

async function main() {
  const argv = process.argv.slice(2)
  const command = argv[0]
  const flags = parseArgs(argv)
  try {
    if (command === 'serve') return await cmdServe(flags)
    if (command === 'register') return await cmdRegister(flags)
    if (command === 'demo') return await cmdDemo(flags)
    if (command === 'inspect') return await cmdInspect(flags)
    if (command === 'audit') return await cmdAudit(flags)
    if (command === '--version' || command === 'version') {
      const { default: pkg } = await import('../package.json', { with: { type: 'json' } })
      console.log(pkg.version)
      return
    }
    console.log('dsh-human-intent — human intent verification and cryptographic action authorization')
    console.log('')
    console.log('Usage:')
    console.log('  dsh-human-intent serve [--port N] [--data-dir DIR] [--no-open]')
    console.log('  dsh-human-intent register [--port N]')
    console.log('  dsh-human-intent demo [a|b|c|d|e] [--no-open]')
    console.log('  dsh-human-intent inspect <receipt.json | -> [--data-dir DIR]')
    console.log('  dsh-human-intent audit [--data-dir DIR]')
    process.exitCode = command && command !== '--help' && command !== 'help' ? 1 : 0
  } catch (error) {
    if (error instanceof IntentConsumptionError) {
      console.error(`consumption rejected [${error.code}]: ${error.message}`)
    } else {
      console.error(error instanceof Error ? error.message : String(error))
    }
    process.exitCode = 1
  }
}

await main()
