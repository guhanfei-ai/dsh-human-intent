/**
 * Local audit log: append-only JSONL record of every intent lifecycle
 * transition.
 *
 * PRIVACY: raw action arguments are never written. Only the arguments
 * hash (part of intentHash), the tool/operation/target labels, and a
 * redacted credential reference are recorded. Never log secrets.
 */
import { createHash } from 'node:crypto'
import { appendFile, mkdir, readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'

export const AUDIT_EVENTS = [
  'request-created',
  'approved',
  'denied',
  'expired',
  'cancelled',
  'consumed',
  'consumption-rejected',
  'assertion-rejected',
  'credential-registered',
  'policy-denied',
]

export class AuditLog {
  constructor({ file = null, inMemory = false, maxEntryBytes = 64 * 1024 } = {}) {
    this.file = file ? resolve(file) : null
    this.inMemory = inMemory
    this.entries = inMemory ? [] : null
    this.maxEntryBytes = maxEntryBytes
    this.listeners = new Set()
  }

  onEvent(listener) {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  async record(entry) {
    const record = {
      ts: new Date().toISOString(),
      event: String(entry.event ?? ''),
      ...(entry.requestId ? { requestId: entry.requestId } : {}),
      ...(entry.intentHash ? { intentHash: entry.intentHash } : {}),
      ...(entry.expiresAt ? { expiresAt: entry.expiresAt } : {}),
      ...(entry.tool ? { tool: entry.tool } : {}),
      ...(entry.operation ? { operation: entry.operation } : {}),
      ...(entry.target ? { target: entry.target } : {}),
      ...(entry.risk ? { risk: entry.risk } : {}),
      ...(entry.decision ? { decision: entry.decision } : {}),
      ...(entry.reason ? { reason: String(entry.reason).slice(0, 500) } : {}),
      ...(entry.verificationMethod ? { verificationMethod: entry.verificationMethod } : {}),
      ...(entry.credentialRef ? { credentialRef: entry.credentialRef } : {}),
      ...(entry.executionStatus ? { executionStatus: entry.executionStatus } : {}),
      ...(entry.rejectionReason ? { rejectionReason: String(entry.rejectionReason).slice(0, 500) } : {}),
    }
    if (!AUDIT_EVENTS.includes(record.event)) {
      throw new Error(`unknown audit event ${JSON.stringify(record.event)}`)
    }
    const line = JSON.stringify(record)
    if (line.length > this.maxEntryBytes) {
      // SECURITY: oversized entries are truncated to labels only, never dropped silently.
      const minimal = JSON.stringify({ ts: record.ts, event: record.event, requestId: record.requestId, intentHash: record.intentHash, note: 'entry-truncated' })
      await this.#write(minimal)
    } else {
      await this.#write(line)
    }
    for (const listener of this.listeners) {
      try { listener(record) } catch { /* listener errors must never break auditing */ }
    }
    return record
  }

  async #write(line) {
    if (this.inMemory) {
      this.entries.push(JSON.parse(line))
      return
    }
    await mkdir(dirname(this.file), { recursive: true })
    await appendFile(this.file, `${line}\n`, 'utf8')
  }

  /** Read all entries (for CLI inspection). */
  async readAll() {
    if (this.inMemory) return [...this.entries]
    let raw = ''
    try {
      raw = await readFile(this.file, 'utf8')
    } catch {
      return []
    }
    return raw.split('\n').filter(Boolean).map((line) => {
      try { return JSON.parse(line) } catch { return { event: 'corrupt-entry', line: line.slice(0, 200) } }
    })
  }

  /**
   * Rebuild the set of consumed (one-shot spent) requestIds that are still
   * inside their validity window. Used on startup so a restart cannot be
   * used to replay receipts.
   */
  async loadConsumedMap(now = Date.now()) {
    const consumed = new Map()
    for (const entry of await this.readAll()) {
      if (entry.event !== 'consumed' || !entry.requestId) continue
      const expiresAt = entry.expiresAt ? new Date(entry.expiresAt).getTime() : 0
      if (expiresAt > now) consumed.set(entry.requestId, entry)
      else if (consumed.has(entry.requestId)) consumed.delete(entry.requestId)
    }
    return consumed
  }
}

/** Digest reference for argument values in audit entries (never raw values). */
export function argumentsRef(action) {
  if (!action || typeof action !== 'object') return ''
  return createHash('sha256').update(JSON.stringify(action.arguments ?? {})).digest('hex').slice(0, 16)
}
