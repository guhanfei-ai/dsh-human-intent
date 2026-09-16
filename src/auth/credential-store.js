/**
 * Credential store: server-side persistence of registered WebAuthn
 * credentials (public keys). Private keys never leave authenticators and
 * must never be stored here.
 */
import { createHash, randomUUID } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'

export class CredentialStoreError extends Error {
  constructor(message) {
    super(message)
    this.name = 'CredentialStoreError'
  }
}

/**
 * File-backed credential store. One JSON document per store directory.
 * Writes are atomic (tmp file + rename) to avoid torn state.
 */
export class CredentialStore {
  constructor({ file = null, inMemory = false } = {}) {
    if (!file && !inMemory) throw new CredentialStoreError('CredentialStore requires a file path or inMemory mode')
    this.file = file ? resolve(file) : null
    this.inMemory = inMemory
    this.records = null
  }

  async load() {
    if (this.records) return this
    if (this.inMemory) {
      this.records = {}
      return this
    }
    try {
      const raw = await readFile(this.file, 'utf8')
      const parsed = JSON.parse(raw)
      this.records = {}
      for (const record of Object.values(parsed.credentials ?? {})) {
        this.records[record.id] = this.#normalize(record)
      }
    } catch (error) {
      if (error?.code === 'ENOENT') {
        this.records = {}
      } else {
        throw new CredentialStoreError(`credential store is unreadable: ${error.message}`)
      }
    }
    return this
  }

  #normalize(record) {
    return {
      id: String(record.id),
      publicKey: String(record.publicKey),
      counter: Number(record.counter) || 0,
      ...(Array.isArray(record.transports) ? { transports: record.transports } : {}),
      deviceType: record.deviceType === 'multiDevice' ? 'multiDevice' : 'singleDevice',
      backedUp: record.backedUp === true,
      createdAt: record.createdAt ?? new Date().toISOString(),
      label: record.label ?? '',
    }
  }

  #assertLoaded() {
    if (!this.records) throw new CredentialStoreError('credential store not loaded; call load() first')
  }

  async #persist() {
    if (this.inMemory) return
    const payload = JSON.stringify({ version: 1, credentials: this.records }, null, 2)
    await mkdir(dirname(this.file), { recursive: true })
    const tmp = resolve(dirname(this.file), `.credentials-${randomUUID()}.tmp`)
    await writeFile(tmp, payload, 'utf8')
    await rename(tmp, this.file)
  }

  async list() {
    this.#assertLoaded()
    return Object.values(this.records).sort((a, b) => a.createdAt.localeCompare(b.createdAt))
  }

  async get(id) {
    this.#assertLoaded()
    return this.records[id] ?? null
  }

  async save(record) {
    this.#assertLoaded()
    this.records[record.id] = this.#normalize(record)
    await this.#persist()
    return this.records[record.id]
  }

  async updateCounter(id, counter) {
    this.#assertLoaded()
    const record = this.records[id]
    if (!record) throw new CredentialStoreError(`unknown credential ${id}`)
    if (!Number.isInteger(counter) || counter < record.counter) {
      throw new CredentialStoreError(`counter must be a non-decreasing integer (have ${record.counter}, got ${counter})`)
    }
    record.counter = counter
    await this.#persist()
    return record
  }

  async size() {
    this.#assertLoaded()
    return Object.keys(this.records).length
  }
}

/** Privacy-preserving reference for audit logs (never the raw credential id). */
export function credentialRef(credentialId) {
  const digest = createHash('sha256').update(String(credentialId)).digest('hex')
  return `sha256:${digest.slice(0, 16)}`
}
