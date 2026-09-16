/**
 * HTTP API layer for human-intent flows. Shared by the standalone demo
 * server and the DSH host web-server registration.
 *
 * SECURITY: the API is loopback-only. Requests must be same-origin or
 * explicitly loopback; cross-site requests (sec-fetch-site: cross-site)
 * and foreign Origin headers are rejected before any state changes.
 */
export const API_BODY_LIMIT = 512 * 1024
const PENDING_VIEW_LIMIT = 20

export function trustedRequest(req) {
  const host = String(req?.headers?.host ?? '')
  if (!host) return false
  if (String(req?.headers?.['sec-fetch-site'] ?? '') === 'cross-site') return false
  const origin = String(req?.headers?.origin ?? '')
  if (!origin) return /^(localhost|127\.0\.0\.1|\[::1\])(?::\d+)?$/.test(host)
  try { return new URL(origin).host === host } catch { return false }
}

export function json(res, status, value) {
  const body = JSON.stringify(value)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  })
  res.end(body)
  return true
}

export async function readJsonBody(req, maxBytes = API_BODY_LIMIT) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > maxBytes) throw new Error('request body too large')
    chunks.push(chunk)
  }
  if (chunks.length === 0) return {}
  const text = Buffer.concat(chunks).toString('utf8')
  try {
    return JSON.parse(text)
  } catch {
    throw new Error('request body must be valid JSON')
  }
}

function publicRequestView(request) {
  return {
    requestId: request.requestId,
    intentHash: request.intentHash,
    agent: request.agent ?? null,
    session: request.session ?? null,
    action: request.action,
    context: request.context ?? null,
    issuedAt: request.issuedAt,
    expiresAt: request.expiresAt,
    nonce: request.nonce,
    version: request.version,
  }
}

function errorBody(error) {
  const message = error instanceof Error ? error.message : String(error)
  return { ok: false, error: message }
}

/**
 * Create the loopback API handler.
 * @param {object} options
 * @param {import('../service.js').IntentService} options.service
 * @param {string} [options.prefix] - e.g. '/human-intent/api' (DSH) or '' (standalone)
 * @param {boolean} [options.fallthrough] - when true, unmatched paths are NOT
 *   answered here (returns false) so a static file server can take over.
 * @returns {{handler: Function, dispose: Function}}
 */
export function createApiRouter({ service, prefix = '', fallthrough = false } = {}) {
  const clients = new Set()
  const emit = (message) => {
    const data = `data: ${JSON.stringify(message)}\n\n`
    for (const res of clients) {
      try { res.write(data) } catch { clients.delete(res) }
    }
  }
  const unsubscribe = service.onIntentEvent((event) => {
    if (event.type === 'request-created') {
      emit({ type: 'request-created', request: publicRequestView(event.request) })
    } else if (event.type === 'request-settled') {
      emit({ type: 'request-settled', requestId: event.requestId, status: event.status, decision: event.decision })
    } else if (event.type === 'state-changed') {
      emit({ type: 'state-changed' })
    }
  })

  async function handle(req, res) {
    let pathname
    try {
      pathname = new URL(req.url ?? '/', 'http://dsh-internal.invalid').pathname
      if (prefix) {
        if (!pathname.startsWith(prefix)) return false
        pathname = pathname.slice(prefix.length)
      }
    } catch {
      return false
    }
    if (!trustedRequest(req)) {
      json(res, 403, { ok: false, error: 'forbidden: loopback and same-origin requests only' })
      return true
    }
    const respond = (status, value) => json(res, status, value)
    try {
      if (req.method === 'GET' && pathname === '/state') {
        const status = await service.status()
        return respond(200, {
          ok: true,
          status,
          pending: service.listPending().slice(0, PENDING_VIEW_LIMIT).map(publicRequestView),
        })
      }
      if (req.method === 'GET' && pathname === '/events') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-store',
          Connection: 'keep-alive',
        })
        res.write(`data: ${JSON.stringify({ type: 'hello', pending: service.listPending().slice(0, PENDING_VIEW_LIMIT).map(publicRequestView) })}\n\n`)
        clients.add(res)
        req.on('close', () => clients.delete(res))
        return true
      }
      if (req.method === 'POST' && pathname === '/register/options') {
        const payload = await readJsonBody(req)
        const options = await service.registrationOptions({ userName: typeof payload.userName === 'string' ? payload.userName.slice(0, 120) : undefined })
        return respond(200, { ok: true, options })
      }
      if (req.method === 'POST' && pathname === '/register/verify') {
        const payload = await readJsonBody(req)
        if (!payload?.attestation) return respond(400, { ok: false, error: 'attestation is required' })
        const result = await service.registerCredential(payload.attestation)
        return respond(200, { ok: true, ...result })
      }
      const intentMatch = pathname.match(/^\/intent\/([^/]+)(\/(options|approve|deny|cancel))?$/)
      if (intentMatch) {
        const requestId = decodeURIComponent(intentMatch[1])
        const actionPart = intentMatch[3]
        if (!actionPart && req.method === 'GET') {
          const intent = await service.getIntent(requestId)
          if (!intent) return respond(404, { ok: false, error: 'unknown or settled request' })
          return respond(200, { ok: true, request: publicRequestView(intent.request) })
        }
        if (actionPart === 'options' && req.method === 'GET') {
          const options = await service.authenticationOptions(requestId)
          return respond(200, { ok: true, options })
        }
        if (actionPart === 'approve' && req.method === 'POST') {
          const payload = await readJsonBody(req)
          if (!payload?.assertion) return respond(400, { ok: false, error: 'assertion is required' })
          const result = await service.approve(requestId, payload.assertion)
          return respond(200, { ok: true, status: result.status })
        }
        if (actionPart === 'deny' && req.method === 'POST') {
          const payload = await readJsonBody(req)
          const result = await service.deny(requestId, { reason: typeof payload.reason === 'string' ? payload.reason.slice(0, 500) : '' })
          return respond(200, { ok: true, status: result.status })
        }
        if (actionPart === 'cancel' && req.method === 'POST') {
          const result = await service.cancel(requestId)
          return respond(200, { ok: true, status: result.status })
        }
      }
      if (req.method === 'POST' && pathname === '/verify') {
        const payload = await readJsonBody(req)
        if (!payload?.receipt) return respond(400, { ok: false, error: 'receipt is required' })
        const result = await service.consumeReceipt(payload.receipt, payload.action ?? null)
        return respond(200, { ok: true, ...result })
      }
      if (fallthrough) return false
      return respond(404, { ok: false, error: 'not found' })
    } catch (error) {
      const status = error?.name === 'IntentConsumptionError' ? 403 : 400
      return respond(status, errorBody(error))
    }
  }

  return {
    handler: handle,
    dispose: () => {
      unsubscribe()
      for (const res of clients) {
        try { res.end() } catch { /* already gone */ }
      }
      clients.clear()
    },
  }
}
