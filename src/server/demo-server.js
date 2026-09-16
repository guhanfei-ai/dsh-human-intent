/**
 * Standalone HTTP server for demos, local development, and CLI flows.
 * Serves the approval UI from public/ plus the loopback API.
 */
import { createServer } from 'node:http'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { extname, join, normalize, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApiRouter } from './routes.js'

const PUBLIC_DIR = resolve(fileURLToPath(import.meta.url), '../../../public')
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
}

export function createDemoServer({ service, port = 8787, host = '127.0.0.1' } = {}) {
  const api = createApiRouter({ service, prefix: '/api', fallthrough: true })
  const server = createServer(async (req, res) => {
    try {
      const handled = await api.handler(req, res)
      if (handled) return
      await serveStatic(req, res)
    } catch (error) {
      if (res.writableEnded || res.destroyed) {
        console.error('[dsh-human-intent] request handler error after response ended:', req.method, req.url, error.message)
        return
      }
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' })
      }
      res.end(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }))
    }
  })

  async function serveStatic(req, res) {
    if (req.method !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ ok: false, error: 'method not allowed' }))
      return
    }
    const url = new URL(req.url ?? '/', 'http://localhost')
    let pathname = decodeURIComponent(url.pathname)
    // Approval page: /intent/:id renders the intent detail view.
    if (/^\/intent\/[A-Za-z0-9_-]+$/.test(pathname)) pathname = '/index.html'
    if (pathname === '/') pathname = '/index.html'
    // SECURITY: resolve inside public/ only; reject traversal.
    const target = normalize(join(PUBLIC_DIR, pathname))
    if (!target.startsWith(PUBLIC_DIR + sep) && target !== PUBLIC_DIR) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ ok: false, error: 'forbidden' }))
      return
    }
    let stats
    try {
      stats = await stat(target)
    } catch {
      res.writeHead(404, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ ok: false, error: 'not found' }))
      return
    }
    const filePath = stats.isDirectory() ? join(target, 'index.html') : target
    const finalPath = normalize(filePath)
    if (!finalPath.startsWith(PUBLIC_DIR + sep)) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' })
      res.end(JSON.stringify({ ok: false, error: 'forbidden' }))
      return
    }
    const type = MIME_TYPES[extname(finalPath)] ?? 'application/octet-stream'
    res.writeHead(200, {
      'Content-Type': type,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'",
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
    })
    createReadStream(finalPath).pipe(res)
  }

  return {
    server,
    listen(extraPort) {
      return new Promise((resolvePromise, reject) => {
        server.once('error', reject)
        server.listen(extraPort ?? port, host, () => resolvePromise(server.address()))
      })
    },
    close() {
      api.dispose()
      return new Promise((resolvePromise) => server.close(() => resolvePromise()))
    },
  }
}

/** Open a URL in the default browser (best effort). */
export async function openBrowser(url) {
  const { spawn } = await import('node:child_process')
  const command = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open'
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url]
  try {
    const child = spawn(command, args, { stdio: 'ignore', detached: true })
    child.unref()
    return true
  } catch {
    return false
  }
}
