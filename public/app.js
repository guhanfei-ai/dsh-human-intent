/* global document, window, fetch, location, navigator, PublicKeyCredential, AbortController */
/**
 * Human Intent approval UI.
 *
 * The page shows the EXACT action (tool, operation, target, arguments) and
 * the intent hash. Approving signs the intentHash via WebAuthn; the server
 * re-verifies everything. This page performs no cryptography itself.
 */
(function () {
  'use strict'

  var API = '/api'

  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer)
    let binary = ''
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i])
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  function base64urlToBuffer(value) {
    const padded = String(value).replace(/-/g, '+').replace(/_/g, '/')
    const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
    return bytes.buffer
  }

  // Minimal equivalents of @simplewebauthn/browser's start* functions:
  // they only marshal options and responses. All verification is server-side.
  function startRegistration(options) {
    if (!window.PublicKeyCredential) return Promise.reject(new Error('this browser has no WebAuthn support'))
    return navigator.credentials.create({
      publicKey: {
        challenge: base64urlToBuffer(options.challenge),
        rp: options.rp,
        user: {
          id: base64urlToBuffer(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout,
        excludeCredentials: (options.excludeCredentials || []).map(function (item) {
          return { id: base64urlToBuffer(item.id), type: 'public-key' }
        }),
        authenticatorSelection: options.authenticatorSelection,
        attestation: options.attestation,
      },
    }).then(function (credential) {
      const response = credential.response
      return {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
          attestationObject: bufferToBase64url(response.attestationObject),
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      }
    })
  }

  function startAuthentication(options) {
    if (!window.PublicKeyCredential) return Promise.reject(new Error('this browser has no WebAuthn support'))
    return navigator.credentials.get({
      publicKey: {
        challenge: base64urlToBuffer(options.challenge),
        rpId: options.rpId,
        allowCredentials: (options.allowCredentials || []).map(function (item) {
          return { id: base64urlToBuffer(item.id), type: 'public-key', transports: item.transports }
        }),
        timeout: options.timeout,
        userVerification: options.userVerification || 'required',
      },
    }).then(function (assertion) {
      const response = assertion.response
      return {
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
          authenticatorData: bufferToBase64url(response.authenticatorData),
          signature: bufferToBase64url(response.signature),
          userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
        },
        clientExtensionResults: assertion.getClientExtensionResults(),
      }
    })
  }

  async function api(path, options) {
    const response = await fetch(API + path, {
      method: (options && options.method) || 'GET',
      headers: options && options.body ? { 'content-type': 'application/json' } : {},
      body: options && options.body ? JSON.stringify(options.body) : undefined,
    })
    let payload = null
    try { payload = await response.json() } catch { /* non-json error */ }
    if (!response.ok || !payload || payload.ok !== true) {
      throw new Error((payload && payload.error) || 'HTTP ' + response.status)
    }
    return payload
  }

  function show(id) {
    for (const section of document.querySelectorAll('main > section')) section.classList.add('hidden')
    const el = document.getElementById(id)
    if (el) el.classList.remove('hidden')
  }

  function setText(id, value) {
    const el = document.getElementById(id)
    if (el) el.textContent = value === undefined || value === null || value === '' ? '—' : String(value)
  }

  let countdownTimer = null
  function startCountdown(expiresAt) {
    if (countdownTimer) clearInterval(countdownTimer)
    const target = new Date(expiresAt).getTime()
    const el = document.getElementById('expiry-line')
    function tick() {
      const remaining = target - Date.now()
      if (remaining <= 0) {
        clearInterval(countdownTimer)
        el.textContent = 'request window has elapsed'
        window.location.reload()
        return
      }
      const seconds = Math.floor(remaining / 1000)
      el.textContent = 'expires in ' + seconds + 's — after that a new authorization is required'
      el.classList.add('countdown')
    }
    tick()
    countdownTimer = setInterval(tick, 1000)
  }

  function renderIntent(request) {
    const action = request.action || {}
    const context = request.context || {}
    const badge = document.getElementById('risk-badge')
    const risk = context.risk || 'medium'
    badge.textContent = risk + ' risk'
    badge.className = 'risk-badge risk-' + risk
    setText('action-tool', action.tool)
    setText('action-operation', action.operation)
    setText('action-target', action.target)
    setText('action-reason', context.reason || context.description)
    setText('action-hash', request.intentHash)
    setText('action-nonce', request.nonce)
    document.getElementById('action-arguments').textContent = JSON.stringify(action.arguments, null, 2)
    startCountdown(request.expiresAt)
    show('approval')
  }

  async function registerPasskey() {
    const button = document.getElementById('register-button')
    const errorEl = document.getElementById('register-error')
    button.disabled = true
    errorEl.hidden = true
    try {
      const options = await api('/register/options', { method: 'POST', body: {} })
      const attestation = await startRegistration(options.options)
      await api('/register/verify', { method: 'POST', body: { attestation } })
      await refreshState()
    } catch (error) {
      errorEl.textContent = String(error.message || error)
      errorEl.hidden = false
    } finally {
      button.disabled = false
    }
  }

  async function approveCurrent(options) {
    const status = document.getElementById('approval-status')
    const approveButton = document.getElementById('approve-button')
    const denyButton = document.getElementById('deny-button')
    approveButton.disabled = true
    denyButton.disabled = true
    status.textContent = 'waiting for the platform authenticator…'
    try {
      const assertion = await startAuthentication(options)
      status.textContent = 'verifying signature…'
      await api('/intent/' + encodeURIComponent(currentRequestId) + '/approve', {
        method: 'POST',
        body: { assertion },
      })
      document.getElementById('settled-title').textContent = 'Approved'
      document.getElementById('settled-detail').textContent =
        'The human authorized this exact action.\nintentHash: ' + currentRequest.intentHash +
        '\nThis authorization is one-shot and expires at ' + currentRequest.expiresAt + '.'
      show('settled')
    } catch (error) {
      status.textContent = 'verification failed: ' + String(error.message || error)
      approveButton.disabled = false
      denyButton.disabled = false
    }
  }

  async function denyCurrent() {
    const status = document.getElementById('approval-status')
    document.getElementById('approve-button').disabled = true
    document.getElementById('deny-button').disabled = true
    status.textContent = 'recording denial…'
    try {
      await api('/intent/' + encodeURIComponent(currentRequestId) + '/deny', {
        method: 'POST',
        body: { reason: 'denied from approval page' },
      })
      document.getElementById('settled-title').textContent = 'Denied'
      document.getElementById('settled-detail').textContent =
        'The human denied this action. The agent receives an explicit denial, not a timeout.'
      show('settled')
    } catch (error) {
      status.textContent = String(error.message || error)
    }
  }

  let currentRequestId = null
  let currentRequest = null

  async function loadIntent(requestId) {
    currentRequestId = requestId
    try {
      const payload = await api('/intent/' + encodeURIComponent(requestId))
      currentRequest = payload.request
      renderIntent(payload.request)
      const options = await api('/intent/' + encodeURIComponent(requestId) + '/options')
      document.getElementById('approve-button').onclick = function () { approveCurrent(options.options) }
    } catch (error) {
      document.getElementById('settled-title').textContent = 'Request unavailable'
      document.getElementById('settled-detail').textContent =
        'This request is unknown, already settled, or expired.\n' + String(error.message || error)
      show('settled')
    }
  }

  async function refreshState() {
    const stateEl = document.getElementById('credential-state')
    try {
      const state = await api('/state')
      const count = state.status.credentialCount
      if (count > 0) {
        stateEl.textContent = 'passkey registered'
        stateEl.classList.add('ok')
      } else {
        stateEl.textContent = 'no passkey'
        stateEl.classList.remove('ok')
      }
      return state
    } catch (error) {
      stateEl.textContent = 'offline'
      return null
    }
  }

  async function main() {
    document.getElementById('register-button').onclick = registerPasskey
    document.getElementById('deny-button').onclick = denyCurrent
    const state = await refreshState()
    const intentMatch = location.pathname.match(/^\/intent\/([A-Za-z0-9_-]+)/)
    if (intentMatch) {
      await loadIntent(intentMatch[1])
      return
    }
    if (state && state.status.credentialCount === 0) {
      show('setup')
      return
    }
    show('idle')
    const events = new EventSource(API + '/events')
    events.onmessage = function (event) {
      try {
        const message = JSON.parse(event.data)
        if (message.type === 'request-created' && message.request) {
          window.location.href = '/intent/' + encodeURIComponent(message.request.requestId)
        }
      } catch { /* ignore malformed events */ }
    }
  }

  main().catch(function (error) {
    console.error('[human-intent] failed to initialize', error)
  })
}())
