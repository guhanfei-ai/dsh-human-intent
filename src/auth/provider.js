/**
 * AuthenticatorProvider: the abstraction through which a human proves
 * authorization for one exact intent.
 *
 * The core never talks to "fingerprints" or specific platforms. A provider
 * must:
 *  - produce an authorization challenge bound to the intentHash,
 *  - verify the human's cryptographic response server-side,
 *  - report whether the human was verified (UV), and
 *  - expose enough material for later re-verification of receipts.
 *
 * v0.1 ships WebAuthnAuthenticator. Platform authenticators (Touch ID,
 * Windows Hello), passkeys, hardware security keys and remote approvals
 * are all instances of this interface.
 */
export const AUTHENTICATOR_METHOD_WEBAUTHN = 'webauthn'

/**
 * @typedef {Object} AuthorizationChallenge
 * @property {string} method - provider method identifier (e.g. "webauthn")
 * @property {object} options - provider-specific options handed to the client UI
 */

/**
 * @typedef {Object} AuthorizationVerification
 * @property {boolean} verified
 * @property {string} credentialId
 * @property {boolean} userVerified
 * @property {number} counter
 * @property {object} assertion - raw provider response, embedded in receipts
 */

export class AuthenticatorError extends Error {
  constructor(message, { code = 'verification_failed' } = {}) {
    super(message)
    this.name = 'AuthenticatorError'
    this.code = code
  }
}

/** Contract documentation; JS has no interfaces, this documents the shape. */
export const AuthenticatorProvider = {
  method: 'abstract',
  async registrationOptions(..._args) {
    throw new Error('AuthenticatorProvider#registrationOptions must be implemented')
  },
  async verifyRegistration(..._args) {
    throw new Error('AuthenticatorProvider#verifyRegistration must be implemented')
  },
  async authorizationChallenge(..._args) {
    throw new Error('AuthenticatorProvider#authorizationChallenge must be implemented')
  },
  async verifyAuthorization(..._args) {
    throw new Error('AuthenticatorProvider#verifyAuthorization must be implemented')
  },
}
