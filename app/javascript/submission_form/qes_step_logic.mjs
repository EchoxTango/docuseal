// Čistá logika kroku QES (SPEC § 6), testovatelná bez Vue v `node --test`.
// `ERROR_KEYS` mapuje kódy z API na i18n klíče; neznámý kód = network.
export const ERROR_KEYS = {
  expired_token: 'qes_error_expired_token',
  used_token: 'qes_error_used_token',
  unknown_token: 'qes_error_expired_token',
  signature_invalid: 'qes_error_signature_invalid',
  qes_required_qscd: 'qes_error_qes_required_qscd',
  level_mismatch: 'qes_error_level_mismatch',
  not_qualified: 'qes_error_not_qualified',
  not_trusted: 'qes_error_not_trusted',
  revoked: 'qes_error_revoked',
  rate_limited: 'qes_error_network',
  server_error: 'qes_error_network',
  network: 'qes_error_network'
}

export const MAX_POLL_MS = 15 * 60 * 1000
export const MAX_BACKOFF_MS = 10_000

export function errorKey (code) {
  return ERROR_KEYS[code] || 'qes_error_network'
}

// Korenový `t` v `form.vue` neumí interpolaci `{level}`/`{minutes}`.
export function doneText (t, level) {
  return t('qes_step_done').replace('{level}', String(level || 'ades').toUpperCase())
}

export function expiresInText (t, minutes) {
  return t('qes_step_expires_in').replace('{minutes}', String(minutes))
}

export function minutesLeft (expiresAt, now = Date.now()) {
  if (!expiresAt) return '—'

  const diff = new Date(expiresAt).getTime() - now

  return String(Math.max(0, Math.ceil(diff / 60000)))
}

export function nextBackoff (backoff) {
  return Math.min(backoff * 2, MAX_BACKOFF_MS)
}

export function pollTimedOut (startedAt, now = Date.now()) {
  return now - startedAt > MAX_POLL_MS
}

export function cancelPath (sessionId) {
  return `/qes_sessions/${encodeURIComponent(sessionId)}/cancel`
}

export function cancelledState () {
  return { phase: 'idle', session: null }
}

export function terminalPhase (state) {
  if (state === 'completed') return 'completed'
  if (state === 'expired') return 'expired'
  if (['failed', 'cancelled', 'declined'].includes(state)) return 'failed'

  return null
}

// Každý požadavek patří ke generaci i konkrétní session.
export function createPollGuard () {
  let generation = 0
  let controller = null

  function invalidate () {
    generation += 1
    controller?.abort()
    controller = null
  }

  return {
    invalidate,
    begin (sessionId) {
      invalidate()
      const capturedGeneration = generation
      controller = new AbortController()

      return {
        sessionId,
        signal: controller.signal,
        isCurrent: (currentSessionId) => generation === capturedGeneration && currentSessionId === sessionId
      }
    }
  }
}
