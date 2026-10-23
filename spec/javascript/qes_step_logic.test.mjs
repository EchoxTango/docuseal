import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import * as compiler from '@vue/compiler-sfc'

import {
  ERROR_KEYS,
  cancelPath,
  cancelledState,
  doneText,
  errorKey,
  expiresInText,
  minutesLeft,
  nextBackoff,
  pollTimedOut,
  terminalPhase
} from '../../app/javascript/submission_form/qes_step_logic.mjs'

const t = (key) => ({ qes_step_done: 'Signed ({level})', qes_step_expires_in: 'Link expires in {minutes} min' }[key])

test('maps API error codes to i18n keys', () => {
  assert.equal(errorKey('revoked'), 'qes_error_revoked')
  assert.equal(errorKey('unknown_token'), 'qes_error_expired_token')
  assert.equal(errorKey('rate_limited'), 'qes_error_network')
  assert.equal(errorKey('something_new'), 'qes_error_network')
  assert.equal(ERROR_KEYS.not_trusted, 'qes_error_not_trusted')
})

test('builds done and expiry texts with interpolation', () => {
  assert.equal(doneText(t, 'qes'), 'Signed (QES)')
  assert.equal(doneText(t, null), 'Signed (ADES)')
  assert.equal(expiresInText(t, 4), 'Link expires in 4 min')
})

test('counts remaining minutes', () => {
  assert.equal(minutesLeft(null), '—')
  assert.equal(minutesLeft(new Date(Date.now() + 90_000).toISOString()), '2')
  assert.equal(minutesLeft(new Date(Date.now() - 90_000).toISOString()), '0')
})

test('backs off up to 10 s', () => {
  assert.equal(nextBackoff(2000), 4000)
  assert.equal(nextBackoff(8000), 10_000)
})

test('stops polling after 15 minutes', () => {
  assert.equal(pollTimedOut(Date.now()), false)
  assert.equal(pollTimedOut(Date.now() - (16 * 60 * 1000)), true)
})

test('maps states to terminal phases', () => {
  assert.equal(terminalPhase('completed'), 'completed')
  assert.equal(terminalPhase('expired'), 'expired')
  assert.equal(terminalPhase('failed'), 'failed')
  assert.equal(terminalPhase('cancelled'), 'failed')
  assert.equal(terminalPhase('awaiting_app'), null)
})

test('builds the cancel request and state', () => {
  assert.equal(cancelPath(42), '/qes_sessions/42/cancel')
  assert.deepEqual(cancelledState(), { phase: 'idle', session: null })
})

test('qes_step.vue compiles and wires the tested logic', () => {
  const source = readFileSync(new URL('../../app/javascript/submission_form/qes_step.vue', import.meta.url), 'utf8')
  const { descriptor, errors } = compiler.parse(source)

  assert.equal(errors.length, 0)
  assert.equal(descriptor.script != null || descriptor.scriptSetup != null, true)

  const script = compiler.compileScript(descriptor, { id: 'qes-step' })

  assert.match(script.content, /qesStepCancelPath/)
  assert.match(script.content, /qesStepCancelledState/)
  assert.match(script.content, /qesStepTerminalPhase/)
  assert.match(script.content, /qesStepErrorKey/)
  assert.match(script.content, /qesStepNextBackoff/)
  assert.match(script.content, /qesStepPollTimedOut/)
})

test('form.vue and area.vue keep the QesStep integration', () => {
  const form = readFileSync(new URL('../../app/javascript/submission_form/form.vue', import.meta.url), 'utf8')
  const area = readFileSync(new URL('../../app/javascript/submission_form/area.vue', import.meta.url), 'utf8')

  assert.match(form, /import QesStep from '\.\/qes_step'/)
  assert.match(form, /currentField\.type === 'qes'/)
  assert.match(area, /field\.type === 'qes'/)
})
