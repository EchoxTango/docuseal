import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import * as compiler from '@vue/compiler-sfc'

import {
  ERROR_KEYS,
  cancelPath,
  cancelledState,
  createPollGuard,
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


test('invalidates poll tickets and aborts their requests', () => {
  const guard = createPollGuard()
  const old = guard.begin(1)
  assert.equal(old.isCurrent(1), true)
  assert.equal(old.isCurrent(2), false)
  guard.invalidate()
  assert.equal(old.signal.aborted, true)
  assert.equal(old.isCurrent(1), false)
  const replacement = guard.begin(1)
  assert.equal(old.isCurrent(1), false)
  assert.equal(replacement.isCurrent(1), true)
})

function deferred () {
  let resolve
  const promise = new Promise((done) => { resolve = done })
  return { promise, resolve }
}

async function componentInstance () {
  const source = readFileSync(new URL('../../app/javascript/submission_form/qes_step.vue', import.meta.url), 'utf8')
  const logicUrl = new URL('../../app/javascript/submission_form/qes_step_logic.mjs', import.meta.url).href
  const script = source.match(/<script>([\s\S]*?)<\/script>/)[1]
    .replace("'./qes_step_logic.mjs'", JSON.stringify(logicUrl))
  const component = (await import(`data:text/javascript,${encodeURIComponent(script)}`)).default
  const emissions = []
  const timers = []
  const vm = {
    ...component.data.call({ field: {} }),
    field: { uuid: 'field' },
    $emit: (...args) => emissions.push(args)
  }
  for (const [name, method] of Object.entries(component.methods)) vm[name] = method.bind(vm)
  vm.session = { id: 1 }
  vm.startedAt = Date.now()
  vm.schedulePoll = (delay) => timers.push(delay)
  vm.post = async () => ({ id: 2 })
  return { vm, component, emissions, timers }
}

for (const action of ['cancel', 'reset', 'unmount', 'replace']) {
  test(`ignores an outstanding poll after ${action}`, async () => {
    const { vm, component, emissions, timers } = await componentInstance()
    const pending = deferred()
    vm.fetchState = () => pending.promise
    const poll = vm.poll()

    if (action === 'cancel') await vm.cancelSession()
    if (action === 'reset') vm.reset()
    if (action === 'unmount') component.beforeUnmount.call(vm)
    if (action === 'replace') await vm.createSession()
    const expectedEmissions = [...emissions]
    const expectedTimers = [...timers]

    pending.resolve({ state: 'completed', value: 'qes:old' })
    await poll

    assert.deepEqual(emissions, expectedEmissions)
    assert.deepEqual(timers, expectedTimers)
    assert.notEqual(vm.phase, 'completed')
  })
}

for (const stage of ['fetch', 'json']) {
  test(`ignores a poll cancelled during ${stage}`, async () => {
    const { vm, emissions, timers } = await componentInstance()
    const pending = deferred()
    const originalFetch = globalThis.fetch
    globalThis.fetch = stage === 'fetch'
      ? () => pending.promise
      : async () => ({ ok: true, json: () => pending.promise })
    try {
      const poll = vm.poll()
      await Promise.resolve()
      vm.reset()
      pending.resolve(stage === 'fetch'
        ? { ok: true, json: async () => ({ state: 'completed', value: 'qes:old' }) }
        : { state: 'completed', value: 'qes:old' })
      await poll
      assert.deepEqual(emissions, [])
      assert.deepEqual(timers, [])
    } finally {
      globalThis.fetch = originalFetch
    }
  })
}

test('does not resurrect a session created after unmount', async () => {
  const { vm, component, emissions, timers } = await componentInstance()
  const pending = deferred()
  vm.post = () => pending.promise
  const creating = vm.createSession()
  component.beforeUnmount.call(vm)
  pending.resolve({ id: 2 })
  await creating
  assert.equal(vm.session, null)
  assert.deepEqual(emissions, [['start']])
  assert.deepEqual(timers, [])
})


test('accepts the current completion response', async () => {
  const { vm, emissions, timers } = await componentInstance()
  vm.fetchState = async () => ({ state: 'completed', value: 'qes:current' })
  await vm.poll()
  assert.deepEqual(emissions, [['update:modelValue', 'qes:current'], ['submit']])
  assert.deepEqual(timers, [])
  assert.equal(vm.phase, 'completed')
})

test('resumes polling an in-progress signature returned by create without a token', async () => {
  const { vm, component, timers } = await componentInstance()
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => ({
    ok: false,
    status: 409,
    json: async () => ({ error: 'signature_in_progress', id: 42, state: 'awaiting_signature' })
  })
  vm.csrfToken = () => null
  vm.post = component.methods.post.bind(vm)
  try {
    await vm.createSession()
    assert.equal(vm.session.id, 42)
    assert.equal(vm.session.token, undefined)
    assert.equal(vm.phase, 'awaiting_app')
    assert.deepEqual(timers, [2000])
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('ignores a stale request failure without restarting polling', async () => {
  const { vm, emissions, timers } = await componentInstance()
  const pending = deferred()
  vm.fetchState = () => pending.promise.then(() => { throw new Error('network') })
  const poll = vm.poll()
  vm.reset()
  pending.resolve()
  await poll
  assert.deepEqual(emissions, [])
  assert.deepEqual(timers, [])
  assert.equal(vm.phase, 'idle')
})
