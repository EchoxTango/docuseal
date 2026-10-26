import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

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
  assert.equal(errorKey('fields_incomplete'), 'qes_error_fields_incomplete')
  assert.equal(errorKey('seal_failed'), 'qes_error_seal_failed')
  assert.equal(errorKey('validation_failed'), 'qes_error_validation_failed')
  assert.equal(errorKey('tsa_unavailable'), 'qes_error_tsa_unavailable')
  assert.equal(errorKey('values_changed'), 'qes_error_values_changed')
  assert.equal(errorKey('document_set_changed'), 'qes_error_document_set_changed')
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

async function componentInstance (props = {}) {
  const source = readFileSync(new URL('../../app/javascript/submission_form/qes_step.vue', import.meta.url), 'utf8')
  const logicUrl = new URL('../../app/javascript/submission_form/qes_step_logic.mjs', import.meta.url).href
  const script = source.match(/<script>([\s\S]*?)<\/script>/)[1]
    .replace("'./qes_step_logic.mjs'", JSON.stringify(logicUrl))
  const component = (await import(`data:text/javascript,${encodeURIComponent(script)}`)).default
  const emissions = []
  const timers = []
  const vm = {
    ...component.data.call({ field: {}, ...props }),
    field: { uuid: 'field' },
    ...props,
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


test('starts completed when the field already has a qes token', async () => {
  const { vm } = await componentInstance({ modelValue: 'qes:7' })

  assert.equal(vm.phase, 'completed')
})

test('stops polling on a non-terminal failure', async () => {
  const { vm, timers } = await componentInstance()
  vm.fetchState = async () => ({ state: 'awaiting_signature', error: { code: 'seal_failed' } })

  await vm.poll()

  assert.equal(vm.phase, 'failed')
  assert.equal(vm.error, 'seal_failed')
  assert.deepEqual(timers, [])
})

test('merges frozen values returned while polling', async () => {
  const { vm, emissions } = await componentInstance()
  vm.fetchState = async () => ({ state: 'awaiting_signature', values: { text: 'frozen' } })

  await vm.poll()

  assert.ok(emissions.some(([event, values]) => event === 'update:values' && values.text === 'frozen'))
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
    const calls = []
    globalThis.fetch = async (url, options) => {
      calls.push({ url, method: options.method, body: JSON.parse(options.body) })
      return { ok: true, json: async () => calls.length === 1
        ? { state: 'cancelled' }
        : { id: 43, token: 'fresh', qr_svg: '<svg/>', state: 'awaiting_app' } }
    }
    vm.baseUrl = ''
    vm.submitterSlug = 'signer'
    await vm.restartSession()
    assert.deepEqual(calls, [
      { url: '/s/signer/qes_sessions/42/cancel', method: 'POST', body: {} },
      { url: '/s/signer/qes_sessions', method: 'POST', body: { field_uuid: 'field' } }
    ])
    assert.equal(vm.session.id, 43)
    assert.equal(vm.session.token, 'fresh')
    assert.equal(vm.phase, 'awaiting_app')
    assert.equal(vm.restarting, false)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('shows the in-progress explanation and restart action in Czech and English', () => {
  const vue = readFileSync(new URL('../../app/javascript/submission_form/qes_step.vue', import.meta.url), 'utf8')
  const translations = readFileSync(new URL('../../app/javascript/submission_form/i18n.js', import.meta.url), 'utf8')
  assert.match(vue, /session.error === 'signature_in_progress' \? 'qes_step_in_progress'/)
  assert.match(vue, /@click="restartSession"/)
  assert.match(vue, /t\('qes_step_cancel_restart'\)/)
  assert.match(translations, /Podpis právě probíhá v aplikaci\. Dokončete ho v telefonu, nebo ho zrušte\./)
  assert.match(translations, /Zrušit a začít znovu/)
  assert.match(translations, /Signing is in progress in the app\. Complete it on your phone, or cancel it\./)
  assert.match(translations, /Cancel and start again/)
})

test('waits for confirmed cancellation and suppresses duplicate restart clicks', async () => {
  const { vm } = await componentInstance()
  const pending = deferred()
  const calls = []
  vm.post = async (path) => {
    calls.push(path)
    return path.endsWith('/cancel') ? pending.promise : { id: 2 }
  }
  const restart = vm.restartSession()
  await vm.restartSession()
  assert.deepEqual(calls, ['/qes_sessions/1/cancel'])
  pending.resolve({ state: 'cancelled' })
  await restart
  assert.deepEqual(calls, ['/qes_sessions/1/cancel', '/qes_sessions'])
})

for (const outcome of ['failure', 'completed', 'unmounted']) {
  test(`does not create a replacement after cancellation ${outcome}`, async () => {
    const { vm, component, timers } = await componentInstance()
    const pending = deferred()
    const calls = []
    vm.phase = 'awaiting_app'
    vm.post = async (path) => {
      calls.push(path)
      await pending.promise
      if (outcome === 'failure') throw new Error('network')
      return { state: outcome === 'completed' ? 'completed' : 'cancelled' }
    }
    const restart = vm.restartSession()
    if (outcome === 'unmounted') component.beforeUnmount.call(vm)
    pending.resolve()
    await restart
    assert.deepEqual(calls, ['/qes_sessions/1/cancel'])
    assert.equal(vm.session.id, 1)
    assert.equal(vm.restarting, false)
    if (outcome === 'failure') assert.equal(vm.error, 'network')
    if (outcome === 'unmounted') assert.deepEqual(timers, [])
  })
}

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
