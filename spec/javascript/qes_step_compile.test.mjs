import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import * as compiler from '@vue/compiler-sfc'

test('qes_step.vue compiles and wires the tested logic', () => {
  const source = readFileSync(new URL('../../app/javascript/submission_form/qes_step.vue', import.meta.url), 'utf8')
  const { descriptor, errors } = compiler.parse(source)

  assert.equal(errors.length, 0)
  assert.equal(descriptor.script != null || descriptor.scriptSetup != null, true)

  const script = compiler.compileScript(descriptor, { id: 'qes-step' })
  const template = compiler.compileTemplate({ source: descriptor.template.content, id: 'qes-step', filename: 'qes_step.vue' })
  assert.deepEqual(template.errors, [])

  assert.match(script.content, /qesStepCancelPath/)
  assert.match(script.content, /qesStepCancelledState/)
  assert.match(script.content, /qesStepTerminalPhase/)
  assert.match(script.content, /qesStepErrorKey/)
  assert.match(script.content, /qesStepNextBackoff/)
  assert.match(script.content, /qesStepPollTimedOut/)
})
