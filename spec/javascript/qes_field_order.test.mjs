import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { errorKey, qesFieldsLast } from '../../app/javascript/submission_form/qes_step_logic.mjs'

const field = (uuid, type = 'text') => Object.freeze({ uuid, type })

test('moves QES after data and verification, preserving relative order and input', () => {
  const fields = Object.freeze([
    field('qes1', 'qes'), field('text'), field('qes2', 'qes'),
    field('checkbox', 'checkbox'), field('verification', 'verification')
  ])

  assert.deepEqual(qesFieldsLast(fields), [fields[1], fields[3], fields[4], fields[0], fields[2]])
  assert.equal(fields[0].uuid, 'qes1')
})

test('preserves template order and page order within both groups', () => {
  const qes1 = field('qes1', 'qes')
  const qes2 = field('qes2', 'qes')
  const text1 = field('text1')
  const text2 = field('text2')

  assert.deepEqual(qesFieldsLast([qes1, text1, qes2, text2]), [text1, text2, qes1, qes2])
  assert.deepEqual(qesFieldsLast([text2, qes2, qes1, text1]), [text2, text1, qes2, qes1])
})

test('handles empty forms, ordinary forms and consecutive QES fields', () => {
  const ordinary = [field('text'), field('kba', 'kba')]
  const signatures = [field('qes1', 'qes'), field('qes2', 'qes')]

  assert.deepEqual(qesFieldsLast([]), [])
  assert.deepEqual(qesFieldsLast(ordinary), ordinary)
  assert.deepEqual(qesFieldsLast(signatures), signatures)
})

test('form applies QES ordering after page sorting and before grouping steps', () => {
  const form = readFileSync(new URL('../../app/javascript/submission_form/form.vue', import.meta.url), 'utf8')

  assert.match(form, /import \{ qesFieldsLast \} from '\.\/qes_step_logic.mjs'/)
  assert.match(form, /return qesFieldsLast\(sortedFields\)\.reduce/)
  assert.ok(form.indexOf('sortedFields.sort(') < form.indexOf('return qesFieldsLast(sortedFields)'))
})

test('maps missing fields to an error translated in English and Czech', () => {
  const translations = readFileSync(new URL('../../app/javascript/submission_form/i18n.js', import.meta.url), 'utf8')

  assert.equal(errorKey('fields_incomplete'), 'qes_error_fields_incomplete')
  assert.match(translations, /qes_error_fields_incomplete: 'Fill in all required fields/)
  assert.match(translations, /qes_error_fields_incomplete: 'Před podpisem vyplňte všechna povinná pole/)
})
