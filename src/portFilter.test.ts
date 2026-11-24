import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parsePortFilter, PORT_FILTER_ERROR } from './portFilter.ts'

test('numbers from 0 to 65535 are a port filter', () => {
  for (const [text, port] of [['0', 0], ['22', 22], ['443', 443], ['0022', 22], ['65535', 65535], [' 80 ', 80]] as const) {
    assert.deepEqual(parsePortFilter(text), { kind: 'port', port }, text)
  }
})

test('empty text means no filter', () => {
  for (const text of ['', ' ', '\t']) assert.deepEqual(parsePortFilter(text), { kind: 'any' }, JSON.stringify(text))
})

test('anything else is reported, never silently treated as no filter', () => {
  const odd = ['abc', '22 80', '22,80', 'tcp:22', '22-80', '22.0', '-1', '+22', '1e3', '0x16', '٢٢', '22/tcp', '22;', '70000', '65536', '99999999999999999999999']
  for (const text of odd) assert.deepEqual(parsePortFilter(text), { kind: 'invalid', message: PORT_FILTER_ERROR }, text)
})

test('the message matches the Why? tab', () => {
  assert.equal(PORT_FILTER_ERROR, 'Port must be a number from 0 to 65535.')
})
