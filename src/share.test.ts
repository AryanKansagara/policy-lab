import { test } from 'node:test'
import assert from 'node:assert/strict'
import { decodeState, encodeState, shareCodeFromHash } from './share.ts'

test('shareCodeFromHash reads only #s= fragments', () => {
  assert.equal(shareCodeFromHash('#s=abc_DEF-123'), 'abc_DEF-123')
  assert.equal(shareCodeFromHash('#s=a'), 'a')
  // Not share links: nothing to apply, and nothing to clear from the address bar.
  for (const h of ['', '#', '#s=', '#S=abc', '#s', '#x=abc', 's=abc', '#section', ' #s=abc', '#?s=abc']) {
    assert.equal(shareCodeFromHash(h), null, JSON.stringify(h))
  }
})

test('a code taken from a location hash decodes to the encoded state', async () => {
  const state = { t: '// MARK\n{"acls": []}', i: { users: [], devices: [] }, o: '' }
  const code = await encodeState(state)
  assert.deepEqual(await decodeState(shareCodeFromHash(`#s=${code}`)!), state)
})

test('a damaged code from a hash rejects instead of decoding to something', async () => {
  const code = await encodeState({ t: 'x' })
  for (const bad of ['not-a-real-share-link', code.slice(0, 3), code.slice(0, -4), '!!!', code + '%%']) {
    await decodeState(bad).then(() => assert.fail(`decoded ${bad}`), () => {})
  }
})
