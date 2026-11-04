// Share state in the URL hash: JSON -> deflate-raw -> base64url.
const b64 = (b: Uint8Array) => btoa(Array.from(b, (c) => String.fromCharCode(c)).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const unb64 = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))

async function pipe(data: Uint8Array, t: { readable: ReadableStream; writable: WritableStream }) {
  const w = t.writable.getWriter()
  void w.write(data).then(() => w.close()).catch(() => {})
  return new Uint8Array(await new Response(t.readable).arrayBuffer())
}
export async function encodeState(state: unknown): Promise<string> {
  return b64(await pipe(new TextEncoder().encode(JSON.stringify(state)), new CompressionStream('deflate-raw')))
}
export async function decodeState(s: string): Promise<unknown> {
  return JSON.parse(new TextDecoder().decode(await pipe(unb64(s), new DecompressionStream('deflate-raw'))))
}
