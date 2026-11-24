import { expect, test as base, type Browser, type BrowserContext, type Page } from '@playwright/test'

// The page loads Google Fonts from index.html. That is the only external host
// the app is expected to ask for, and it is blocked so the suite is offline-safe.
// Any other external request is a failure, as is any uncaught page error.
const EXPECTED_BLOCKED = new Set(['fonts.googleapis.com', 'fonts.gstatic.com'])

export interface Guard {
  blocked: string[]
  errors: string[]
  check: () => void
}

export async function guardContext(context: BrowserContext, baseURL: string): Promise<Guard> {
  const origin = new URL(baseURL).origin
  const guard: Guard = {
    blocked: [],
    errors: [],
    check() {
      const unexpected = guard.blocked.filter((u) => !EXPECTED_BLOCKED.has(new URL(u).hostname))
      expect(unexpected, 'unexpected external requests').toEqual([])
      expect(guard.errors, 'uncaught page errors').toEqual([])
    },
  }
  await context.route('**/*', (route) => {
    const url = route.request().url()
    if (url.startsWith('data:') || url.startsWith('blob:') || new URL(url).origin === origin) return route.continue()
    guard.blocked.push(url)
    return route.abort()
  })
  context.on('weberror', (e) => guard.errors.push(e.error().message))
  return guard
}

export async function guardedPage(browser: Browser, baseURL: string, options: Parameters<Browser['newContext']>[0] = {}): Promise<{ page: Page; context: BrowserContext; guard: Guard }> {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, ...options })
  const guard = await guardContext(context, baseURL)
  return { page: await context.newPage(), context, guard }
}

export const test = base.extend<{ guard: Guard }>({
  guard: [
    async ({ context, baseURL }, use) => {
      const guard = await guardContext(context, baseURL!)
      await use(guard)
      guard.check()
    },
    { auto: true },
  ],
})

export { expect }
