import type { Page } from '@playwright/test'
import { expect, guardedPage, test } from './fixtures'

// Every test runs signed out, offline-safe (see fixtures.ts) and starts from the
// bundled "Startup (ACLs)" sample unless it says otherwise. Expected values come
// from reading that sample policy, not from copying the app's output blindly.

const STORE = 'policy-lab:v1'

async function openSample(page: Page, id = 'startup') {
  await page.goto(`/app?sample=${id}`)
  await expect(page.locator('table.matrix')).toBeVisible()
}
const policyEditor = (page: Page) => page.getByLabel('Tailnet policy file')
const editorStatus = (page: Page) => page.locator('.pane-head .status')
const sampleSelect = (page: Page) => page.getByRole('combobox', { name: /Sample/ })
const tab = (page: Page, name: string) => page.getByRole('tab', { name })
const cell = (page: Page, from: string, to: string) => page.locator(`table.matrix button[aria-label^="${from} to ${to}: "]`)

test.describe('landing and docs', () => {
  test('landing page opens the lab and docs render', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveTitle(/Policy Lab/)
    await expect(page.getByRole('heading', { level: 1 })).toContainText('See who can reach what')
    await page.getByRole('link', { name: 'Open the lab' }).first().click()
    await expect(page).toHaveURL(/\/app$/)
    await expect(page.locator('table.matrix')).toBeVisible()

    await page.goto('/docs')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('How Policy Lab evaluates a tailnet policy')
  })
})

test.describe('access matrix', () => {
  test('loads a sample, shows the matrix and filters by port', async ({ page }) => {
    await page.goto('/app?sample=enterprise')
    await expect(page.locator('table.matrix')).toBeVisible()
    await sampleSelect(page).selectOption('startup')
    await expect(policyEditor(page)).toHaveValue(/Acme Robotics/)
    await expect(editorStatus(page)).toHaveText('✓ Valid HuJSON')

    // 12 devices; each row has one column per destination, the sample's devices plus the subnet host.
    await expect(page.locator('table.matrix tbody tr')).toHaveCount(12)
    await expect(page.locator('.tile', { hasText: 'Allowed paths' })).toContainText('of 144 possible')
    await expect(page.locator('.tile', { hasText: 'Mesh coverage' })).toContainText('any port')

    // From the sample: group:eng reaches prod only on 443, CI reaches prod on 22.
    await expect(cell(page, 'alice-mbp', 'api-prod-1')).toHaveAttribute('aria-label', 'alice-mbp to api-prod-1: tcp+udp:443')
    await expect(cell(page, 'gh-runner', 'api-prod-1')).toHaveAttribute('aria-label', 'gh-runner to api-prod-1: tcp+udp:22')
    await expect(cell(page, 'alice-mbp', 'dana-mbp')).toHaveAttribute('aria-label', 'alice-mbp to dana-mbp: denied')

    await page.getByLabel('Filter by port').fill('22')
    await expect(page.locator('.tile', { hasText: 'Mesh coverage' })).toContainText('on port 22')
    await expect(cell(page, 'alice-mbp', 'api-prod-1')).toHaveAttribute('aria-label', 'alice-mbp to api-prod-1: denied')
    await expect(cell(page, 'gh-runner', 'api-prod-1')).toHaveAttribute('aria-label', 'gh-runner to api-prod-1: tcp+udp:22')
    await expect(cell(page, 'alice-mbp', 'staging-1')).toHaveAttribute('aria-label', 'alice-mbp to staging-1: tcp+udp:*')

    await page.getByLabel('Filter by port').fill('')
    await expect(cell(page, 'alice-mbp', 'api-prod-1')).toHaveAttribute('aria-label', 'alice-mbp to api-prod-1: tcp+udp:443')
  })
})

test.describe('why', () => {
  test('explains an allowed and a denied connection with the exact rule', async ({ page }) => {
    await openSample(page)

    // Allowed: select the matrix cell. alice is in group:eng, so acls[1] (0-based) grants tag:prod:443.
    await cell(page, 'alice-mbp', 'api-prod-1').click()
    await expect(tab(page, 'Why?')).toHaveAttribute('aria-selected', 'true')
    const verdict = page.locator('.verdict')
    await expect(verdict).toContainText('Allowed')
    await expect(verdict).toContainText('alice-mbp → api-prod-1 on tcp:443')
    const matched = page.locator('.rule.hit')
    await expect(matched).toHaveCount(1)
    await expect(matched).toContainText('acls[1]')
    await expect(matched).toContainText('Source via group:eng, destination via tag:prod:443')
    // The same rule is lit in the editor, and only that line.
    await expect(page.locator('.ln-hit')).toHaveCount(1)
    await expect(page.locator('.ln-hit')).toContainText('"src": ["group:eng"], "dst": ["tag:staging:*", "tag:prod:443"]')

    // Denied: same pair on port 22. Nothing allows it; acls[1] is the near miss because it only opens 443.
    await page.getByLabel('Port', { exact: true }).fill('22')
    await expect(verdict).toContainText('Denied')
    await expect(verdict).toContainText('alice-mbp → api-prod-1 on tcp:22')
    await expect(page.locator('.rule.hit')).toHaveCount(0)
    const nearMiss = page.locator('.rule.near', { hasText: 'acls[1]' })
    await expect(nearMiss).toContainText('Source and destination match, but it only allows tcp+udp:443')
    await expect(page.locator('.ln-hit')).toHaveCount(0)
    await expect(page.locator('.ln-near', { hasText: '"tag:prod:443"' })).toHaveCount(1)
  })
})

test.describe('policy diff', () => {
  test('editing a rule shows the connections gained and lost', async ({ page }) => {
    await openSample(page)
    await tab(page, 'Policy diff').click()
    await page.getByRole('button', { name: 'Use current as baseline' }).click()
    await expect(page.getByText('No change in network access')).toBeVisible()
    await expect(page.locator('.tile', { hasText: 'Connections gained' })).toContainText('+0')

    // Engineers lose HTTPS to prod and gain SSH to prod instead.
    const text = await policyEditor(page).inputValue()
    const edited = text.replace('"tag:staging:*", "tag:prod:443"', '"tag:staging:*", "tag:prod:22"')
    expect(edited).not.toBe(text)
    await policyEditor(page).fill(edited)

    // Three engineers own four devices (alice has two); two prod hosts: 4 x 2 = 8 pairs change.
    await expect(page.locator('.tile', { hasText: 'Connections gained' })).toContainText('+8')
    await expect(page.locator('.tile', { hasText: 'Connections lost' })).toContainText('−8')
    const row = page.locator('.diff-table tbody tr', { has: page.locator('code', { hasText: /^alice-mbp$/ }) }).filter({ hasText: 'api-prod-1' })
    await expect(row).toContainText('+ tcp+udp:22')
    await expect(row).toContainText('− tcp+udp:443')
    await expect(row.locator('td').nth(3)).toHaveText('tcp+udp:443')
    await expect(row.locator('td').nth(4)).toHaveText('tcp+udp:22')

    await page.getByRole('group', { name: 'Filter changes' }).getByRole('button', { name: 'gained' }).click()
    // Every changed pair here both gains and loses, so the filter keeps all eight rows.
    await expect(page.locator('.diff-table tbody tr')).toHaveCount(8)
    await expect(page.locator('.chip-gain')).toHaveCount(8)
  })
})

test.describe('policy tests', () => {
  test('runs the policys own tests and reports the one that fails on purpose', async ({ page }) => {
    await openSample(page)
    await expect(tab(page, 'Tests')).toContainText('1')
    await tab(page, 'Tests').click()

    await expect(page.locator('.tile', { hasText: 'Test blocks' })).toContainText('6/7')
    await expect(page.locator('.tile', { hasText: 'Assertions' })).toContainText('13/14')
    await expect(page.locator('.tile', { hasText: 'Save would be' })).toContainText('Rejected')

    const failing = page.locator('li.test.bad')
    await expect(failing).toHaveCount(1)
    await expect(failing).toContainText('tests[3]')
    await expect(failing).toContainText('from eve@acme.dev')
    const failedRow = failing.locator('tr.row-bad')
    await expect(failedRow).toContainText('192.168.10.5:631')
    await expect(failedRow).toContainText('deny')
    await expect(failedRow).toContainText('✕ accept')
    await expect(failedRow).toContainText('acls[3]')
    await expect(page.locator('li.test.ok')).toHaveCount(6)

    // Selecting the failing block lights it in the editor.
    await failing.locator('.test-head').click()
    await expect(page.locator('.ln-err')).toContainText('"deny": ["192.168.10.5:631"]')

    // Turning the expectation around makes every block pass and the save acceptable.
    const text = await policyEditor(page).inputValue()
    const fixed = text.replace('"deny": ["192.168.10.5:631"]', '"accept": ["192.168.10.5:631"]')
    expect(fixed).not.toBe(text)
    await policyEditor(page).fill(fixed)
    await expect(page.locator('.tile', { hasText: 'Test blocks' })).toContainText('7/7')
    await expect(page.locator('.tile', { hasText: 'Save would be' })).toContainText('Accepted')
    await expect(page.locator('li.test.bad')).toHaveCount(0)
  })
})

test.describe('syntax errors', () => {
  test('reports line and column and flags results as coming from the last good version', async ({ page }) => {
    await openSample(page)
    await expect(page.locator('.tile', { hasText: 'Allowed paths' })).toContainText('54')
    const text = await policyEditor(page).inputValue()
    // Line 24 is the first acls rule; dropping the comma after "accept" puts the error at the next quote, column 25.
    const broken = text.replace('{"action": "accept", "src": ["group:sre"]', '{"action": "accept" "src": ["group:sre"]')
    expect(broken.split('\n')[23]).toBe('    {"action": "accept" "src": ["group:sre"], "dst": ["*:*"]},')
    await policyEditor(page).fill(broken)

    await expect(editorStatus(page)).toHaveText('✕ Line 24, col 25')
    const alert = page.locator('.ed-error')
    await expect(alert).toContainText("Expected ',' or '}' but found '\"' (missing comma?)")
    await expect(alert).toContainText('Results below use the last version that parsed.')
    await expect(page.locator('.ln-err').first()).toBeVisible()

    // The views keep the last good result, so a change made while broken must not leak into them.
    await policyEditor(page).fill(broken.replace('"dst": ["*:*"]', '"dst": ["*:*"], "bogus": '))
    await expect(editorStatus(page)).toContainText('✕ Line')
    await expect(alert).toContainText('Results below use the last version that parsed.')
    await expect(page.locator('.tile', { hasText: 'Allowed paths' })).toContainText('54')

    // Fixing it clears the error and results follow the new text.
    await policyEditor(page).fill(text.replace('"dst": ["*:*"]', '"dst": ["tag:prod:22"]'))
    await expect(editorStatus(page)).toHaveText('✓ Valid HuJSON')
    await expect(alert).toHaveCount(0)
    await expect(page.locator('.tile', { hasText: 'Allowed paths' })).not.toContainText('54')
  })

  test('shows no results at all when the only version is broken', async ({ page }) => {
    await page.addInitScript(([key]) => {
      if (!localStorage.getItem(key)) localStorage.setItem(key, JSON.stringify({ text: '{ "acls": [ { "action": "accept" "src": ["*"] } ] }', inv: { users: [], devices: [] }, old: '', sampleId: '' }))
    }, [STORE])
    await page.goto('/app')
    await expect(editorStatus(page)).toHaveText('✕ Line 1, col 34')
    await expect(page.getByRole('heading', { name: 'Fix the syntax error to see results' })).toBeVisible()
    await expect(page.locator('table.matrix')).toHaveCount(0)
    await expect(page.locator('.tile')).toHaveCount(0)
    await expect(page.locator('.stale-note')).toHaveCount(0)
  })

  // Line 24 is the first acls rule; dropping the comma after "accept" breaks the syntax at line 24, col 25.
  const breakFirstRule = (text: string) => {
    const broken = text.replace('{"action": "accept", "src": ["group:sre"]', '{"action": "accept" "src": ["group:sre"]')
    expect(broken).not.toBe(text)
    return broken
  }

  test('every result view says it is out of date while the policy has a syntax error', async ({ page }) => {
    await openSample(page)
    const stale = page.locator('.stale-note')
    await expect(stale).toHaveCount(0)

    // Why? on an allowed pair: one rule, highlighted in the editor.
    await cell(page, 'alice-mbp', 'api-prod-1').click()
    const verdict = page.locator('.verdict')
    await expect(verdict).toContainText('Allowed')
    await expect(verdict).toContainText('1 matching rule, highlighted in the editor.')
    await expect(page.locator('.ln-hit')).toHaveCount(1)
    await expect(stale).toHaveCount(0)

    const text = await policyEditor(page).inputValue()
    await policyEditor(page).fill(breakFirstRule(text))
    await expect(editorStatus(page)).toHaveText('✕ Line 24, col 25')

    // The old result is still shown, but it is marked, and it no longer claims a highlight that cannot exist.
    await expect(stale).toBeVisible()
    await expect(stale).toContainText('Out of date')
    await expect(stale).toContainText('line 24, col 25')
    await expect(verdict).toContainText('Allowed')
    await expect(verdict).toContainText('1 matching rule.')
    await expect(verdict).not.toContainText('highlighted in the editor')
    await expect(page.locator('.ln-hit')).toHaveCount(0)

    // Every other result view carries the marker; the inventory is input, not a result.
    for (const name of ['Access matrix', 'Tests', 'Policy diff', 'Lints', 'Graph']) {
      await tab(page, name).click()
      await expect(page.locator('#view .stale-note'), name).toBeVisible()
    }
    await tab(page, 'Inventory').click()
    await expect(stale).toHaveCount(0)

    // Fixing the syntax removes the marker and the highlight comes back.
    await policyEditor(page).fill(text)
    await expect(editorStatus(page)).toHaveText('✓ Valid HuJSON')
    await expect(stale).toHaveCount(0)
    await tab(page, 'Why?').click()
    await expect(verdict).toContainText('1 matching rule, highlighted in the editor.')
    await expect(page.locator('.ln-hit')).toHaveCount(1)
  })

  test('the Tests verdict from an older version is marked while the text is broken', async ({ page }) => {
    await openSample(page)
    await tab(page, 'Tests').click()
    const saveTile = page.locator('.tile', { hasText: 'Save would be' })
    await expect(saveTile).toContainText('Rejected')

    // Make every test pass, then break the syntax: the last good version said "Accepted".
    const text = await policyEditor(page).inputValue()
    const fixed = text.replace('"deny": ["192.168.10.5:631"]', '"accept": ["192.168.10.5:631"]')
    expect(fixed).not.toBe(text)
    await policyEditor(page).fill(fixed)
    await expect(saveTile).toContainText('Accepted')
    await expect(page.locator('.stale-note')).toHaveCount(0)

    await policyEditor(page).fill(breakFirstRule(fixed))
    await expect(editorStatus(page)).toHaveText('✕ Line 24, col 25')
    await expect(page.locator('.tile', { hasText: 'Test blocks' })).toContainText('7/7')
    await expect(saveTile).toContainText('Accepted')
    // The Accepted figure is from the older text, and the panel says so right above it.
    const stale = page.locator('#view .stale-note')
    await expect(stale).toBeVisible()
    await expect(stale).toContainText('This view shows the last version that parsed')
    expect(await stale.evaluate((n) => n.compareDocumentPosition(document.querySelector('.tiles')!) & Node.DOCUMENT_POSITION_FOLLOWING)).toBeTruthy()

    await policyEditor(page).fill(fixed)
    await expect(editorStatus(page)).toHaveText('✓ Valid HuJSON')
    await expect(page.locator('.stale-note')).toHaveCount(0)
  })
})

test.describe('share links', () => {
  test('a share link restores policy and inventory in a new browser context', async ({ page, browser, baseURL, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write'])
    await openSample(page)

    const marker = '// shared by e2e: marker 7f3a'
    await policyEditor(page).fill(marker + '\n' + (await policyEditor(page).inputValue()))
    await tab(page, 'Inventory').click()
    await page.getByLabel('Device name').first().fill('shared-device-1')
    await page.getByRole('button', { name: 'Copy share link' }).click()
    await expect(page.locator('.toast')).toContainText('Share link copied')
    const link = await page.evaluate(() => navigator.clipboard.readText())
    expect(link).toMatch(new RegExp(`^${baseURL!.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/app#s=[A-Za-z0-9_-]+$`))

    const other = await guardedPage(browser, baseURL!)
    try {
      await other.page.goto(link)
      await expect(other.page.locator('.toast')).toContainText('Loaded shared policy')
      await expect(policyEditor(other.page)).toHaveValue(new RegExp(marker))
      await expect(sampleSelect(other.page)).toHaveValue('')
      await expect(sampleSelect(other.page).locator('option:checked')).toHaveText('Your policy')
      await expect(other.page.locator('table.matrix tbody th.rowh', { hasText: 'shared-device-1' })).toBeVisible()
      // The fragment is removed from the address bar once loaded.
      await expect(other.page).toHaveURL(/\/app$/)
      other.guard.check()
    } finally {
      await other.context.close()
    }
  })

  test('a damaged share link is ignored with a message and the default sample loads', async ({ browser, baseURL }) => {
    const other = await guardedPage(browser, baseURL!)
    try {
      await other.page.goto('/app#s=not-a-real-share-link')
      await expect(other.page.locator('.toast')).toContainText('That share link is damaged, so it was ignored')
      await expect(other.page.locator('table.matrix')).toBeVisible()
      await expect(policyEditor(other.page)).toHaveValue(/Acme Robotics/)
      other.guard.check()
    } finally {
      await other.context.close()
    }
  })
})

test.describe('persistence', () => {
  test('edits and inventory survive a reload', async ({ page }) => {
    await openSample(page)
    const marker = '// persisted by e2e: marker 51c9'
    await policyEditor(page).fill(marker + '\n' + (await policyEditor(page).inputValue()))
    await tab(page, 'Inventory').click()
    await page.getByLabel('Device name').first().fill('persisted-device-1')
    // Saved to localStorage after a short debounce.
    await expect.poll(() => page.evaluate((k) => localStorage.getItem(k) ?? '', STORE)).toContain('persisted-device-1')

    await page.goto('/app')
    await expect(policyEditor(page)).toHaveValue(new RegExp(marker))
    await expect(sampleSelect(page).locator('option:checked')).toHaveText('Your policy')
    await expect(page.locator('table.matrix tbody th.rowh', { hasText: 'persisted-device-1' })).toBeVisible()

    // Choosing a sample replaces the saved state, and that survives a reload too.
    await sampleSelect(page).selectOption('homelab')
    await expect.poll(() => page.evaluate((k) => localStorage.getItem(k) ?? '', STORE)).toContain('"sampleId":"homelab"')
    await page.reload()
    await expect(policyEditor(page)).toHaveValue(/Nguyen household/)
    await expect(sampleSelect(page)).toHaveValue('homelab')
  })

  test('corrupt saved state falls back to the default sample without errors', async ({ page }) => {
    await page.addInitScript(([key]) => localStorage.setItem(key, '{not json'), [STORE])
    await page.goto('/app')
    await expect(page.locator('table.matrix')).toBeVisible()
    await expect(policyEditor(page)).toHaveValue(/Acme Robotics/)
  })
})
