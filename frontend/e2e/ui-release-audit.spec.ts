import { expect, test, type Page } from '@playwright/test'

const ADMIN_PASSWORD = 'E2E-Strong-Password-2026!'
const INITIAL_PASSWORD = 'change_m)_e'

async function authenticate(page: Page) {
  await page.goto('/')
  await expect(page).toHaveURL(/\/login$/)
  await page.getByLabel('Username').fill('admin')

  let loggedIn = false
  for (const password of [ADMIN_PASSWORD, INITIAL_PASSWORD]) {
    await page.getByLabel('Password').fill(password)
    const [response] = await Promise.all([
      page.waitForResponse(value => value.url().endsWith('/api/auth/login') && value.request().method() === 'POST'),
      page.getByRole('button', { name: 'Sign In' }).click(),
    ])
    if (response.ok()) {
      loggedIn = true
      break
    }
  }
  expect(loggedIn, 'admin login must succeed with the rotated or initial password').toBeTruthy()

  const me = await page.evaluate(async () => {
    const response = await fetch('/api/auth/me')
    const payload = await response.json() as { data?: { must_change_password?: boolean }; must_change_password?: boolean }
    return payload.data || payload
  })
  const passwordHeading = page.getByRole('heading', { name: 'Set a new password' })
  if (me.must_change_password) {
    await expect(passwordHeading).toBeVisible()
    await page.getByLabel('New password', { exact: true }).fill(ADMIN_PASSWORD)
    await page.getByLabel('Confirm new password').fill(ADMIN_PASSWORD)
    const [response] = await Promise.all([
      page.waitForResponse(value => value.url().endsWith('/api/auth/change-password') && value.request().method() === 'POST'),
      page.getByRole('button', { name: 'Set password' }).click(),
    ])
    expect(response.ok(), 'first-boot password rotation must succeed').toBeTruthy()
    await expect(passwordHeading).toBeHidden()
  }
  await expect(page.getByRole('heading', { name: 'Attack surface overview' })).toBeVisible()
}

const routes = [
  ['/', 'Attack surface overview'],
  ['/bounty-programs', 'Bug bounty programs'],
  ['/targets', 'Projects'],
  ['/analyze', 'Guided Analyze'],
  ['/findings', 'Findings'],
  ['/tasks', 'Scan activity'],
  ['/system', 'System & updates'],
] as const

for (const viewport of [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'mobile', width: 390, height: 844 },
]) {
  test(`v3 release UI remains usable on ${viewport.name}`, async ({ browser }) => {
    const context = await browser.newContext({ viewport })
    const page = await context.newPage()
    const errors: string[] = []
    page.on('console', message => {
      if (message.type() === 'error') errors.push(message.text())
    })
    page.on('pageerror', error => errors.push(error.message))

    await authenticate(page)
    // The anonymous auth probe intentionally logs one 401 before login.
    errors.length = 0

    for (const [path, heading] of routes) {
      await page.goto(path)
      await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible()
      await expect(page.locator('main')).toBeVisible()

      const overflow = await page.evaluate(() => ({
        body: document.body.scrollWidth - window.innerWidth,
        root: document.documentElement.scrollWidth - window.innerWidth,
      }))
      expect(overflow.body, `${path} body overflow on ${viewport.name}`).toBeLessThanOrEqual(1)
      expect(overflow.root, `${path} root overflow on ${viewport.name}`).toBeLessThanOrEqual(1)

      // Keyboard users must always get a visible focus target on every page.
      await page.keyboard.press('Tab')
      await expect(page.locator(':focus')).not.toHaveCount(0)
    }

    if (viewport.name === 'mobile') {
      await page.goto('/')
      await page.getByRole('button', { name: 'Open navigation' }).click()
      await expect(page.getByRole('link', { name: /Projects/ })).toBeVisible()
      await page.getByRole('button', { name: 'Close navigation' }).last().click()
    }

    expect(errors, `browser console/page errors:\n${errors.join('\n')}`).toEqual([])
    await context.close()
  })
}
