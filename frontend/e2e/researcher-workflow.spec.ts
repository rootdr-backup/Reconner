import { expect, test } from '@playwright/test'

const NEW_PASSWORD = 'E2E-Strong-Password-2026!'

test('first boot, project CRUD, focused scan and phase ledger', async ({ page }, testInfo) => {
  const consoleErrors: string[] = []
  page.on('console', message => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })
  page.on('pageerror', error => consoleErrors.push(error.message))

  await page.goto('/')
  await expect(page).toHaveURL(/\/login$/)
  await page.getByLabel('Username').fill('admin')

  // repeat-each exercises the same running service. The first iteration owns
  // first-boot password rotation; later iterations must log in with the rotated
  // password instead of depending on a pristine database.
  await page.getByLabel('Password').fill(NEW_PASSWORD)
  const currentLogin = await Promise.all([
    page.waitForResponse(response => response.url().endsWith('/api/auth/login') && response.request().method() === 'POST'),
    page.getByRole('button', { name: 'Sign In' }).click(),
  ])
  if (!currentLogin[0].ok()) {
    await page.getByLabel('Password').fill('change_m)_e')
    const initialLogin = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/api/auth/login') && response.request().method() === 'POST'),
      page.getByRole('button', { name: 'Sign In' }).click(),
    ])
    expect(initialLogin[0].ok()).toBeTruthy()
    await expect(page.getByRole('heading', { name: 'Set a new password' })).toBeVisible()
    await page.getByLabel('New password', { exact: true }).fill(NEW_PASSWORD)
    await page.getByLabel('Confirm new password').fill(NEW_PASSWORD)
    await page.getByRole('button', { name: 'Set password' }).click()
  }
  await expect(page.getByRole('heading', { name: 'Attack surface overview' })).toBeVisible()
  // The initial anonymous /auth/me probe intentionally returns 401 so the app
  // redirects to login; Chromium reports that expected response as a console
  // resource error. Product-console assertions start after authentication.
  consoleErrors.length = 0

  await page.getByRole('link', { name: /System & updates/ }).click()
  await page.getByRole('tab', { name: 'Integrations' }).click()
  const telegram = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Telegram control bot' }) })
  await telegram.getByLabel('Chat ID').fill('1340857378')
  await telegram.getByLabel('Label', { exact: true }).fill('Owner chat')
  await telegram.locator('select').first().selectOption('admin')
  await telegram.getByRole('button', { name: 'Add chat' }).click()
  await expect(telegram.getByText('1340857378')).toBeVisible()
  await telegram.getByLabel('Chat ID').fill('-1001234567890')
  await telegram.getByLabel('Label', { exact: true }).fill('Bounty team')
  await telegram.locator('select').first().selectOption('operator')
  await telegram.getByRole('button', { name: 'Add chat' }).click()
  await expect(telegram.getByText('-1001234567890')).toBeVisible()

  for (const chatID of ['1340857378', '-1001234567890']) {
    const row = telegram.getByText(chatID).locator('..').locator('..')
    page.once('dialog', dialog => dialog.accept())
    await row.getByRole('button', { name: 'Remove' }).click()
    await expect(telegram.getByText(chatID)).toHaveCount(0)
  }

  await page.getByRole('link', { name: /Projects/ }).click()
  await page.getByRole('button', { name: '+ New Project' }).click()
  const createDialog = page.getByRole('dialog', { name: 'Create Project' })
  const initialName = `E2E local app ${testInfo.repeatEachIndex}`
  const verifiedName = `E2E verified app ${testInfo.repeatEachIndex}`
  await createDialog.getByLabel('Project name').fill(initialName)
  await createDialog.getByLabel('Initial assets *').fill('http://127.0.0.1:18080')
  await createDialog.getByLabel('Tags (comma separated)').fill('e2e, local')
  await createDialog.getByRole('button', { name: 'Create', exact: true }).click()
  await expect(page.getByText(initialName, { exact: true })).toBeVisible()

  await page.getByTitle('Edit target').click()
  const editDialog = page.getByRole('dialog', { name: 'Edit Project' })
  await editDialog.getByLabel('Project name').fill(verifiedName)
  await editDialog.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText(verifiedName, { exact: true })).toBeVisible()

  await page.getByRole('button', { name: 'Scan', exact: true }).click()
  const scanDialog = page.getByRole('dialog', { name: new RegExp(`Scan — ${verifiedName}`) })
  await scanDialog.getByRole('button', { name: 'Clear' }).click()
  await scanDialog.getByRole('button', { name: /HTTP service probe/ }).click()
  await scanDialog.getByRole('button', { name: '▶ Start Scan (1 phases)' }).click()

  await page.getByRole('link', { name: /Scan activity/ }).click()
  await expect(page.getByText(verifiedName, { exact: true })).toBeVisible()
  await page.getByText(verifiedName, { exact: true }).click()
  await expect(page.getByLabel('Scan phase outcomes')).toContainText('http_probe')
  await expect(page.getByLabel('Scan phase outcomes')).toContainText('completed', { timeout: 30_000 })

  await page.getByRole('link', { name: /Projects/ }).click()
  await page.getByTitle('Delete target').click()
  const deleteDialog = page.getByRole('dialog', { name: 'Delete Project' })
  await deleteDialog.getByRole('button', { name: 'Delete', exact: true }).click()
  await expect(page.getByText(verifiedName, { exact: true })).toHaveCount(0)

  expect(consoleErrors, `browser console/page errors:\n${consoleErrors.join('\n')}`).toEqual([])
})
