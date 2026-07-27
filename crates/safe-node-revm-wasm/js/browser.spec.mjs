import { expect, test } from '@playwright/test'

test('browser WASM replays revm misses over a pinned KPS stream', async ({ page }) => {
  await page.goto('http://127.0.0.1:4173/')
  const result = await page.evaluate(() => window.smokePromise)
  expect(result.status).toBe('success')
  expect(result.attempt).toBeLessThanOrEqual(10)
  await expect(page.locator('body')).toHaveAttribute('data-status', 'ok')
})
