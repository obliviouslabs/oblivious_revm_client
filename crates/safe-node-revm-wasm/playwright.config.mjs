import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './js',
  testMatch: 'browser.spec.mjs',
  timeout: 60_000,
  use: { headless: true },
  webServer: {
    command: 'node js/fixture-server.mjs',
    url: 'http://127.0.0.1:4173/health',
    reuseExistingServer: true,
    timeout: 30_000
  }
})
