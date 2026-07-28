import { defineConfig } from '@playwright/test';

const baseURL = process.env.CAMELLIA_NEXUS_ADMIN_E2E_BASE_URL;

if (!baseURL) {
  throw new Error('CAMELLIA_NEXUS_ADMIN_E2E_BASE_URL is required for live Admin UI tests');
}

export default defineConfig({
  testDir: './tests/live',
  outputDir: process.env.CAMELLIA_NEXUS_ADMIN_E2E_OUTPUT_DIR ?? 'test-results/live',
  forbidOnly: true,
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'line',
  use: {
    baseURL,
    actionTimeout: 30_000,
    trace: 'off',
    screenshot: 'only-on-failure'
  }
});
