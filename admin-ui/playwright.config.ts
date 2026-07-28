import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  testIgnore: '**/live/**',
  forbidOnly: Boolean(process.env.CI),
  reporter: 'line',
  use: {
    baseURL: 'http://127.0.0.1:4178',
    trace: 'retain-on-failure'
  },
  webServer: {
    command: 'pnpm exec vite preview --host 127.0.0.1 --port 4178 --strictPort',
    wait: { stdout: /Local:\s+http:\/\/127\.0\.0\.1:4178\// },
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  }
});
