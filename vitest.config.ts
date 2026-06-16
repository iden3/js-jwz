import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'node',
          globals: true,
          environment: 'node',
          testTimeout: 60000,
          include: ['test/**/*.test.ts'],
          exclude: ['test/**/*.browser.test.ts']
        }
      },
      {
        test: {
          name: 'browser',
          globals: true,
          testTimeout: 120000,
          include: ['test/**/*.browser.test.ts'],
          browser: {
            enabled: true,
            provider: playwright(),
            headless: true,
            instances: [{ browser: 'chromium' }]
          }
        }
      }
    ]
  }
});
