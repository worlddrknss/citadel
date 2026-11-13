import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 20_000,
    // The integration suite builds and starts the real Go server.
    hookTimeout: 300_000,
  },
});
