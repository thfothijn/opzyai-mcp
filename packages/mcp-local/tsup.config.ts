import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { cli: 'src/cli.ts' },
  format: ['esm'],
  target: 'node20',
  platform: 'node',
  noExternal: ['@appsec/detectors', '@appsec/core'],
  banner: { js: '#!/usr/bin/env node' },
  clean: true,
});
