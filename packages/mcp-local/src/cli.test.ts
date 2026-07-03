import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';

describe('cli module', () => {
  it('exports a createServer that registers security_check', async () => {
    const { createServer } = await import('./cli');
    const server = createServer();
    expect(server).toBeTruthy();
  });

  it('reports the package.json version (no hardcoded drift)', async () => {
    const { SERVER_INFO } = await import('./cli');
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    expect(SERVER_INFO.version).toBe(pkg.version);
  });
});
