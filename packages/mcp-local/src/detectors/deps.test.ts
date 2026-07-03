import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { parseLockfile, scanDependencies } from './deps';

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'opzy-dep-')); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const NPM_LOCK = JSON.stringify({
  lockfileVersion: 3,
  packages: { '': {}, 'node_modules/lodash': { version: '4.17.20' } },
});

describe('parseLockfile', () => {
  it('extracts name+version from package-lock.json', () => {
    writeFileSync(join(dir, 'package-lock.json'), NPM_LOCK);
    expect(parseLockfile(dir)).toContainEqual({ name: 'lodash', version: '4.17.20' });
  });

  it('reads pnpm-lock.yaml when there is no package-lock.json', () => {
    writeFileSync(join(dir, 'pnpm-lock.yaml'), "lockfileVersion: '9.0'\npackages:\n  /lodash@4.17.20:\n    resolution: {integrity: sha512-x}\n  /@babel/core@7.20.0:\n    resolution: {integrity: sha512-y}\n");
    const pkgs = parseLockfile(dir);
    expect(pkgs).toContainEqual({ name: 'lodash', version: '4.17.20' });
    expect(pkgs).toContainEqual({ name: '@babel/core', version: '7.20.0' });
  });

  it('reads yarn.lock when there is no npm/pnpm lockfile', () => {
    writeFileSync(join(dir, 'yarn.lock'), '"lodash@^4.17.0":\n  version "4.17.20"\n  resolved "https://x"\n\n"@babel/core@^7.0.0":\n  version "7.20.0"\n');
    const pkgs = parseLockfile(dir);
    expect(pkgs).toContainEqual({ name: 'lodash', version: '4.17.20' });
    expect(pkgs).toContainEqual({ name: '@babel/core', version: '7.20.0' });
  });
});

describe('scanDependencies', () => {
  it('sends only coordinates to OSV and maps the advisory’s real severity', async () => {
    writeFileSync(join(dir, 'package-lock.json'), NPM_LOCK);
    const fetchFn = vi.fn(async (url: string) => {
      if (String(url).includes('/querybatch')) {
        return new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-x' }] }] }), { status: 200 });
      }
      return new Response(JSON.stringify({ id: 'GHSA-x', summary: 'Prototype pollution', database_specific: { severity: 'HIGH' } }), { status: 200 });
    });
    const out = await scanDependencies(dir, { fetchFn: fetchFn as unknown as typeof fetch });

    // privacy: the querybatch body must contain only package coordinates, never source
    const sentBody = JSON.parse(((fetchFn.mock.calls[0] as unknown[])[1] as RequestInit).body as string);
    expect(sentBody).toEqual({ queries: [{ package: { ecosystem: 'npm', name: 'lodash' }, version: '4.17.20' }] });

    expect(out).toHaveLength(1);
    expect(out[0]?.category).toBe('dependency');
    expect(out[0]?.severity).toBe('high'); // resolved from the advisory, not defaulted to medium
    expect(out[0]?.title).toContain('lodash');
    expect(out[0]?.evidence).toContain('GHSA-x');
  });
});
