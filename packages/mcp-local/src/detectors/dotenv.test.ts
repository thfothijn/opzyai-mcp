import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { scanDotenv } from './dotenv';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'opzy-env-'));
  execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });
});
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('scanDotenv', () => {
  it('flags a .env that is not gitignored', async () => {
    writeFileSync(join(dir, '.env'), 'SECRET=abc123');
    const out = await scanDotenv(dir);
    expect(out).toHaveLength(1);
    expect(out[0]?.category).toBe('dotenv');
    expect(out[0]?.severity).toBe('high');
  });
  it('does not flag a .env that IS gitignored', async () => {
    writeFileSync(join(dir, '.env'), 'SECRET=abc123');
    writeFileSync(join(dir, '.gitignore'), '.env\n');
    expect(await scanDotenv(dir)).toHaveLength(0);
  });
});
