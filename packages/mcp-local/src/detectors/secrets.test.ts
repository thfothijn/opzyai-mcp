import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { scanWorkingTreeSecrets } from './secrets';

// Assembled at runtime so no contiguous key-shaped string ever exists in this
// file's source or git history (keeps our own scanner and GitHub secret
// scanning quiet on this repo).
const FAKE_KEY_SRC = ['sk_live', 'abcdEFGH1234567890'].join('_');
const FAKE_KEY_NODE_MODULES = ['sk_live', 'zzzzZZZZ0000000000'].join('_');

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'opzy-sec-'));
  execFileSync('git', ['init'], { cwd: dir, stdio: 'ignore' });
});
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('scanWorkingTreeSecrets', () => {
  it('finds a hardcoded key in a source file but skips node_modules', async () => {
    writeFileSync(join(dir, 'config.ts'), `export const k = "${FAKE_KEY_SRC}";`);
    mkdirSync(join(dir, 'node_modules'));
    writeFileSync(join(dir, 'node_modules', 'x.js'), FAKE_KEY_NODE_MODULES);
    const out = await scanWorkingTreeSecrets(dir);
    expect(out).toHaveLength(1);
    expect(out[0]?.category).toBe('secret');
    expect(out[0]?.location).toContain('config.ts');
  });
});
