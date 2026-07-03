import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanGitHistory } from './git-history';

// Assembled at runtime so no contiguous key-shaped string ever exists in this
// file's source or git history (keeps our own scanner and GitHub secret
// scanning quiet on this repo).
const FAKE_STRIPE_KEY = ['sk_live', 'abcdEFGH1234567890'].join('_');

let dir: string;
const git = (...a: string[]) => execFileSync('git', ['-C', dir, ...a], { stdio: 'ignore' });
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'opzy-hist-'));
  git('init'); git('config', 'user.email', 't@t.co'); git('config', 'user.name', 't');
});
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe('scanGitHistory', () => {
  it('finds a secret committed then removed', async () => {
    writeFileSync(join(dir, 'a.js'), `const k = "${FAKE_STRIPE_KEY}";`);
    git('add', '.'); git('commit', '-m', 'add key');
    writeFileSync(join(dir, 'a.js'), 'const k = process.env.K;');
    git('add', '.'); git('commit', '-m', 'remove key');
    const out = await scanGitHistory(dir);
    expect(out.length).toBeGreaterThanOrEqual(1);
    expect(out[0]?.category).toBe('history');
  });
  it('returns nothing for a non-git directory', async () => {
    expect(await scanGitHistory(join(tmpdir(), 'nope-' + Math.random().toString(36).slice(2)))).toEqual([]);
  });
});
