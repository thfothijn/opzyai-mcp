import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import type { LocalFinding } from '../types';

/** True if git would ignore the path (exit 0 = ignored). */
function isGitIgnored(root: string, rel: string): boolean {
  try { execFileSync('git', ['-C', root, 'check-ignore', '-q', rel], { stdio: 'ignore' }); return true; }
  catch { return false; }
}

export async function scanDotenv(root: string): Promise<LocalFinding[]> {
  const out: LocalFinding[] = [];
  const candidates = readdirSync(root).filter((n) => /^\.env(\..+)?$/.test(n) && !/\.(example|sample)$/.test(n));
  for (const name of candidates) {
    if (isGitIgnored(root, name)) continue;
    out.push({
      category: 'dotenv',
      signature: `dotenv-exposed:${name}`,
      title: `${name} is not gitignored`,
      severity: 'high',
      location: name,
      evidence: `${name} holds secret values and is not ignored by git — it can be committed and leaked.`,
      remediation: `Add \`${name}\` to .gitignore, and if it was ever committed, remove it from history and rotate the keys it held.`,
    });
  }
  return out;
}
