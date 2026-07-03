import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { analyzeBundleSecrets } from '@appsec/detectors';
import type { LocalFinding } from '../types';

const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'build', 'coverage', '.turbo', '.vercel']);
const SKIP_EXT = /\.(png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|lock|map|woff2?|ttf|mp4|mov)$/i;
const MAX_BYTES = 1_500_000;

/** Tracked + untracked-not-ignored files via git; fallback to a manual walk. */
export function listScannableFiles(root: string): string[] {
  try {
    const out = execFileSync('git', ['-C', root, 'ls-files', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    return out.split('\n').map((p) => p.trim()).filter(Boolean).map((p) => join(root, p));
  } catch {
    const acc: string[] = [];
    const walk = (d: string) => {
      for (const e of readdirSync(d, { withFileTypes: true })) {
        if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(join(d, e.name)); }
        else acc.push(join(d, e.name));
      }
    };
    walk(root);
    return acc;
  }
}

export async function scanWorkingTreeSecrets(root: string): Promise<LocalFinding[]> {
  const findings: LocalFinding[] = [];
  for (const abs of listScannableFiles(root)) {
    if (abs.split(sep).some((part) => SKIP_DIRS.has(part))) continue;
    if (SKIP_EXT.test(abs)) continue;
    let content: string;
    try {
      if (statSync(abs).size > MAX_BYTES) continue;
      content = readFileSync(abs, 'utf8');
    } catch { continue; }
    const rel = relative(root, abs) || abs;
    for (const f of analyzeBundleSecrets(content, rel)) {
      findings.push({ category: 'secret', signature: f.signature, title: f.title, severity: f.severity, location: f.location, evidence: f.evidence, remediation: f.remediation });
    }
  }
  return findings;
}
