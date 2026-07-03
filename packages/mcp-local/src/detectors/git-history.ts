import { execFileSync } from 'node:child_process';
import { analyzeBundleSecrets } from '@appsec/detectors';
import type { LocalFinding } from '../types';

/** Scan added lines across recent history for committed secrets. Bounded for speed. */
export async function scanGitHistory(root: string, opts: { maxCommits?: number } = {}): Promise<LocalFinding[]> {
  const max = opts.maxCommits ?? 200;
  let diff: string;
  try {
    diff = execFileSync('git', ['-C', root, 'log', '-p', '--all', '--no-color', `-n`, String(max), '--', '.'], { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 });
  } catch {
    return []; // not a git repo, or git unavailable
  }
  // Collect added lines only (start with '+' but not the '+++' file header).
  const added = diff.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).map((l) => l.slice(1)).join('\n');
  const seen = new Set<string>();
  const out: LocalFinding[] = [];
  for (const f of analyzeBundleSecrets(added, 'git history')) {
    if (seen.has(f.signature)) continue;
    seen.add(f.signature);
    out.push({
      category: 'history',
      signature: `history-${f.signature}`,
      title: f.title.replace('in client code', 'in git history'),
      severity: f.severity,
      location: 'git history',
      evidence: `${f.evidence} It appears in a past commit even if removed from the current code.`,
      remediation: `${f.remediation} A secret in git history is still exposed — rotate it and consider rewriting history (e.g. git filter-repo).`,
    });
  }
  return out;
}
