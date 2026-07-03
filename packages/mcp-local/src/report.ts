import type { LocalScanReport } from './types';

const ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function formatReport(r: LocalScanReport): string {
  const verdict = r.score >= 80 ? 'looking solid' : r.score >= 50 ? 'needs attention before shipping' : 'not safe to ship yet';
  const sorted = [...r.findings].sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9));
  const body = sorted.length
    ? `Findings (${sorted.length}), most severe first:\n\n` +
      sorted.map((f) => `[${f.severity.toUpperCase()}] ${f.title}\n  Where: ${f.location}\n  Why:   ${f.evidence}\n  Fix:   ${f.remediation}`).join('\n\n')
    : 'No secrets, exposed .env, history leaks or known-vulnerable dependencies found — nice.';
  const depsNote = r.ranBy.deps === 'offline'
    ? 'Dependency check skipped (offline mode).'
    : 'Dependency check used OSV.dev — only package names + versions were sent, never your code.';
  return `Launch Readiness: ${r.score}/100 — ${verdict}.\n\n${body}\n\n${depsNote}\nRan entirely on your machine. For a hosted scan of your live URL, see https://www.opzyai.com.`;
}
