import type { Severity } from '@appsec/core';

export interface LocalFinding {
  category: 'secret' | 'dotenv' | 'history' | 'dependency';
  signature: string;
  title: string;
  severity: Severity;
  location: string;
  evidence: string;
  remediation: string;
}

export interface LocalScanReport {
  score: number;
  findings: LocalFinding[];
  ranBy: { secrets: boolean; dotenv: boolean; history: boolean; deps: boolean | 'offline' };
}

const WEIGHT: Record<Severity, number> = { critical: 45, high: 20, medium: 8, low: 3, info: 0 };

/**
 * Dependency advisories are capped as a group so a pile of (often dev-only,
 * transitive) CVEs can't alone tank the score to 0 — a leaked secret is
 * catastrophic, a stack of build-tool advisories is not. Secrets / exposed
 * .env / git-history leaks stay uncapped.
 */
const DEP_PENALTY_CAP = 35;

/** 0–100 launch-readiness score. Dangerous categories uncapped; dependency CVEs capped as a group. */
export function scoreFor(findings: LocalFinding[]): number {
  let core = 0;
  let dep = 0;
  for (const f of findings) {
    const w = WEIGHT[f.severity] ?? 0;
    if (f.category === 'dependency') dep += w;
    else core += w;
  }
  const penalty = core + Math.min(dep, DEP_PENALTY_CAP);
  return Math.max(0, Math.min(100, 100 - penalty));
}
