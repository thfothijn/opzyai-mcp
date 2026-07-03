import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Severity } from '@appsec/core';
import type { LocalFinding } from '../types';

export interface LockedPackage {
  name: string;
  version: string;
}

function dedupe(pkgs: LockedPackage[]): LockedPackage[] {
  const seen = new Set<string>();
  return pkgs.filter((p) => {
    const k = `${p.name}@${p.version}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** npm: extract name+version from the package-lock.json `packages` map. */
export function parsePackageLock(text: string): LockedPackage[] {
  try {
    const json = JSON.parse(text) as { packages?: Record<string, { version?: string }> };
    const out: LockedPackage[] = [];
    for (const [path, meta] of Object.entries(json.packages ?? {})) {
      const idx = path.lastIndexOf('node_modules/');
      if (idx === -1 || !meta.version) continue;
      out.push({ name: path.slice(idx + 'node_modules/'.length), version: meta.version });
    }
    return dedupe(out);
  } catch {
    return [];
  }
}

/** pnpm: the lockfile is YAML, but package keys encode `name@version`; extract them without a YAML parser. */
export function parsePnpmLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  // Matches keys like `  /lodash@4.17.20:`, `  /@babel/core@7.20.0(peer):`, or unslashed `  lodash@4.17.20:`.
  const re = /^\s{2,}'?\/?((?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)@(\d[a-z0-9.+-]*)/gim;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[1] && m[2]) out.push({ name: m[1], version: m[2] });
  }
  return dedupe(out);
}

/** yarn: `"name@range":` (or comma-joined) header followed by a `version "x.y.z"` line. */
export function parseYarnLock(text: string): LockedPackage[] {
  const out: LockedPackage[] = [];
  const lines = text.split('\n');
  let pending: string | null = null;
  for (const line of lines) {
    const header = line.match(/^"?((?:@[^@\s,"]+\/)?[^@\s,"]+)@/);
    if (header && line.trimEnd().endsWith(':')) {
      pending = header[1] ?? null;
      continue;
    }
    const ver = line.match(/^\s+version:?\s+"?([^"\s]+)"?/);
    if (ver && pending && ver[1]) {
      out.push({ name: pending, version: ver[1] });
      pending = null;
    }
  }
  return dedupe(out);
}

/** Read whichever lockfile exists (npm → pnpm → yarn) and return its packages. */
export function parseLockfile(root: string): LockedPackage[] {
  const npm = join(root, 'package-lock.json');
  if (existsSync(npm)) return safeRead(npm, parsePackageLock);
  const pnpm = join(root, 'pnpm-lock.yaml');
  if (existsSync(pnpm)) return safeRead(pnpm, parsePnpmLock);
  const yarn = join(root, 'yarn.lock');
  if (existsSync(yarn)) return safeRead(yarn, parseYarnLock);
  return [];
}

function safeRead(file: string, parse: (text: string) => LockedPackage[]): LockedPackage[] {
  try {
    return parse(readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: { type?: string; score?: string }[];
  database_specific?: { severity?: string };
}

/** GHSA-style label → our buckets. */
function bucketFromLabel(label: string): Severity | null {
  const l = label.toUpperCase();
  if (l.includes('CRITICAL')) return 'critical';
  if (l.includes('HIGH')) return 'high';
  if (l.includes('MODERATE') || l.includes('MEDIUM')) return 'medium';
  if (l.includes('LOW')) return 'low';
  return null;
}

/** Heuristic from a CVSS:3.x vector when no labelled severity is present. */
function bucketFromCvss(vector: string | undefined): Severity {
  if (!vector) return 'medium';
  const high = /\/C:H/.test(vector) || /\/I:H/.test(vector) || /\/A:H/.test(vector);
  return high ? 'high' : 'low';
}

/** Resolve a real severity for a vuln: prefer the advisory's labelled severity, fall back to CVSS, else medium. */
export function severityFromVuln(v: OsvVuln): { severity: Severity; summary: string } {
  const labelled = v.database_specific?.severity ? bucketFromLabel(String(v.database_specific.severity)) : null;
  const cvssVector = v.severity?.find((s) => s.type?.startsWith('CVSS'))?.score;
  const severity = labelled ?? (cvssVector ? bucketFromCvss(cvssVector) : 'medium');
  const summary = v.summary || v.details?.split('\n')[0] || '';
  return { severity, summary };
}

// Bound detail lookups on pathological dependency trees.
const SEVERITY_FETCH_CAP = 200;

async function fetchVulnDetail(id: string, doFetch: typeof fetch): Promise<OsvVuln | null> {
  try {
    const res = await doFetch(`https://api.osv.dev/v1/vulns/${id}`);
    if (!res.ok) return null;
    return (await res.json()) as OsvVuln;
  } catch {
    return null;
  }
}

export async function scanDependencies(root: string, opts: { fetchFn?: typeof fetch } = {}): Promise<LocalFinding[]> {
  const pkgs = parseLockfile(root);
  if (pkgs.length === 0) return [];
  const doFetch = opts.fetchFn ?? fetch;

  // 1. Batch-query OSV for which packages have advisories (only coordinates are sent — never source).
  const queries = pkgs.map((p) => ({ package: { ecosystem: 'npm', name: p.name }, version: p.version }));
  let results: { vulns?: { id: string }[] }[] = [];
  try {
    const res = await doFetch('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries }),
    });
    if (!res.ok) return [];
    results = ((await res.json()) as { results?: typeof results }).results ?? [];
  } catch {
    return [];
  }

  // 2. Collect (package, vuln-id) pairs.
  const pairs: { pkg: LockedPackage; id: string }[] = [];
  results.forEach((r, i) => {
    const pkg = pkgs[i];
    if (!pkg || !r.vulns?.length) return;
    for (const v of r.vulns) pairs.push({ pkg, id: v.id });
  });
  if (pairs.length === 0) return [];

  // 3. Look up real severity per unique advisory (querybatch omits it — that's why it was all "medium").
  const uniqueIds = [...new Set(pairs.map((p) => p.id))].slice(0, SEVERITY_FETCH_CAP);
  const details = new Map<string, OsvVuln>();
  await Promise.all(
    uniqueIds.map(async (id) => {
      const d = await fetchVulnDetail(id, doFetch);
      if (d) details.set(id, d);
    }),
  );

  // 4. Build findings with the resolved severity.
  return pairs.map(({ pkg, id }) => {
    const detail = details.get(id);
    const { severity, summary } = detail ? severityFromVuln(detail) : { severity: 'medium' as Severity, summary: '' };
    return {
      category: 'dependency',
      signature: `dep-cve:${pkg.name}:${id}`,
      title: `Vulnerable dependency: ${pkg.name}@${pkg.version}`,
      severity,
      location: `${pkg.name}@${pkg.version} (lockfile)`,
      evidence: `${id}${summary ? ` — ${summary}` : ''} affects ${pkg.name}@${pkg.version}.`,
      remediation: `Upgrade ${pkg.name} to a patched version (see https://osv.dev/vulnerability/${id}).`,
    };
  });
}
