import type { Severity } from '@appsec/core';

export interface DetectorFinding {
  signature: string;
  title: string;
  severity: Severity;
  cvss: number;
  location: string;
  evidence: string;
  remediation: string;
}

const CVSS_FOR: Record<Severity, number> = { info: 0, low: 3.1, medium: 5.3, high: 7.5, critical: 9.5 };

interface SecretRule {
  id: string;
  name: string;
  regex: RegExp;
  severity: Severity;
  why: string;
  fix: string;
}

/** Credentials that must NEVER appear in client-side code. */
const SECRET_RULES: SecretRule[] = [
  { id: 'openai', name: 'OpenAI API key', regex: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, severity: 'critical',
    why: 'Anyone who opens your site in a browser can copy this key and run up your OpenAI bill.',
    fix: 'Move the key to a server-side environment variable and call OpenAI from an API route — never the browser. Then rotate the key.' },
  { id: 'anthropic', name: 'Anthropic API key', regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, severity: 'critical',
    why: 'This key lets anyone make Claude API calls on your account.',
    fix: 'Keep it server-side only and call Anthropic from an API route. Then rotate the key.' },
  { id: 'stripe-secret', name: 'Stripe secret key', regex: /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/g, severity: 'critical',
    why: 'This key can charge cards and read your full Stripe account.',
    fix: 'Remove it from the browser, use it only on the server, and roll it now in the Stripe dashboard.' },
  { id: 'aws', name: 'AWS access key id', regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'critical',
    why: 'AWS keys in the browser can be used to access your cloud account.',
    fix: 'Remove from the client and rotate in IAM immediately. Use server-side credentials only.' },
  { id: 'github', name: 'GitHub token', regex: /\b(?:ghp|gho|ghs)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, severity: 'critical',
    why: 'A GitHub token in the browser can read or push to your repositories.',
    fix: 'Revoke it in GitHub → Settings → Developer settings, and never ship it to the client.' },
  { id: 'google', name: 'Google API key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: 'medium',
    why: 'Google browser keys are only safe if restricted; an unrestricted key can be abused on your bill.',
    fix: 'Restrict this key to your domain and specific APIs in the Google Cloud console.' },
];

/**
 * Patterns/contexts that are MEANT to be public — never flagged.
 * Defense-in-depth: guards publishable keys should a broader rule ever match them;
 * today the secret regexes are specific enough that publishable keys aren't matched.
 */
const PUBLISHABLE_ALLOW: RegExp[] = [
  /\bpk_(?:live|test)_[A-Za-z0-9]+/, // Stripe publishable
];

function redact(s: string): string {
  return s.length <= 10 ? '••••' : `${s.slice(0, 6)}…${s.slice(-4)}`;
}

/** Decode a JWT's payload and return its `role` claim, or null. */
function jwtRole(jwt: string): string | null {
  try {
    const payload = jwt.split('.')[1];
    if (!payload) return null;
    const json = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    return typeof json?.role === 'string' ? json.role : null;
  } catch {
    return null;
  }
}

function finding(id: string, name: string, severity: Severity, source: string, why: string, fix: string, sample: string): DetectorFinding {
  return {
    signature: `leaked-secret:${id}`,
    title: `Exposed ${name} in client code`,
    severity,
    cvss: CVSS_FOR[severity],
    location: source,
    evidence: `Found ${name} (${redact(sample)}) in ${source}. ${why}`,
    remediation: fix,
  };
}

/** Scan one chunk of client-served text (a JS bundle or HTML) for leaked credentials. */
export function analyzeBundleSecrets(text: string, source: string): DetectorFinding[] {
  const out: DetectorFinding[] = [];
  const seen = new Set<string>();

  for (const rule of SECRET_RULES) {
    for (const m of text.matchAll(rule.regex)) {
      const val = m[0];
      if (PUBLISHABLE_ALLOW.some((a) => a.test(val))) continue;
      const key = `${rule.id}:${val.slice(0, 12)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(finding(rule.id, rule.name, rule.severity, source, rule.why, rule.fix, val));
    }
  }

  // Supabase service_role JWT — decoded by role claim. anon/authenticated are public-safe.
  for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g)) {
    if (jwtRole(m[0]) !== 'service_role') continue;
    const key = `supabase-service-role:${m[0].slice(0, 16)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(finding(
      'supabase-service-role', 'Supabase service_role key', 'critical', source,
      'This key bypasses all Row-Level Security — anyone can read and write your entire database.',
      'Use the anon (public) key in the browser; keep service_role on the server only. Then rotate keys in Supabase → Settings → API.',
      m[0],
    ));
  }

  return out;
}
