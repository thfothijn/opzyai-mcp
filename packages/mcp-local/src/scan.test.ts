import { describe, it, expect, vi } from 'vitest';

vi.mock('./detectors/secrets', () => ({ scanWorkingTreeSecrets: vi.fn(async () => [{ category: 'secret', signature: 'leaked-secret:stripe-secret', title: 'Exposed Stripe secret key in client code', severity: 'critical', location: 'app.ts', evidence: 'redacted', remediation: 'rotate it' }]) }));
vi.mock('./detectors/dotenv', () => ({ scanDotenv: vi.fn(async () => []) }));
vi.mock('./detectors/git-history', () => ({ scanGitHistory: vi.fn(async () => []) }));
vi.mock('./detectors/deps', () => ({ scanDependencies: vi.fn(async () => []) }));

describe('runSecurityCheck', () => {
  it('aggregates findings and scores them', async () => {
    const { runSecurityCheck } = await import('./scan');
    const report = await runSecurityCheck({ root: '/tmp/x' });
    expect(report.findings).toHaveLength(1);
    expect(report.score).toBe(55);
    expect(report.ranBy.deps).toBe(true);
  });
  it('marks deps offline when offline', async () => {
    const { runSecurityCheck } = await import('./scan');
    const report = await runSecurityCheck({ root: '/tmp/x', offline: true });
    expect(report.ranBy.deps).toBe('offline');
  });
});

describe('formatReport', () => {
  it('includes score, a fix, and the OSV disclosure', async () => {
    const { runSecurityCheck } = await import('./scan');
    const { formatReport } = await import('./report');
    const text = formatReport(await runSecurityCheck({ root: '/tmp/x' }));
    expect(text).toContain('Launch Readiness: 55/100');
    expect(text).toContain('Fix:');
    expect(text).toMatch(/OSV/i);
  });
});
