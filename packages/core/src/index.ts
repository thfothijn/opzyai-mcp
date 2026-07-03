/**
 * Trimmed shim of the monorepo's `@appsec/core` — only the shared types the
 * local scanner needs. The full package (server-side scan orchestration,
 * remediation planning, billing) lives in the private Opzyai monorepo; the
 * scanner published from this repo is byte-identical to the one there.
 */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
