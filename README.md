# Opzyai MCP — local security check for AI coding agents

[![CI](https://github.com/thfothijn/opzyai-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/thfothijn/opzyai-mcp/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/%40opzyai%2Fmcp)](https://www.npmjs.com/package/@opzyai/mcp)
[![license](https://img.shields.io/badge/license-MIT-teal)](./LICENSE)

Source for [`@opzyai/mcp`](https://www.npmjs.com/package/@opzyai/mcp) — an
[MCP](https://modelcontextprotocol.io) server that scans the project in your workspace for
the mistakes that ship secrets and vulnerabilities to production, **entirely on your
machine**. Ask your agent *"is this safe to ship?"* and get a Launch Readiness score with
a fix for every finding.

Built by [Opzyai](https://www.opzyai.com?utm_source=github) — security for apps built with
AI tools like Cursor, Lovable, v0 and Bolt.

## Install

```bash
# Claude Code
claude mcp add opzyai -- npx -y @opzyai/mcp
```

```json
// Cursor / generic MCP client
{
  "mcpServers": {
    "opzyai": { "command": "npx", "args": ["-y", "@opzyai/mcp"] }
  }
}
```

## What it checks

One tool — `security_check({ path?, offline? })` — runs four detectors:

| Detector | Catches |
|----------|---------|
| Working-tree secrets | API keys/tokens hardcoded in source (OpenAI, Anthropic, Stripe, Supabase service-role, AWS, GitHub, …) |
| `.env` exposure | env files committed or not gitignored |
| Git-history secrets | credentials committed once and "removed" — still recoverable from history |
| Dependency CVEs | known-vulnerable packages via [OSV](https://osv.dev) (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) |

Detection is precision-first: an explicit allowlist keeps intentionally-public values
(Stripe `pk_*`, Supabase anon keys) from ever being flagged.

## Privacy

Everything runs locally over stdio. The only network call is the OSV dependency check —
**package names + versions only, never your code** — and `offline: true` disables even
that.

## Repository layout

This is the public source mirror of the local scanner; it is developed inside the private
Opzyai monorepo and synced here on each release, byte-identical.

```
packages/
  mcp-local/   @opzyai/mcp — the MCP server published to npm
  detectors/   @appsec/detectors — shared secret-detection patterns + allowlist
  core/        @appsec/core — trimmed shim (shared types only; the full package is server-side)
```

## Develop

```bash
pnpm install
pnpm typecheck && pnpm test   # vitest, all packages
pnpm build                    # tsup → packages/mcp-local/dist/cli.js
```

Requires Node >= 20 and `git` on PATH (for the git-history detector's tests).

## Related

- **Free URL scan (no account):** paste your deployed URL at
  [opzyai.com/scan](https://www.opzyai.com/scan?utm_source=github) — passive check for
  leaked client-bundle keys, exposed `.env`/`.git`/source maps, missing headers.
- **Hosted Pro MCP:** deep scans of repos you own (dependency CVEs, SAST, git-history
  secrets) plus `propose_fix` — the exact change for your agent to apply:
  [opzyai.com/mcp](https://www.opzyai.com/mcp?utm_source=github).

## License

MIT © Opzyai
