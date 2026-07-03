# @opzyai/mcp

[![npm](https://img.shields.io/npm/v/%40opzyai%2Fmcp)](https://www.npmjs.com/package/@opzyai/mcp)
[![license](https://img.shields.io/badge/license-MIT-teal)](./LICENSE)

**A local-first security check for AI coding agents.** An [MCP](https://modelcontextprotocol.io)
server that scans the project in your workspace for the mistakes that ship secrets and
vulnerabilities to production — and runs **entirely on your machine**.

Ask your agent _"is this safe to ship?"_ and get a Launch Readiness score with a fix for
every finding.

Built by [Opzyai](https://www.opzyai.com?utm_source=npm). For deep, server-side scanning of
repositories you own (SAST, dependency CVEs, git-history secrets) and fixes your AI editor
applies for you, see [the hosted Pro server](https://www.opzyai.com/mcp?utm_source=npm).

## What it checks

The single `security_check` tool runs four detectors over your project:

- **Hardcoded secrets** — API keys, tokens and credentials in your working tree
  (OpenAI, Anthropic, Stripe, Supabase service-role, AWS, GitHub and more).
- **Exposed `.env` files** — env files that are committed or not gitignored.
- **Secrets in git history** — credentials that were committed and later "removed" (but are
  still in the history).
- **Vulnerable dependencies** — known-vulnerable packages, checked against [OSV](https://osv.dev)
  (`package-lock.json`, `pnpm-lock.yaml` and `yarn.lock` supported).

## Example output

```
Launch Readiness: 35/100 — not safe to ship yet.

Findings (2), most severe first:

[CRITICAL] Stripe live secret key in source
  Where: src/lib/billing.ts:12
  Why:   sk_live_… assigned to a constant that ships to production
  Fix:   Move it to an environment variable and rotate the key in the Stripe dashboard.

[HIGH] .env is not gitignored
  Where: .env
  Why:   the file with your real credentials can be committed by any `git add .`
  Fix:   Add `.env` to .gitignore and rotate anything already committed.

Dependency check used OSV.dev — only package names + versions were sent, never your code.
Ran entirely on your machine.
```

## Privacy

Everything runs locally over stdio. The only network call is the dependency check (OSV),
which sends **package names + versions only — never your code**. Pass `offline: true` to
skip it so nothing leaves your machine at all.

## Install

No global install needed — run it on demand with `npx`.

### Claude Code

```bash
claude mcp add opzyai -- npx -y @opzyai/mcp
```

### Cursor / generic MCP client

```json
{
  "mcpServers": {
    "opzyai": {
      "command": "npx",
      "args": ["-y", "@opzyai/mcp"]
    }
  }
}
```

Then ask your agent: _"run a security check on this project"_ or _"is this safe to ship?"_

## Tool reference

### `security_check`

| Input     | Type      | Description                                                          |
| --------- | --------- | -------------------------------------------------------------------- |
| `path`    | `string?` | Project root to scan. Defaults to the current working directory.     |
| `offline` | `boolean?`| Skip the OSV dependency check so nothing leaves the machine.         |

## Free URL scan

Not sure what your **deployed** app exposes? Run the free, no-account
[Vibe Check](https://www.opzyai.com/scan?utm_source=npm) — paste your URL, get a 0–100
Launch Readiness score in ~15 seconds (leaked keys in the client bundle, exposed `.env` /
`.git` / source maps, missing headers).

## Requirements

- Node.js >= 20
- `git` on PATH (for the git-history check)

## License

MIT © Opzyai
