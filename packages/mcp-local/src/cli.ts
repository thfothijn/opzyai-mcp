import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { version } from '../package.json';
import { runSecurityCheck } from './scan';
import { formatReport } from './report';

/** Single source of truth for what this MCP server reports to clients — version tracks package.json. */
export const SERVER_INFO = { name: 'opzyai', version } as const;

/** Build the MCP server with the security_check tool registered. Exported for tests. */
export function createServer(): McpServer {
  const server = new McpServer(SERVER_INFO);
  server.registerTool(
    'security_check',
    {
      title: 'Security check (local)',
      description:
        'Run a local security check on the project in this workspace: finds hardcoded API keys, committed/exposed .env files, secrets in git history, and known-vulnerable dependencies. Runs entirely on this machine. Use when asked to do a security check, audit, or "is this safe to ship".',
      inputSchema: {
        path: z.string().optional().describe('Project root to scan; defaults to the current working directory'),
        offline: z.boolean().optional().describe('Skip the OSV dependency check so nothing leaves the machine'),
      },
    },
    async ({ path, offline }) => {
      const report = await runSecurityCheck({ root: path ?? process.cwd(), offline });
      return { content: [{ type: 'text' as const, text: formatReport(report) }] };
    },
  );
  return server;
}

async function main(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Run only when invoked as the binary (not when imported by tests).
if (process.argv[1] && /cli\.(ts|js)$/.test(process.argv[1])) {
  main().catch((e) => { console.error(e); process.exit(1); });
}
