/**
 * Server Connection
 *
 * Handles MCP server connection via HTTP, SSE, or stdio transport.
 *
 * @module cli/lib/assessment-runner/server-connection
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import type { ServerConfig } from "../cli-parser.js";

/**
 * Returns minimal environment variables for spawned MCP servers.
 * Using a curated set prevents unintended behavior from inherited env vars
 * (e.g., native module loading triggered by unexpected env conditions).
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/211
 */
function getMinimalEnv(): Record<string, string> {
  const minimal: Record<string, string> = {};

  // Essential system paths
  if (process.env.PATH) minimal.PATH = process.env.PATH;
  if (process.env.HOME) minimal.HOME = process.env.HOME;
  if (process.env.TMPDIR) minimal.TMPDIR = process.env.TMPDIR;
  if (process.env.TMP) minimal.TMP = process.env.TMP;
  if (process.env.TEMP) minimal.TEMP = process.env.TEMP;

  // Node.js environment
  minimal.NODE_ENV = process.env.NODE_ENV || "production";

  // Platform-specific essentials
  if (process.env.USER) minimal.USER = process.env.USER;
  if (process.env.SHELL) minimal.SHELL = process.env.SHELL;
  if (process.env.LANG) minimal.LANG = process.env.LANG;

  return minimal;
}

/**
 * Connect to MCP server via configured transport
 *
 * @param config - Server configuration
 * @returns Connected MCP client
 */
export async function connectToServer(config: ServerConfig): Promise<Client> {
  let transport;
  let stderrData = ""; // Capture stderr for error reporting

  switch (config.transport) {
    case "http":
      if (!config.url) throw new Error("URL required for HTTP transport");
      transport = new StreamableHTTPClientTransport(new URL(config.url));
      break;

    case "sse":
      if (!config.url) throw new Error("URL required for SSE transport");
      transport = new SSEClientTransport(new URL(config.url));
      break;

    case "stdio":
    default:
      if (!config.command)
        throw new Error("Command required for stdio transport");
      transport = new StdioClientTransport({
        command: config.command,
        args: config.args,
        env: {
          ...getMinimalEnv(),
          ...config.env, // Explicit config overrides take priority
        },
        cwd: config.cwd,
        stderr: "pipe",
      });

      // Capture stderr BEFORE connecting - critical for error context
      // The MCP SDK creates a PassThrough stream immediately when stderr: "pipe"
      // is set, allowing us to attach listeners before start() is called
      const stderrStream = (transport as StdioClientTransport).stderr;
      if (stderrStream) {
        stderrStream.on("data", (data: Buffer) => {
          stderrData += data.toString();
        });
      }
      break;
  }

  const client = new Client(
    {
      name: "mcp-assess-full",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  try {
    await client.connect(transport);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    // Issue #212: Detect SIGKILL (exit code 137) which may indicate Gatekeeper blocking
    const isSigkill =
      errorMessage.includes("exit code 137") ||
      errorMessage.includes("SIGKILL") ||
      errorMessage.toLowerCase().includes("killed");

    // Provide helpful context when connection fails
    let contextualHelp = `Failed to connect to MCP server: ${errorMessage}\n\n`;

    if (stderrData.trim()) {
      contextualHelp += `Server stderr:\n${stderrData.trim()}\n\n`;
    }

    contextualHelp += `Common causes:\n`;
    contextualHelp += `  - Missing environment variables (check .env file)\n`;
    contextualHelp += `  - Required external services not running\n`;
    contextualHelp += `  - Missing API credentials\n`;

    // Issue #212: Add native module specific help for SIGKILL/timeout
    if (isSigkill) {
      contextualHelp += `\n\u{1F534} Exit code 137 (SIGKILL) detected - possible causes:\n`;
      contextualHelp += `  - macOS Gatekeeper blocked unsigned native binaries\n`;
      contextualHelp += `  - Native module (canvas, sharp, better-sqlite3) killed by security policy\n`;
      contextualHelp += `  - Out of memory during native module initialization\n`;
      contextualHelp += `\nSuggested actions:\n`;
      contextualHelp += `  - Check pre-flight warnings above for detected native modules\n`;
      contextualHelp += `  - Try: xattr -d com.apple.quarantine /path/to/binary\n`;
      contextualHelp += `  - Open System Preferences > Security & Privacy to allow blocked apps\n`;
      contextualHelp += `  - Consider pure JavaScript alternatives (e.g., jimp instead of sharp)\n`;
    }

    throw new Error(contextualHelp);
  }

  return client;
}
