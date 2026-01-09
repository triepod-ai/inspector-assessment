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
          ...(Object.fromEntries(
            Object.entries(process.env).filter(([, v]) => v !== undefined),
          ) as Record<string, string>),
          ...config.env,
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

    // Provide helpful context when connection fails
    if (stderrData.trim()) {
      throw new Error(
        `Failed to connect to MCP server: ${errorMessage}\n\n` +
          `Server stderr:\n${stderrData.trim()}\n\n` +
          `Common causes:\n` +
          `  - Missing environment variables (check .env file)\n` +
          `  - Required external services not running\n` +
          `  - Missing API credentials`,
      );
    }
    throw new Error(`Failed to connect to MCP server: ${errorMessage}`);
  }

  return client;
}
