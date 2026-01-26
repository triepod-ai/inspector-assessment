import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { findActualExecutable } from "spawn-rx";

export type TransportOptions = {
  transportType: "sse" | "stdio" | "http";
  command?: string;
  args?: string[];
  url?: string;
  headers?: Record<string, string>;
};

/**
 * Returns minimal environment variables for spawned MCP servers.
 * Using a curated set prevents unintended behavior from inherited env vars.
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

function createStdioTransport(options: TransportOptions): Transport {
  let args: string[] = [];

  if (options.args !== undefined) {
    args = options.args;
  }

  // Use minimal env + SDK defaults instead of full process.env
  const defaultEnv = getDefaultEnvironment();

  const env: Record<string, string> = {
    ...defaultEnv,
    ...getMinimalEnv(),
  };

  const { cmd: actualCommand, args: actualArgs } = findActualExecutable(
    options.command ?? "",
    args,
  );

  return new StdioClientTransport({
    command: actualCommand,
    args: actualArgs,
    env,
    stderr: "pipe",
  });
}

export function createTransport(options: TransportOptions): Transport {
  const { transportType } = options;

  try {
    if (transportType === "stdio") {
      return createStdioTransport(options);
    }

    // If not STDIO, then it must be either SSE or HTTP.
    if (!options.url) {
      throw new Error("URL must be provided for SSE or HTTP transport types.");
    }
    const url = new URL(options.url);

    if (transportType === "sse") {
      const transportOptions = options.headers
        ? {
            requestInit: {
              headers: options.headers,
            },
          }
        : undefined;
      return new SSEClientTransport(url, transportOptions);
    }

    if (transportType === "http") {
      const transportOptions = options.headers
        ? {
            requestInit: {
              headers: options.headers,
            },
          }
        : undefined;
      return new StreamableHTTPClientTransport(url, transportOptions);
    }

    throw new Error(`Unsupported transport type: ${transportType}`);
  } catch (error) {
    throw new Error(
      `Failed to create transport: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
