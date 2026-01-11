/**
 * Server Configuration Loading
 *
 * Handles loading MCP server configuration from Claude Code settings.
 * Uses Zod schemas for runtime validation (Issue #84).
 *
 * @module cli/lib/assessment-runner/server-config
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import type { ServerConfig } from "../cli-parser.js";
import {
  ServerEntrySchema,
  isHttpSseConfig,
  isStdioConfig,
  type ServerEntry,
} from "./server-configSchemas.js";
import { formatZodError } from "../zodErrorFormatter.js";

/**
 * Load server configuration from Claude Code's MCP settings
 *
 * @param serverName - Name of the server to look up
 * @param configPath - Optional explicit config path
 * @returns Server configuration object
 */
export function loadServerConfig(
  serverName: string,
  configPath?: string,
): ServerConfig {
  const possiblePaths = [
    configPath,
    path.join(os.homedir(), ".config", "mcp", "servers", `${serverName}.json`),
    path.join(os.homedir(), ".config", "claude", "claude_desktop_config.json"),
  ].filter(Boolean) as string[];

  for (const tryPath of possiblePaths) {
    if (!fs.existsSync(tryPath)) continue;

    let rawConfig: unknown;
    try {
      rawConfig = JSON.parse(fs.readFileSync(tryPath, "utf-8"));
    } catch (e) {
      throw new Error(
        `Invalid JSON in config file: ${tryPath}\n${e instanceof Error ? e.message : String(e)}`,
      );
    }

    // Determine which config entry to validate
    let serverEntry: unknown;
    let configSource: string;

    // Check for Claude Desktop format (mcpServers object)
    if (
      typeof rawConfig === "object" &&
      rawConfig !== null &&
      "mcpServers" in rawConfig &&
      typeof (rawConfig as Record<string, unknown>).mcpServers === "object"
    ) {
      const mcpServers = (rawConfig as { mcpServers: Record<string, unknown> })
        .mcpServers;
      if (mcpServers && serverName in mcpServers) {
        serverEntry = mcpServers[serverName];
        configSource = `${tryPath} (mcpServers.${serverName})`;
      } else {
        continue; // Server not in this file, try next path
      }
    } else {
      // Standalone config format
      serverEntry = rawConfig;
      configSource = tryPath;
    }

    // Validate server entry with Zod schema
    const validationResult = ServerEntrySchema.safeParse(serverEntry);
    if (!validationResult.success) {
      throw new Error(
        `Invalid server config in ${configSource}:\n${formatZodError(validationResult.error)}`,
      );
    }

    const validatedEntry: ServerEntry = validationResult.data;

    // Convert to ServerConfig using type guards
    if (isHttpSseConfig(validatedEntry)) {
      return {
        transport: validatedEntry.transport || "http",
        url: validatedEntry.url,
      };
    }

    if (isStdioConfig(validatedEntry)) {
      return {
        transport: "stdio",
        command: validatedEntry.command,
        args: validatedEntry.args || [],
        env: validatedEntry.env || {},
        cwd: validatedEntry.cwd,
      };
    }

    // This should never happen due to schema validation, but TypeScript needs it
    throw new Error(
      `Unable to determine transport type for config: ${configSource}`,
    );
  }

  throw new Error(
    `Server config not found for: ${serverName}\nTried: ${possiblePaths.join(", ")}`,
  );
}
