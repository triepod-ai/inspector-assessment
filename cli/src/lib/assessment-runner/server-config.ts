/**
 * Server Configuration Loading
 *
 * Handles loading MCP server configuration from Claude Code settings.
 *
 * @module cli/lib/assessment-runner/server-config
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import type { ServerConfig } from "../cli-parser.js";

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

    const config = JSON.parse(fs.readFileSync(tryPath, "utf-8"));

    if (config.mcpServers && config.mcpServers[serverName]) {
      const serverConfig = config.mcpServers[serverName];

      // Check if serverConfig specifies http/sse transport
      if (
        serverConfig.url ||
        serverConfig.transport === "http" ||
        serverConfig.transport === "sse"
      ) {
        if (!serverConfig.url) {
          throw new Error(
            `Invalid server config: transport is '${serverConfig.transport}' but 'url' is missing`,
          );
        }
        return {
          transport: serverConfig.transport || "http",
          url: serverConfig.url,
        };
      }

      // Default to stdio transport
      return {
        transport: "stdio",
        command: serverConfig.command,
        args: serverConfig.args || [],
        env: serverConfig.env || {},
        cwd: serverConfig.cwd,
      };
    }

    if (
      config.url ||
      config.transport === "http" ||
      config.transport === "sse"
    ) {
      if (!config.url) {
        throw new Error(
          `Invalid server config: transport is '${config.transport}' but 'url' is missing`,
        );
      }
      return {
        transport: config.transport || "http",
        url: config.url,
      };
    }

    if (config.command) {
      return {
        transport: "stdio",
        command: config.command,
        args: config.args || [],
        env: config.env || {},
      };
    }
  }

  throw new Error(
    `Server config not found for: ${serverName}\nTried: ${possiblePaths.join(", ")}`,
  );
}
