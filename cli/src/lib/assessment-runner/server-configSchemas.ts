/**
 * Zod Schemas for Server Configuration Files
 *
 * Runtime validation for MCP server configuration loaded from JSON files.
 * Supports both Claude Desktop config format and standalone config format.
 *
 * @module cli/lib/assessment-runner/server-configSchemas
 */

import { z } from "zod";

/**
 * Transport type for MCP connections.
 */
export const TransportTypeSchema = z.enum(["stdio", "http", "sse"]);

/**
 * Schema for HTTP/SSE transport server configuration.
 */
export const HttpSseServerConfigSchema = z.object({
  transport: z.enum(["http", "sse"]).optional(),
  url: z.string().url("url must be a valid URL"),
});

/**
 * Schema for stdio transport server configuration.
 */
export const StdioServerConfigSchema = z.object({
  transport: z.literal("stdio").optional(),
  command: z.string().min(1, "command is required for stdio transport"),
  args: z.array(z.string()).optional().default([]),
  env: z.record(z.string()).optional().default({}),
  cwd: z.string().optional(),
});

/**
 * Schema for a single server entry (either transport type).
 * Used within mcpServers object or as standalone config.
 */
export const ServerEntrySchema = z.union([
  HttpSseServerConfigSchema,
  StdioServerConfigSchema,
]);

/**
 * Schema for Claude Desktop config format.
 * Contains nested mcpServers object with server configurations.
 */
export const ClaudeDesktopConfigSchema = z.object({
  mcpServers: z.record(ServerEntrySchema).optional(),
});

/**
 * Schema for standalone config file format.
 * Direct server configuration without nesting.
 */
export const StandaloneConfigSchema = ServerEntrySchema;

/**
 * Combined schema for any valid config file format.
 */
export const ConfigFileSchema = z.union([
  ClaudeDesktopConfigSchema,
  StandaloneConfigSchema,
]);

/**
 * Type for HTTP/SSE server config.
 */
export type HttpSseServerConfig = z.infer<typeof HttpSseServerConfigSchema>;

/**
 * Type for stdio server config.
 */
export type StdioServerConfig = z.infer<typeof StdioServerConfigSchema>;

/**
 * Type for any server entry.
 */
export type ServerEntry = z.infer<typeof ServerEntrySchema>;

/**
 * Type for Claude Desktop config format.
 */
export type ClaudeDesktopConfig = z.infer<typeof ClaudeDesktopConfigSchema>;

/**
 * Type for standalone config format.
 */
export type StandaloneConfig = z.infer<typeof StandaloneConfigSchema>;

/**
 * Parse a config file's JSON content and validate its structure.
 *
 * @param jsonContent - Raw JSON object from file
 * @returns Validated config file content
 * @throws ZodError if validation fails
 */
export function parseConfigFile(jsonContent: unknown) {
  return ConfigFileSchema.parse(jsonContent);
}

/**
 * Safely parse a config file without throwing.
 *
 * @param jsonContent - Raw JSON object from file
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseConfigFile(jsonContent: unknown) {
  return ConfigFileSchema.safeParse(jsonContent);
}

/**
 * Validate a server entry matches expected structure.
 *
 * @param entry - Server configuration entry
 * @returns Array of validation error messages (empty if valid)
 */
export function validateServerEntry(entry: unknown): string[] {
  const result = ServerEntrySchema.safeParse(entry);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Check if a server entry is HTTP/SSE transport.
 */
export function isHttpSseConfig(
  entry: ServerEntry,
): entry is HttpSseServerConfig {
  return (
    "url" in entry || entry.transport === "http" || entry.transport === "sse"
  );
}

/**
 * Check if a server entry is stdio transport.
 */
export function isStdioConfig(entry: ServerEntry): entry is StdioServerConfig {
  return "command" in entry && !("url" in entry);
}
