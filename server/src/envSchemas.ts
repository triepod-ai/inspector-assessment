/**
 * Zod Schemas for Server Environment Variables
 *
 * Runtime validation and type coercion for environment variables.
 * Provides type-safe access to server configuration.
 *
 * @module server/envSchemas
 */

import { z } from "zod";

/**
 * Schema for server environment variables.
 * Handles string-to-type coercion for process.env values.
 */
export const ServerEnvSchema = z.object({
  /**
   * JSON string of additional environment variables to pass to MCP servers.
   * Parsed into an object at runtime.
   */
  MCP_ENV_VARS: z
    .string()
    .optional()
    .transform((val) => {
      if (!val) return {};
      try {
        return JSON.parse(val) as Record<string, string>;
      } catch {
        return {};
      }
    }),

  /**
   * Authentication token for MCP proxy.
   * If not provided, a random token is generated at startup.
   */
  MCP_PROXY_AUTH_TOKEN: z.string().optional(),

  /**
   * Disable authentication (dangerous, for development only).
   * Truthy string values enable this flag.
   */
  DANGEROUSLY_OMIT_AUTH: z
    .string()
    .optional()
    .transform((val) => val === "true" || val === "1"),

  /**
   * Port for the client web application.
   * Used to construct default allowed origins.
   * @default "6274"
   */
  CLIENT_PORT: z
    .string()
    .optional()
    .default("6274")
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive()),

  /**
   * Comma-separated list of allowed origins for CORS.
   * If not set, defaults to localhost with CLIENT_PORT.
   */
  ALLOWED_ORIGINS: z
    .string()
    .optional()
    .transform((val) =>
      val ? val.split(",").map((s) => s.trim()) : undefined,
    ),

  /**
   * Port for the MCP proxy server.
   * @default "6277"
   */
  SERVER_PORT: z
    .string()
    .optional()
    .default("6277")
    .transform((val) => parseInt(val, 10))
    .pipe(z.number().int().positive()),

  /**
   * Hostname for the server to listen on.
   * @default "localhost"
   */
  HOST: z.string().optional().default("localhost"),

  /**
   * Node environment mode.
   * Affects behavior like logging and error handling.
   */
  NODE_ENV: z.enum(["development", "test", "production"]).optional(),
});

/**
 * Type inferred from the server environment schema.
 */
export type ServerEnv = z.infer<typeof ServerEnvSchema>;

/**
 * Parse and validate server environment variables.
 * Returns validated and coerced environment configuration.
 *
 * @returns Validated server environment
 * @throws ZodError if validation fails
 */
export function parseServerEnv(): ServerEnv {
  return ServerEnvSchema.parse(process.env);
}

/**
 * Safely parse server environment without throwing.
 *
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseServerEnv() {
  return ServerEnvSchema.safeParse(process.env);
}

/**
 * Get a specific environment value with defaults.
 * Useful for accessing individual values without full parsing.
 */
export const envDefaults = {
  clientPort: 6274,
  serverPort: 6277,
  host: "localhost",
} as const;
