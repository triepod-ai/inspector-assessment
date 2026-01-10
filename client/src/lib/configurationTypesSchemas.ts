/**
 * Zod Schemas for Inspector Configuration Types
 *
 * Runtime validation for configuration loaded from localStorage/sessionStorage.
 * Replaces unsafe type casts in configUtils.ts with validated parsing.
 *
 * @module lib/configurationTypesSchemas
 * @see configurationTypes.ts - Type definitions
 * @see utils/configUtils.ts - Configuration loading utilities
 */

import { z } from "zod";
import { ZOD_SCHEMA_VERSION } from "./assessment/sharedSchemas";

// Re-export schema version for consumers
export { ZOD_SCHEMA_VERSION };

// ============================================================================
// ConfigItem Schema
// ============================================================================

/**
 * Schema for a single configuration item.
 * Validates the structure used for each config entry.
 */
export const ConfigItemSchema = z.object({
  label: z.string().min(1, "label is required"),
  description: z.string(),
  value: z.union([z.string(), z.number(), z.boolean()]),
  is_session_item: z.boolean(),
});

/**
 * Inferred type from ConfigItemSchema.
 */
export type ConfigItemParsed = z.infer<typeof ConfigItemSchema>;

// ============================================================================
// InspectorConfig Schema
// ============================================================================

/**
 * Schema for the complete Inspector configuration.
 * Matches the InspectorConfig interface from configurationTypes.ts.
 */
export const InspectorConfigSchema = z.object({
  MCP_SERVER_REQUEST_TIMEOUT: ConfigItemSchema,
  MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS: ConfigItemSchema,
  MCP_REQUEST_MAX_TOTAL_TIMEOUT: ConfigItemSchema,
  MCP_PROXY_FULL_ADDRESS: ConfigItemSchema,
  MCP_PROXY_AUTH_TOKEN: ConfigItemSchema,
});

/**
 * Inferred type from InspectorConfigSchema.
 */
export type InspectorConfigParsed = z.infer<typeof InspectorConfigSchema>;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validate inspector configuration and return error messages.
 *
 * @param config - Configuration object to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateInspectorConfig(config: unknown): string[] {
  const result = InspectorConfigSchema.safeParse(config);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Parse inspector configuration with validation.
 *
 * @param config - Raw configuration object
 * @returns Validated configuration
 * @throws ZodError if validation fails
 */
export function parseInspectorConfig(config: unknown): InspectorConfigParsed {
  return InspectorConfigSchema.parse(config);
}

/**
 * Safely parse inspector configuration without throwing.
 *
 * @param config - Raw configuration object
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseInspectorConfig(config: unknown) {
  return InspectorConfigSchema.safeParse(config);
}

/**
 * Validate a single config item.
 *
 * @param item - Config item to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateConfigItem(item: unknown): string[] {
  const result = ConfigItemSchema.safeParse(item);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Safely parse a single config item without throwing.
 *
 * @param item - Raw config item object
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseConfigItem(item: unknown) {
  return ConfigItemSchema.safeParse(item);
}
