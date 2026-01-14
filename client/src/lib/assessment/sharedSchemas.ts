/**
 * Shared Zod Schemas - Single Source of Truth
 *
 * Consolidates common schemas used across CLI and client.
 * Import from here to avoid duplication (DRY principle).
 *
 * @public
 * @module assessment/sharedSchemas
 * @see https://github.com/triepod-ai/inspector-assessment/issues/114
 */

import { z } from "zod";

// ============================================================================
// Schema Versioning
// ============================================================================

/**
 * Schema version for Zod schemas.
 * Increment when schema structure changes to enable migration handling.
 *
 * @remarks
 * Follows the pattern established in moduleScoring.ts for SCHEMA_VERSION.
 * Consumers can check this version to detect schema changes.
 */
export const ZOD_SCHEMA_VERSION = 1;

// ============================================================================
// Shared Enum Schemas
// ============================================================================

/**
 * Schema for log level values.
 * Used by both CLI argument parsing and assessment configuration.
 */
export const LogLevelSchema = z.enum([
  "silent",
  "error",
  "warn",
  "info",
  "debug",
]);

/**
 * Inferred log level type.
 */
export type LogLevel = z.infer<typeof LogLevelSchema>;

/**
 * Schema for transport type values.
 * Used by server configuration validation.
 */
export const TransportTypeSchema = z.enum(["stdio", "http", "sse"]);

/**
 * Inferred transport type.
 */
export type TransportType = z.infer<typeof TransportTypeSchema>;

/**
 * Schema for report output formats.
 * Used by CLI report generation.
 */
export const ReportFormatSchema = z.enum(["json", "markdown"]);

/**
 * Inferred report format type.
 */
export type ReportFormat = z.infer<typeof ReportFormatSchema>;

/**
 * Schema for tiered output format.
 * Issue #136: Tiered output strategy for large assessments
 *
 * - "full": Complete JSON output (default, existing behavior)
 * - "tiered": Directory structure with executive summary, tool summaries, per-tool details
 * - "summary-only": Only executive summary and tool summaries (no per-tool detail files)
 */
export const OutputFormatSchema = z.enum(["full", "tiered", "summary-only"]);

/**
 * Inferred output format type.
 */
export type OutputFormat = z.infer<typeof OutputFormatSchema>;

// ============================================================================
// Validation Range Constants
// ============================================================================

/**
 * Performance configuration validation ranges.
 * Centralizes min/max values for performance-related settings.
 *
 * @remarks
 * These constants are used by performanceConfigSchemas.ts to define
 * validation constraints. Centralizing them here enables:
 * - Consistent validation across the codebase
 * - Easy adjustment of limits without hunting through schema definitions
 * - Documentation of valid ranges in a single location
 */
export const PERF_CONFIG_RANGES = {
  /** Interval between progress batch flushes (ms) */
  batchFlushIntervalMs: { min: 50, max: 10000 },
  /** Batch size for functionality assessment progress events */
  functionalityBatchSize: { min: 1, max: 100 },
  /** Batch size for security assessment progress events */
  securityBatchSize: { min: 1, max: 100 },
  /** Timeout for individual test scenario execution (ms) */
  testTimeoutMs: { min: 100, max: 300000 },
  /** Timeout for individual security payload tests (ms) */
  securityTestTimeoutMs: { min: 100, max: 300000 },
  /** Warning threshold for queue depth monitoring */
  queueWarningThreshold: { min: 100, max: 1000000 },
  /** Maximum EventEmitter listeners to prevent Node.js warnings */
  eventEmitterMaxListeners: { min: 10, max: 1000 },
  /** Maximum retry attempts for transient errors in security tests (Issue #157) */
  securityRetryMaxAttempts: { min: 0, max: 10 },
  /** Initial backoff delay in ms for security test retries (Issue #157) */
  securityRetryBackoffMs: { min: 10, max: 5000 },
} as const;

/**
 * Type for performance configuration range keys.
 */
export type PerfConfigRangeKey = keyof typeof PERF_CONFIG_RANGES;

/**
 * Timeout-related validation ranges.
 * Used across various configuration schemas for timeout validation.
 */
export const TIMEOUT_RANGES = {
  /** General test timeout (ms) */
  testTimeout: { min: 100, max: 300000 },
  /** Security test timeout (ms) */
  securityTestTimeout: { min: 100, max: 300000 },
  /** Connection establishment timeout (ms) */
  connectionTimeout: { min: 1000, max: 60000 },
} as const;

/**
 * Type for timeout range keys.
 */
export type TimeoutRangeKey = keyof typeof TIMEOUT_RANGES;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Get the valid values for LogLevelSchema as an array.
 * Useful for CLI help text and documentation.
 */
export function getLogLevelValues(): readonly string[] {
  return LogLevelSchema.options;
}

/**
 * Get the valid values for TransportTypeSchema as an array.
 * Useful for CLI help text and documentation.
 */
export function getTransportTypeValues(): readonly string[] {
  return TransportTypeSchema.options;
}

/**
 * Get the valid values for ReportFormatSchema as an array.
 * Useful for CLI help text and documentation.
 */
export function getReportFormatValues(): readonly string[] {
  return ReportFormatSchema.options;
}
