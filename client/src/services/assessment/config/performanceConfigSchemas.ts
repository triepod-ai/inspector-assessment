/**
 * Zod Schemas for Performance Configuration
 *
 * Runtime validation schemas for performance configuration.
 * Replaces manual validatePerformanceConfig() function with declarative schemas.
 *
 * @module assessment/config/performanceConfigSchemas
 * @see performanceConfig.ts for the interface definitions
 * @see sharedSchemas.ts for PERF_CONFIG_RANGES constants
 */

import { z } from "zod";

// Import validation range constants from single source of truth
import { PERF_CONFIG_RANGES } from "../../../lib/assessment/sharedSchemas";

// Re-export for consumers who need the range constants
export { PERF_CONFIG_RANGES };

/**
 * Schema for performance configuration fields.
 * All fields are optional since partial configs are merged with defaults.
 *
 * Validation ranges are defined in PERF_CONFIG_RANGES (sharedSchemas.ts).
 */
export const PerformanceConfigSchema = z.object({
  /**
   * Interval in milliseconds between progress batch flushes.
   */
  batchFlushIntervalMs: z
    .number()
    .int("batchFlushIntervalMs must be an integer")
    .min(
      PERF_CONFIG_RANGES.batchFlushIntervalMs.min,
      `batchFlushIntervalMs must be >= ${PERF_CONFIG_RANGES.batchFlushIntervalMs.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.batchFlushIntervalMs.max,
      `batchFlushIntervalMs must be <= ${PERF_CONFIG_RANGES.batchFlushIntervalMs.max}`,
    )
    .optional(),

  /**
   * Batch size for functionality assessment progress events.
   */
  functionalityBatchSize: z
    .number()
    .int("functionalityBatchSize must be an integer")
    .min(
      PERF_CONFIG_RANGES.functionalityBatchSize.min,
      `functionalityBatchSize must be >= ${PERF_CONFIG_RANGES.functionalityBatchSize.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.functionalityBatchSize.max,
      `functionalityBatchSize must be <= ${PERF_CONFIG_RANGES.functionalityBatchSize.max}`,
    )
    .optional(),

  /**
   * Batch size for security assessment progress events.
   */
  securityBatchSize: z
    .number()
    .int("securityBatchSize must be an integer")
    .min(
      PERF_CONFIG_RANGES.securityBatchSize.min,
      `securityBatchSize must be >= ${PERF_CONFIG_RANGES.securityBatchSize.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.securityBatchSize.max,
      `securityBatchSize must be <= ${PERF_CONFIG_RANGES.securityBatchSize.max}`,
    )
    .optional(),

  /**
   * Timeout for individual test scenario execution in milliseconds.
   */
  testTimeoutMs: z
    .number()
    .int("testTimeoutMs must be an integer")
    .min(
      PERF_CONFIG_RANGES.testTimeoutMs.min,
      `testTimeoutMs must be >= ${PERF_CONFIG_RANGES.testTimeoutMs.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.testTimeoutMs.max,
      `testTimeoutMs must be <= ${PERF_CONFIG_RANGES.testTimeoutMs.max}`,
    )
    .optional(),

  /**
   * Timeout for individual security payload tests in milliseconds.
   */
  securityTestTimeoutMs: z
    .number()
    .int("securityTestTimeoutMs must be an integer")
    .min(
      PERF_CONFIG_RANGES.securityTestTimeoutMs.min,
      `securityTestTimeoutMs must be >= ${PERF_CONFIG_RANGES.securityTestTimeoutMs.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.securityTestTimeoutMs.max,
      `securityTestTimeoutMs must be <= ${PERF_CONFIG_RANGES.securityTestTimeoutMs.max}`,
    )
    .optional(),

  /**
   * Warning threshold for queue depth monitoring.
   */
  queueWarningThreshold: z
    .number()
    .int("queueWarningThreshold must be an integer")
    .min(
      PERF_CONFIG_RANGES.queueWarningThreshold.min,
      `queueWarningThreshold must be >= ${PERF_CONFIG_RANGES.queueWarningThreshold.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.queueWarningThreshold.max,
      `queueWarningThreshold must be <= ${PERF_CONFIG_RANGES.queueWarningThreshold.max}`,
    )
    .optional(),

  /**
   * Maximum EventEmitter listeners to prevent Node.js warnings.
   */
  eventEmitterMaxListeners: z
    .number()
    .int("eventEmitterMaxListeners must be an integer")
    .min(
      PERF_CONFIG_RANGES.eventEmitterMaxListeners.min,
      `eventEmitterMaxListeners must be >= ${PERF_CONFIG_RANGES.eventEmitterMaxListeners.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.eventEmitterMaxListeners.max,
      `eventEmitterMaxListeners must be <= ${PERF_CONFIG_RANGES.eventEmitterMaxListeners.max}`,
    )
    .optional(),

  /**
   * Maximum retry attempts for transient errors in security tests.
   * Issue #157: Connection retry logic for reliability
   */
  securityRetryMaxAttempts: z
    .number()
    .int("securityRetryMaxAttempts must be an integer")
    .min(
      PERF_CONFIG_RANGES.securityRetryMaxAttempts.min,
      `securityRetryMaxAttempts must be >= ${PERF_CONFIG_RANGES.securityRetryMaxAttempts.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.securityRetryMaxAttempts.max,
      `securityRetryMaxAttempts must be <= ${PERF_CONFIG_RANGES.securityRetryMaxAttempts.max}`,
    )
    .optional(),

  /**
   * Initial backoff delay in milliseconds for security test retries.
   * Issue #157: Connection retry logic for reliability
   */
  securityRetryBackoffMs: z
    .number()
    .int("securityRetryBackoffMs must be an integer")
    .min(
      PERF_CONFIG_RANGES.securityRetryBackoffMs.min,
      `securityRetryBackoffMs must be >= ${PERF_CONFIG_RANGES.securityRetryBackoffMs.min}`,
    )
    .max(
      PERF_CONFIG_RANGES.securityRetryBackoffMs.max,
      `securityRetryBackoffMs must be <= ${PERF_CONFIG_RANGES.securityRetryBackoffMs.max}`,
    )
    .optional(),
});

/**
 * Type inferred from the schema.
 * Equivalent to Partial<PerformanceConfig> from performanceConfig.ts
 */
export type PartialPerformanceConfig = z.infer<typeof PerformanceConfigSchema>;

/**
 * Validate a partial performance config using Zod.
 * Drop-in replacement for the manual validatePerformanceConfig() function.
 *
 * @param config - Partial config to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validatePerformanceConfigWithZod(config: unknown): string[] {
  const result = PerformanceConfigSchema.safeParse(config);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Parse and validate a performance config, returning the validated data.
 * Throws ZodError if validation fails.
 *
 * @param config - Config to parse and validate
 * @returns Validated partial config
 * @throws ZodError if validation fails
 */
export function parsePerformanceConfig(
  config: unknown,
): PartialPerformanceConfig {
  return PerformanceConfigSchema.parse(config);
}

/**
 * Safely parse a performance config without throwing.
 *
 * @param config - Config to parse and validate
 * @returns SafeParseResult with success status and data/error
 */
export function safeParsePerformanceConfig(config: unknown) {
  return PerformanceConfigSchema.safeParse(config);
}
