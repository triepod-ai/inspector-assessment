/**
 * Zod Schemas for Performance Configuration
 *
 * Runtime validation schemas for performance configuration.
 * Replaces manual validatePerformanceConfig() function with declarative schemas.
 *
 * @module assessment/config/performanceConfigSchemas
 * @see performanceConfig.ts for the interface definitions
 */

import { z } from "zod";

/**
 * Schema for performance configuration fields.
 * All fields are optional since partial configs are merged with defaults.
 *
 * Validation ranges match existing validatePerformanceConfig() logic:
 * - batchFlushIntervalMs: 50-10000
 * - functionalityBatchSize: 1-100
 * - securityBatchSize: 1-100
 * - testTimeoutMs: 100-300000
 * - securityTestTimeoutMs: 100-300000
 * - queueWarningThreshold: 100-1000000
 * - eventEmitterMaxListeners: 10-1000
 */
export const PerformanceConfigSchema = z.object({
  /**
   * Interval in milliseconds between progress batch flushes.
   */
  batchFlushIntervalMs: z
    .number()
    .int("batchFlushIntervalMs must be an integer")
    .min(50, "batchFlushIntervalMs must be >= 50")
    .max(10000, "batchFlushIntervalMs must be <= 10000")
    .optional(),

  /**
   * Batch size for functionality assessment progress events.
   */
  functionalityBatchSize: z
    .number()
    .int("functionalityBatchSize must be an integer")
    .min(1, "functionalityBatchSize must be >= 1")
    .max(100, "functionalityBatchSize must be <= 100")
    .optional(),

  /**
   * Batch size for security assessment progress events.
   */
  securityBatchSize: z
    .number()
    .int("securityBatchSize must be an integer")
    .min(1, "securityBatchSize must be >= 1")
    .max(100, "securityBatchSize must be <= 100")
    .optional(),

  /**
   * Timeout for individual test scenario execution in milliseconds.
   */
  testTimeoutMs: z
    .number()
    .int("testTimeoutMs must be an integer")
    .min(100, "testTimeoutMs must be >= 100")
    .max(300000, "testTimeoutMs must be <= 300000")
    .optional(),

  /**
   * Timeout for individual security payload tests in milliseconds.
   */
  securityTestTimeoutMs: z
    .number()
    .int("securityTestTimeoutMs must be an integer")
    .min(100, "securityTestTimeoutMs must be >= 100")
    .max(300000, "securityTestTimeoutMs must be <= 300000")
    .optional(),

  /**
   * Warning threshold for queue depth monitoring.
   */
  queueWarningThreshold: z
    .number()
    .int("queueWarningThreshold must be an integer")
    .min(100, "queueWarningThreshold must be >= 100")
    .max(1000000, "queueWarningThreshold must be <= 1000000")
    .optional(),

  /**
   * Maximum EventEmitter listeners to prevent Node.js warnings.
   */
  eventEmitterMaxListeners: z
    .number()
    .int("eventEmitterMaxListeners must be an integer")
    .min(10, "eventEmitterMaxListeners must be >= 10")
    .max(1000, "eventEmitterMaxListeners must be <= 1000")
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
