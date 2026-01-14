/**
 * Performance Configuration for Assessment Engine
 *
 * Centralizes performance-related magic numbers that were previously
 * scattered across multiple modules. Supports JSON configuration files
 * for runtime tuning via CLI flags.
 *
 * @public
 * @module assessment/performance
 * @see https://github.com/triepod-ai/inspector-assessment/issues/37
 */

import * as fs from "fs";
import type { Logger } from "../lib/logger";
import { validatePerformanceConfigWithZod } from "./performanceConfigSchemas";

/**
 * Performance configuration for assessment execution.
 * Controls batching, timeouts, concurrency, and resource limits.
 * @public
 */
export interface PerformanceConfig {
  /**
   * Interval in milliseconds between progress batch flushes.
   * Controls how often batched test results are emitted.
   * @default 500
   */
  batchFlushIntervalMs: number;

  /**
   * Batch size for functionality assessment progress events.
   * Smaller than security batch size because functionality tests are fewer.
   * @default 5
   */
  functionalityBatchSize: number;

  /**
   * Batch size for security assessment progress events.
   * @default 10
   */
  securityBatchSize: number;

  /**
   * Timeout for individual test scenario execution in milliseconds.
   * Applied via Promise.race in TestScenarioEngine.
   * @default 5000
   */
  testTimeoutMs: number;

  /**
   * Timeout for individual security payload tests in milliseconds.
   * Fallback when not specified in assessment configuration.
   * @default 5000
   */
  securityTestTimeoutMs: number;

  /**
   * Warning threshold for queue depth monitoring.
   * Triggers warning when task queue exceeds this size.
   *
   * Derivation: Advanced security assessments can legitimately queue:
   *   29 tools x 140 payloads (across 23 attack patterns) = 4,060 tasks
   *
   * Threshold of 10,000 provides ~146% headroom to accommodate larger
   * tool sets while catching true runaway scenarios.
   * @default 10000
   */
  queueWarningThreshold: number;

  /**
   * Maximum EventEmitter listeners to prevent Node.js warnings.
   * Assessment operations require more listeners than Node's default (10).
   * @default 50
   */
  eventEmitterMaxListeners: number;

  /**
   * Maximum retry attempts for transient errors in security tests.
   * Payload-level retry with exponential backoff for connection errors.
   * @default 2
   * @see https://github.com/triepod-ai/inspector-assessment/issues/157
   */
  securityRetryMaxAttempts: number;

  /**
   * Initial backoff delay in milliseconds for security test retries.
   * Uses exponential backoff: delay * 2^attempt (100ms → 200ms → 400ms)
   * @default 100
   * @see https://github.com/triepod-ai/inspector-assessment/issues/157
   */
  securityRetryBackoffMs: number;
}

/**
 * Default performance configuration.
 * These values preserve existing behavior across all modules.
 * @public
 */
export const DEFAULT_PERFORMANCE_CONFIG: Readonly<Required<PerformanceConfig>> =
  Object.freeze({
    batchFlushIntervalMs: 500,
    functionalityBatchSize: 5,
    securityBatchSize: 10,
    testTimeoutMs: 5000,
    securityTestTimeoutMs: 5000,
    queueWarningThreshold: 10000,
    eventEmitterMaxListeners: 50,
    securityRetryMaxAttempts: 2,
    securityRetryBackoffMs: 100,
  });

/**
 * Performance presets for common use cases.
 * @public
 */
export const PERFORMANCE_PRESETS = {
  /** Default configuration - balanced performance */
  default: DEFAULT_PERFORMANCE_CONFIG,

  /** Optimized for speed with larger batches */
  fast: Object.freeze({
    ...DEFAULT_PERFORMANCE_CONFIG,
    functionalityBatchSize: 10,
    securityBatchSize: 20,
  }),

  /** Conservative settings for resource-constrained environments */
  resourceConstrained: Object.freeze({
    ...DEFAULT_PERFORMANCE_CONFIG,
    functionalityBatchSize: 3,
    securityBatchSize: 5,
    queueWarningThreshold: 5000,
  }),
} as const;

/**
 * Validate a partial performance config.
 * Ensures values are within reasonable bounds.
 *
 * Uses Zod schema validation under the hood (Issue #84).
 *
 * @public
 * @param config - Partial config to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validatePerformanceConfig(
  config: Partial<PerformanceConfig>,
): string[] {
  // Delegate to Zod schema validation
  return validatePerformanceConfigWithZod(config);
}

/**
 * Merge a partial config with defaults.
 * User-provided values override defaults.
 *
 * @public
 * @param partial - Partial config to merge
 * @returns Complete config with defaults applied
 */
export function mergeWithDefaults(
  partial: Partial<PerformanceConfig>,
): Required<PerformanceConfig> {
  return {
    batchFlushIntervalMs:
      partial.batchFlushIntervalMs ??
      DEFAULT_PERFORMANCE_CONFIG.batchFlushIntervalMs,
    functionalityBatchSize:
      partial.functionalityBatchSize ??
      DEFAULT_PERFORMANCE_CONFIG.functionalityBatchSize,
    securityBatchSize:
      partial.securityBatchSize ?? DEFAULT_PERFORMANCE_CONFIG.securityBatchSize,
    testTimeoutMs:
      partial.testTimeoutMs ?? DEFAULT_PERFORMANCE_CONFIG.testTimeoutMs,
    securityTestTimeoutMs:
      partial.securityTestTimeoutMs ??
      DEFAULT_PERFORMANCE_CONFIG.securityTestTimeoutMs,
    queueWarningThreshold:
      partial.queueWarningThreshold ??
      DEFAULT_PERFORMANCE_CONFIG.queueWarningThreshold,
    eventEmitterMaxListeners:
      partial.eventEmitterMaxListeners ??
      DEFAULT_PERFORMANCE_CONFIG.eventEmitterMaxListeners,
    securityRetryMaxAttempts:
      partial.securityRetryMaxAttempts ??
      DEFAULT_PERFORMANCE_CONFIG.securityRetryMaxAttempts,
    securityRetryBackoffMs:
      partial.securityRetryBackoffMs ??
      DEFAULT_PERFORMANCE_CONFIG.securityRetryBackoffMs,
  };
}

/**
 * Load performance configuration from a JSON file.
 * Partial configs are validated and merged with defaults.
 *
 * @public
 * @param configPath - Path to JSON configuration file
 * @param logger - Optional logger for diagnostic output
 * @returns Complete configuration with defaults applied
 * @throws Error if config file has validation errors
 */
export function loadPerformanceConfig(
  configPath?: string,
  logger?: Logger,
): Required<PerformanceConfig> {
  if (!configPath) {
    return { ...DEFAULT_PERFORMANCE_CONFIG };
  }

  try {
    const configContent = fs.readFileSync(configPath, "utf-8");
    const userConfig = JSON.parse(configContent) as Partial<PerformanceConfig>;

    // Validate the config
    const errors = validatePerformanceConfig(userConfig);
    if (errors.length > 0) {
      const errorMsg = `Invalid performance config: ${errors.join(", ")}`;
      logger?.error(errorMsg, { configPath, errors });
      throw new Error(errorMsg);
    }

    logger?.debug("Loaded performance config", { configPath, userConfig });

    return mergeWithDefaults(userConfig);
  } catch (error) {
    if (error instanceof SyntaxError) {
      logger?.error("Invalid JSON in performance config file", {
        configPath,
        error: error.message,
      });
      throw new Error(`Invalid JSON in performance config: ${configPath}`);
    }

    // Re-throw validation errors
    if (error instanceof Error && error.message.includes("Invalid")) {
      throw error;
    }

    // File read errors - use defaults with warning
    logger?.warn("Could not load performance config, using defaults", {
      configPath,
      error: error instanceof Error ? error.message : String(error),
    });
    return { ...DEFAULT_PERFORMANCE_CONFIG };
  }
}
