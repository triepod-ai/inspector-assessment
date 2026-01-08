/**
 * Performance Configuration for Assessment Engine
 *
 * Centralizes performance-related magic numbers that were previously
 * scattered across multiple modules. Supports JSON configuration files
 * for runtime tuning via CLI flags.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/37
 */

import * as fs from "fs";
import type { Logger } from "../lib/logger";

/**
 * Performance configuration for assessment execution.
 * Controls batching, timeouts, concurrency, and resource limits.
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
}

/**
 * Default performance configuration.
 * These values preserve existing behavior across all modules.
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
  });

/**
 * Performance presets for common use cases.
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
 * @param config - Partial config to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validatePerformanceConfig(
  config: Partial<PerformanceConfig>,
): string[] {
  const errors: string[] = [];

  if (
    config.batchFlushIntervalMs !== undefined &&
    (config.batchFlushIntervalMs < 50 || config.batchFlushIntervalMs > 10000)
  ) {
    errors.push("batchFlushIntervalMs must be between 50 and 10000");
  }

  if (
    config.functionalityBatchSize !== undefined &&
    (config.functionalityBatchSize < 1 || config.functionalityBatchSize > 100)
  ) {
    errors.push("functionalityBatchSize must be between 1 and 100");
  }

  if (
    config.securityBatchSize !== undefined &&
    (config.securityBatchSize < 1 || config.securityBatchSize > 100)
  ) {
    errors.push("securityBatchSize must be between 1 and 100");
  }

  if (
    config.testTimeoutMs !== undefined &&
    (config.testTimeoutMs < 100 || config.testTimeoutMs > 300000)
  ) {
    errors.push("testTimeoutMs must be between 100 and 300000");
  }

  if (
    config.securityTestTimeoutMs !== undefined &&
    (config.securityTestTimeoutMs < 100 ||
      config.securityTestTimeoutMs > 300000)
  ) {
    errors.push("securityTestTimeoutMs must be between 100 and 300000");
  }

  if (
    config.queueWarningThreshold !== undefined &&
    (config.queueWarningThreshold < 100 ||
      config.queueWarningThreshold > 1000000)
  ) {
    errors.push("queueWarningThreshold must be between 100 and 1000000");
  }

  if (
    config.eventEmitterMaxListeners !== undefined &&
    (config.eventEmitterMaxListeners < 10 ||
      config.eventEmitterMaxListeners > 1000)
  ) {
    errors.push("eventEmitterMaxListeners must be between 10 and 1000");
  }

  return errors;
}

/**
 * Merge a partial config with defaults.
 * User-provided values override defaults.
 *
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
  };
}

/**
 * Load performance configuration from a JSON file.
 * Partial configs are validated and merged with defaults.
 *
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
