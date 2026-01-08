/**
 * Simple concurrency limiter for parallel async operations
 * Provides the same interface as p-limit but is CJS-compatible
 */

import { Logger } from "./logger";
import { DEFAULT_PERFORMANCE_CONFIG } from "../config/performanceConfig";

/**
 * Warning threshold for queue depth monitoring.
 * If queue exceeds this size, a warning is emitted to help diagnose
 * slow/stalled servers or runaway task accumulation.
 *
 * Derivation: Advanced security assessments can legitimately queue:
 *   29 tools × 140 payloads (across 23 attack patterns) = 4,060 tasks
 *
 * Threshold of 10,000 provides ~146% headroom to accommodate larger
 * tool sets while catching true runaway scenarios.
 *
 * @see PerformanceConfig.queueWarningThreshold (Issue #37)
 */
export const QUEUE_WARNING_THRESHOLD =
  DEFAULT_PERFORMANCE_CONFIG.queueWarningThreshold;

export type LimitFunction = <T>(fn: () => Promise<T>) => Promise<T>;

/**
 * Creates a concurrency limiter that allows only a specified number
 * of async operations to run simultaneously
 *
 * @param concurrency - Maximum number of concurrent operations
 * @param logger - Optional logger instance for queue depth warnings
 * @returns A function that wraps async operations with the concurrency limit
 *
 * @example
 * const limit = createConcurrencyLimit(5);
 * const results = await Promise.all(
 *   items.map(item => limit(() => processItem(item)))
 * );
 */
export function createConcurrencyLimit(
  concurrency: number,
  logger?: Logger,
): LimitFunction {
  if (concurrency < 1) {
    throw new Error("Concurrency must be at least 1");
  }

  let activeCount = 0;
  let hasWarned = false;
  const queue: Array<{
    fn: () => Promise<unknown>;
    resolve: (value: unknown) => void;
    reject: (error: unknown) => void;
  }> = [];

  const next = () => {
    if (activeCount < concurrency && queue.length > 0) {
      const { fn, resolve, reject } = queue.shift()!;
      activeCount++;

      fn()
        .then((result) => {
          activeCount--;
          resolve(result);
          next();
        })
        .catch((error) => {
          activeCount--;
          reject(error);
          next();
        });
    }
  };

  return <T>(fn: () => Promise<T>): Promise<T> => {
    return new Promise<T>((resolve, reject) => {
      queue.push({
        fn: fn as () => Promise<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
      });

      // Emit warning if queue grows too large (potential slow/stalled server)
      // Only warn once per limiter instance to avoid log spam
      if (queue.length > QUEUE_WARNING_THRESHOLD && !hasWarned) {
        hasWarned = true;
        logger?.warn("Queue depth exceeded threshold", {
          queueDepth: queue.length,
          threshold: QUEUE_WARNING_THRESHOLD,
          activeCount,
          concurrency,
          message: "This may indicate a slow/stalled server",
        });
      }

      next();
    });
  };
}
