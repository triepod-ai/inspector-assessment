/**
 * Simple concurrency limiter for parallel async operations
 * Provides the same interface as p-limit but is CJS-compatible
 */

/**
 * Warning threshold for queue depth monitoring.
 * If queue exceeds this size, a warning is emitted to help diagnose
 * slow/stalled servers or runaway task accumulation.
 *
 * Set to 10000 to avoid false alarms on legitimate advanced security
 * assessments which can queue ~3,475 tasks (29 tools × 20 patterns × 6 payloads).
 */
export const QUEUE_WARNING_THRESHOLD = 10000;

export type LimitFunction = <T>(fn: () => Promise<T>) => Promise<T>;

/**
 * Creates a concurrency limiter that allows only a specified number
 * of async operations to run simultaneously
 *
 * @param concurrency - Maximum number of concurrent operations
 * @returns A function that wraps async operations with the concurrency limit
 *
 * @example
 * const limit = createConcurrencyLimit(5);
 * const results = await Promise.all(
 *   items.map(item => limit(() => processItem(item)))
 * );
 */
export function createConcurrencyLimit(concurrency: number): LimitFunction {
  if (concurrency < 1) {
    throw new Error("Concurrency must be at least 1");
  }

  let activeCount = 0;
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
      if (queue.length > QUEUE_WARNING_THRESHOLD) {
        console.warn(
          `[concurrencyLimit] Queue depth: ${queue.length} ` +
            `(threshold: ${QUEUE_WARNING_THRESHOLD}). ` +
            `This may indicate a slow/stalled server.`,
        );
      }

      next();
    });
  };
}
