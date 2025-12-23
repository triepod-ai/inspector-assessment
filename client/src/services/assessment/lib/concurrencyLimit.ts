/**
 * Simple concurrency limiter for parallel async operations
 * Provides the same interface as p-limit but is CJS-compatible
 */

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
      next();
    });
  };
}
