/**
 * Timeout Utilities for Assessment Operations
 *
 * Provides AbortController-based timeout handling with proper cleanup.
 * Fixes GitHub issue #38: Promise.race patterns that leave timers hanging.
 *
 * Key improvements over basic Promise.race:
 * 1. Clears setTimeout when operation completes (prevents timer leaks)
 * 2. Uses AbortController for signal-based cancellation
 * 3. Provides consistent error messages
 */

export interface TimeoutOptions {
  /** Timeout in milliseconds */
  timeoutMs: number;
  /** Optional custom error message for timeout */
  errorMessage?: string;
}

/**
 * Execute a promise with timeout and proper cleanup.
 *
 * This function wraps any promise with a timeout, ensuring the timer
 * is always cleaned up whether the operation succeeds, fails, or times out.
 *
 * @param promise - The promise to execute
 * @param options - Timeout configuration
 * @returns The result of the promise
 * @throws Error if operation times out
 *
 * @example Basic usage
 * ```typescript
 * const result = await executeWithTimeout(
 *   callTool(tool.name, params),
 *   { timeoutMs: 5000 }
 * );
 * ```
 *
 * @example With custom error message
 * ```typescript
 * const result = await executeWithTimeout(
 *   fetchData(),
 *   { timeoutMs: 10000, errorMessage: "Data fetch timed out" }
 * );
 * ```
 */
export async function executeWithTimeout<T>(
  promise: Promise<T>,
  options: TimeoutOptions,
): Promise<T> {
  const { timeoutMs, errorMessage } = options;

  // Create abort controller for timeout signaling
  const controller = new AbortController();

  // Set up timeout that triggers abort
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  // Create timeout promise that rejects when abort signal fires
  const timeoutPromise = new Promise<never>((_, reject) => {
    controller.signal.addEventListener("abort", () => {
      reject(
        new Error(errorMessage ?? `Operation timed out after ${timeoutMs}ms`),
      );
    });
  });

  try {
    // Race the operation against timeout
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    // CRITICAL: Always clean up timer to prevent leaks
    clearTimeout(timeoutId);
  }
}

/**
 * Execute an async function with timeout and AbortSignal support.
 *
 * This variant accepts a function that receives an AbortSignal, enabling
 * cancellation of fetch requests and other abortable operations.
 *
 * @param fn - Function that accepts an AbortSignal and returns a Promise
 * @param options - Timeout configuration
 * @returns The result of the function
 * @throws Error if operation times out
 *
 * @example With fetch
 * ```typescript
 * const data = await executeWithTimeoutAndSignal(
 *   async (signal) => {
 *     const response = await fetch(url, { signal });
 *     return response.json();
 *   },
 *   { timeoutMs: 5000 }
 * );
 * ```
 */
export async function executeWithTimeoutAndSignal<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  options: TimeoutOptions,
): Promise<T> {
  const { timeoutMs, errorMessage } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort();
  }, timeoutMs);

  try {
    return await fn(controller.signal);
  } catch (error) {
    // Convert AbortError to timeout error for consistency
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(
        errorMessage ?? `Operation timed out after ${timeoutMs}ms`,
      );
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
