/**
 * Timeout Utilities Test Suite
 *
 * Tests for AbortController-based timeout handling with proper cleanup.
 * Validates fix for GitHub issue #38.
 */

import {
  executeWithTimeout,
  executeWithTimeoutAndSignal,
} from "../lib/timeoutUtils";

describe("timeoutUtils", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("executeWithTimeout", () => {
    it("should resolve when operation completes before timeout", async () => {
      const result = await executeWithTimeout(Promise.resolve("success"), {
        timeoutMs: 1000,
      });

      expect(result).toBe("success");
    });

    it("should handle async operations that complete before timeout", async () => {
      const asyncOp = new Promise<string>((resolve) => {
        setTimeout(() => resolve("async success"), 10);
      });

      const result = await executeWithTimeout(asyncOp, { timeoutMs: 1000 });

      expect(result).toBe("async success");
    });

    it("should reject with timeout error when operation exceeds timeout", async () => {
      const slowOperation = new Promise<string>((resolve) => {
        setTimeout(() => resolve("too late"), 100);
      });

      await expect(
        executeWithTimeout(slowOperation, { timeoutMs: 10 }),
      ).rejects.toThrow("Operation timed out after 10ms");
    });

    it("should use custom error message when provided", async () => {
      const slowOperation = new Promise<string>((resolve) => {
        setTimeout(() => resolve("too late"), 100);
      });

      await expect(
        executeWithTimeout(slowOperation, {
          timeoutMs: 10,
          errorMessage: "Custom timeout message",
        }),
      ).rejects.toThrow("Custom timeout message");
    });

    it("should clear timeout when operation completes successfully", async () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      await executeWithTimeout(Promise.resolve("fast"), { timeoutMs: 10000 });

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it("should clear timeout even when operation fails", async () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      await expect(
        executeWithTimeout(Promise.reject(new Error("operation error")), {
          timeoutMs: 10000,
        }),
      ).rejects.toThrow("operation error");

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it("should clear timeout when operation times out", async () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      const slowOperation = new Promise<string>((resolve) => {
        setTimeout(() => resolve("too late"), 100);
      });

      await expect(
        executeWithTimeout(slowOperation, { timeoutMs: 10 }),
      ).rejects.toThrow();

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it("should propagate original error when operation fails before timeout", async () => {
      const error = new Error("specific error message");

      await expect(
        executeWithTimeout(Promise.reject(error), { timeoutMs: 1000 }),
      ).rejects.toThrow("specific error message");
    });

    it("should handle operations returning different types", async () => {
      // Number
      const numberResult = await executeWithTimeout(Promise.resolve(42), {
        timeoutMs: 1000,
      });
      expect(numberResult).toBe(42);

      // Object
      const objResult = await executeWithTimeout(
        Promise.resolve({ key: "value" }),
        { timeoutMs: 1000 },
      );
      expect(objResult).toEqual({ key: "value" });

      // Array
      const arrResult = await executeWithTimeout(Promise.resolve([1, 2, 3]), {
        timeoutMs: 1000,
      });
      expect(arrResult).toEqual([1, 2, 3]);

      // Null
      const nullResult = await executeWithTimeout(Promise.resolve(null), {
        timeoutMs: 1000,
      });
      expect(nullResult).toBeNull();
    });

    it("should handle very short timeouts correctly", async () => {
      const instantOperation = Promise.resolve("instant");

      // This should succeed because the promise is already resolved
      const result = await executeWithTimeout(instantOperation, {
        timeoutMs: 1,
      });
      expect(result).toBe("instant");
    });
  });

  describe("executeWithTimeoutAndSignal", () => {
    it("should pass AbortSignal to function", async () => {
      let receivedSignal: AbortSignal | undefined;

      await executeWithTimeoutAndSignal(
        async (signal) => {
          receivedSignal = signal;
          return "done";
        },
        { timeoutMs: 1000 },
      );

      expect(receivedSignal).toBeDefined();
      expect(receivedSignal?.aborted).toBe(false);
    });

    it("should resolve when function completes before timeout", async () => {
      const result = await executeWithTimeoutAndSignal(
        async () => {
          return "success";
        },
        { timeoutMs: 1000 },
      );

      expect(result).toBe("success");
    });

    it("should abort signal on timeout", async () => {
      let signalAborted = false;

      try {
        await executeWithTimeoutAndSignal(
          async (signal) => {
            signal.addEventListener(
              "abort",
              () => {
                signalAborted = true;
              },
              { once: true },
            );
            await new Promise((resolve) => setTimeout(resolve, 100));
            return "too late";
          },
          { timeoutMs: 10 },
        );
      } catch {
        // Expected timeout
      }

      expect(signalAborted).toBe(true);
    });

    it("should convert AbortError to timeout error", async () => {
      await expect(
        executeWithTimeoutAndSignal(
          async (signal) => {
            // Simulate fetch-like behavior that throws AbortError
            await new Promise<never>((_, reject) => {
              signal.addEventListener(
                "abort",
                () => {
                  const error = new Error("Aborted");
                  error.name = "AbortError";
                  reject(error);
                },
                { once: true },
              );
            });
          },
          { timeoutMs: 10 },
        ),
      ).rejects.toThrow("Operation timed out after 10ms");
    });

    it("should use custom error message when AbortError is thrown", async () => {
      await expect(
        executeWithTimeoutAndSignal(
          async (signal) => {
            await new Promise<never>((_, reject) => {
              signal.addEventListener(
                "abort",
                () => {
                  const error = new Error("Aborted");
                  error.name = "AbortError";
                  reject(error);
                },
                { once: true },
              );
            });
          },
          { timeoutMs: 10, errorMessage: "Custom abort message" },
        ),
      ).rejects.toThrow("Custom abort message");
    });

    it("should propagate non-abort errors unchanged", async () => {
      const customError = new Error("custom error");

      await expect(
        executeWithTimeoutAndSignal(
          async () => {
            throw customError;
          },
          { timeoutMs: 1000 },
        ),
      ).rejects.toThrow("custom error");
    });

    it("should clear timeout after function completes", async () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      await executeWithTimeoutAndSignal(async () => "done", {
        timeoutMs: 10000,
      });

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it("should clear timeout even when function throws", async () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      await expect(
        executeWithTimeoutAndSignal(
          async () => {
            throw new Error("failure");
          },
          { timeoutMs: 10000 },
        ),
      ).rejects.toThrow("failure");

      expect(clearTimeoutSpy).toHaveBeenCalled();
      clearTimeoutSpy.mockRestore();
    });

    it("should work with async functions that use the signal", async () => {
      const result = await executeWithTimeoutAndSignal(
        async (signal) => {
          // Simulate a cancellable operation
          if (signal.aborted) {
            throw new Error("Already aborted");
          }
          return "completed";
        },
        { timeoutMs: 1000 },
      );

      expect(result).toBe("completed");
    });
  });

  describe("timer cleanup verification", () => {
    it("should not accumulate timers when called many times", async () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      // Run many operations
      const operations = Array.from({ length: 100 }, (_, i) =>
        executeWithTimeout(Promise.resolve(i), { timeoutMs: 1000 }),
      );

      await Promise.all(operations);

      // Should have cleared a timer for each operation
      expect(clearTimeoutSpy).toHaveBeenCalledTimes(100);
      clearTimeoutSpy.mockRestore();
    });

    it("should clean up timer for each operation in sequence", async () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      for (let i = 0; i < 10; i++) {
        await executeWithTimeout(Promise.resolve(i), { timeoutMs: 1000 });
      }

      expect(clearTimeoutSpy).toHaveBeenCalledTimes(10);
      clearTimeoutSpy.mockRestore();
    });
  });
});
