/**
 * Event Configuration Utility Unit Tests
 *
 * Tests for the ScopedListenerConfig class and related utilities
 * that replace global EventEmitter modification.
 *
 * @see GitHub Issue #33
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import { EventEmitter } from "events";
import {
  LISTENER_BUDGETS,
  calculateMaxListeners,
  ScopedListenerConfig,
  getListenerCount,
  getProcessListenerCount,
} from "../lib/event-config.js";

describe("event-config", () => {
  // Store original values to restore after each test
  let originalDefaultMaxListeners: number;
  let originalProcessMaxListeners: number;

  beforeEach(() => {
    originalDefaultMaxListeners = EventEmitter.defaultMaxListeners;
    originalProcessMaxListeners = process.getMaxListeners();
  });

  afterEach(() => {
    // Restore original values after each test
    EventEmitter.defaultMaxListeners = originalDefaultMaxListeners;
    process.setMaxListeners(originalProcessMaxListeners);
  });

  describe("LISTENER_BUDGETS", () => {
    it("should have documented listener counts for SDK transports", () => {
      expect(LISTENER_BUDGETS.sdkStdioTransport).toBe(7);
      expect(LISTENER_BUDGETS.sdkHttpTransport).toBe(3);
      expect(LISTENER_BUDGETS.sdkSseTransport).toBe(4);
    });

    it("should have CLI overhead and margin", () => {
      expect(LISTENER_BUDGETS.cliOverhead).toBe(3);
      expect(LISTENER_BUDGETS.margin).toBe(10);
    });

    it("should have total budget less than 50 for any transport", () => {
      const maxStdio =
        LISTENER_BUDGETS.sdkStdioTransport +
        LISTENER_BUDGETS.cliOverhead +
        LISTENER_BUDGETS.margin;
      const maxHttp =
        LISTENER_BUDGETS.sdkHttpTransport +
        LISTENER_BUDGETS.cliOverhead +
        LISTENER_BUDGETS.margin;
      const maxSse =
        LISTENER_BUDGETS.sdkSseTransport +
        LISTENER_BUDGETS.cliOverhead +
        LISTENER_BUDGETS.margin;

      expect(maxStdio).toBeLessThan(50);
      expect(maxHttp).toBeLessThan(50);
      expect(maxSse).toBeLessThan(50);
    });

    it("should have total budget greater than Node default of 10", () => {
      const minBudget =
        LISTENER_BUDGETS.sdkHttpTransport +
        LISTENER_BUDGETS.cliOverhead +
        LISTENER_BUDGETS.margin;
      expect(minBudget).toBeGreaterThan(10);
    });
  });

  describe("calculateMaxListeners", () => {
    it("should calculate correct max for stdio transport", () => {
      const max = calculateMaxListeners("stdio");
      expect(max).toBe(
        LISTENER_BUDGETS.sdkStdioTransport +
          LISTENER_BUDGETS.cliOverhead +
          LISTENER_BUDGETS.margin,
      );
      expect(max).toBe(20); // 7 + 3 + 10
    });

    it("should calculate correct max for http transport", () => {
      const max = calculateMaxListeners("http");
      expect(max).toBe(
        LISTENER_BUDGETS.sdkHttpTransport +
          LISTENER_BUDGETS.cliOverhead +
          LISTENER_BUDGETS.margin,
      );
      expect(max).toBe(16); // 3 + 3 + 10
    });

    it("should calculate correct max for sse transport", () => {
      const max = calculateMaxListeners("sse");
      expect(max).toBe(
        LISTENER_BUDGETS.sdkSseTransport +
          LISTENER_BUDGETS.cliOverhead +
          LISTENER_BUDGETS.margin,
      );
      expect(max).toBe(17); // 4 + 3 + 10
    });

    it("should calculate stdio > sse > http", () => {
      expect(calculateMaxListeners("stdio")).toBeGreaterThan(
        calculateMaxListeners("sse"),
      );
      expect(calculateMaxListeners("sse")).toBeGreaterThan(
        calculateMaxListeners("http"),
      );
    });
  });

  describe("ScopedListenerConfig", () => {
    it("should capture original values on construction", () => {
      // Set known values
      EventEmitter.defaultMaxListeners = 15;
      process.setMaxListeners(25);

      const config = new ScopedListenerConfig(100);

      // Values should not change yet
      expect(EventEmitter.defaultMaxListeners).toBe(15);
      expect(process.getMaxListeners()).toBe(25);
      expect(config.isApplied()).toBe(false);
    });

    it("should apply configuration when apply() is called", () => {
      const config = new ScopedListenerConfig(75);

      config.apply();

      expect(EventEmitter.defaultMaxListeners).toBe(75);
      expect(process.getMaxListeners()).toBe(75);
      expect(config.isApplied()).toBe(true);
    });

    it("should restore original values when restore() is called", () => {
      EventEmitter.defaultMaxListeners = 12;
      process.setMaxListeners(18);

      const config = new ScopedListenerConfig(100);
      config.apply();

      expect(EventEmitter.defaultMaxListeners).toBe(100);
      expect(process.getMaxListeners()).toBe(100);

      config.restore();

      expect(EventEmitter.defaultMaxListeners).toBe(12);
      expect(process.getMaxListeners()).toBe(18);
      expect(config.isApplied()).toBe(false);
    });

    it("should be idempotent on multiple apply() calls", () => {
      EventEmitter.defaultMaxListeners = 10;
      process.setMaxListeners(10);

      const config = new ScopedListenerConfig(50);
      config.apply();

      // Change the global values after first apply
      EventEmitter.defaultMaxListeners = 999;

      // Second apply should be no-op (don't re-capture)
      config.apply();

      // Restore should use original captured values
      config.restore();

      expect(EventEmitter.defaultMaxListeners).toBe(10);
    });

    it("should be safe to call restore() without apply()", () => {
      EventEmitter.defaultMaxListeners = 10;

      const config = new ScopedListenerConfig(50);
      config.restore(); // Should be no-op

      expect(EventEmitter.defaultMaxListeners).toBe(10);
      expect(config.isApplied()).toBe(false);
    });

    it("should use default value of 50 when not specified", () => {
      const config = new ScopedListenerConfig();
      config.apply();

      expect(EventEmitter.defaultMaxListeners).toBe(50);
      expect(process.getMaxListeners()).toBe(50);
    });

    it("should work correctly in try/finally pattern", () => {
      EventEmitter.defaultMaxListeners = 10;
      process.setMaxListeners(10);

      const config = new ScopedListenerConfig(50);
      config.apply();

      try {
        // Simulate some work
        expect(EventEmitter.defaultMaxListeners).toBe(50);
        throw new Error("Simulated error");
      } catch {
        // Error caught
      } finally {
        config.restore();
      }

      // Should be restored even after error
      expect(EventEmitter.defaultMaxListeners).toBe(10);
      expect(process.getMaxListeners()).toBe(10);
    });
  });

  describe("getListenerCount", () => {
    it("should count all listeners on an emitter", () => {
      const emitter = new EventEmitter();
      emitter.on("event1", () => {});
      emitter.on("event1", () => {});
      emitter.on("event2", () => {});

      expect(getListenerCount(emitter)).toBe(3);
    });

    it("should return 0 for emitter with no listeners", () => {
      const emitter = new EventEmitter();
      expect(getListenerCount(emitter)).toBe(0);
    });

    it("should handle multiple event types", () => {
      const emitter = new EventEmitter();
      emitter.on("a", () => {});
      emitter.on("b", () => {});
      emitter.on("c", () => {});
      emitter.on("c", () => {});

      expect(getListenerCount(emitter)).toBe(4);
    });

    it("should count once listeners", () => {
      const emitter = new EventEmitter();
      emitter.once("event", () => {});
      emitter.on("event", () => {});

      expect(getListenerCount(emitter)).toBe(2);
    });
  });

  describe("getProcessListenerCount", () => {
    it("should return a number", () => {
      const count = getProcessListenerCount();
      expect(typeof count).toBe("number");
      expect(count).toBeGreaterThanOrEqual(0);
    });

    it("should increase when adding process listeners", () => {
      const initialCount = getProcessListenerCount();
      const handler = () => {};

      process.on("warning", handler);

      const newCount = getProcessListenerCount();
      expect(newCount).toBe(initialCount + 1);

      // Cleanup
      process.off("warning", handler);
    });
  });
});
