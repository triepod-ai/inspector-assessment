/**
 * Listener Leak Detection Tests
 *
 * These tests verify that EventEmitter listeners are properly managed
 * and don't accumulate during assessment operations.
 *
 * Purpose:
 * - Regression tests to catch listener leaks
 * - Document expected listener counts
 * - Validate that ScopedListenerConfig works in practice
 *
 * @see GitHub Issue #33
 */

import { describe, it, expect, beforeEach, afterEach } from "@jest/globals";
import { EventEmitter } from "events";
import {
  LISTENER_BUDGETS,
  ScopedListenerConfig,
  getProcessListenerCount,
} from "../lib/event-config.js";

describe("Listener Leak Detection", () => {
  // Store original values for restoration
  let originalDefaultMaxListeners: number;
  let originalProcessMaxListeners: number;

  beforeEach(() => {
    originalDefaultMaxListeners = EventEmitter.defaultMaxListeners;
    originalProcessMaxListeners = process.getMaxListeners();
  });

  afterEach(() => {
    EventEmitter.defaultMaxListeners = originalDefaultMaxListeners;
    process.setMaxListeners(originalProcessMaxListeners);
  });

  describe("Listener Budget Documentation", () => {
    it("should document that 50 max listeners is sufficient", () => {
      // This test documents the expected listener budget calculation
      // If this fails, the LISTENER_BUDGETS constants need updating
      const maxBudget =
        LISTENER_BUDGETS.sdkStdioTransport + // 7 (worst case: stdio)
        LISTENER_BUDGETS.cliOverhead + // 3 (stderr + signals)
        LISTENER_BUDGETS.margin; // 10 (safety margin)

      expect(maxBudget).toBe(20);
      expect(maxBudget).toBeLessThan(50); // Our default max
      expect(maxBudget).toBeGreaterThan(10); // Node.js default
    });

    it("should explain why 300 was excessive", () => {
      // Previous implementation used 300 max listeners
      // This test documents why 50 is sufficient
      const oldMax = 300;
      const actualNeeded =
        LISTENER_BUDGETS.sdkStdioTransport +
        LISTENER_BUDGETS.cliOverhead +
        LISTENER_BUDGETS.margin;

      // 300 was 15x more than actually needed
      expect(oldMax / actualNeeded).toBeGreaterThan(10);

      // The excessive limit could mask real leaks
      // Our new limit of 50 gives 2.5x headroom while still catching issues
      const newMax = 50;
      expect(newMax / actualNeeded).toBeGreaterThan(2);
      expect(newMax / actualNeeded).toBeLessThan(5);
    });
  });

  describe("Process Listener Baseline", () => {
    it("should have reasonable baseline process listeners", () => {
      // Baseline should be low - just default Node.js handlers
      const baseline = getProcessListenerCount();

      // Node.js typically has a few default listeners
      // If this is very high, something is adding listeners globally
      expect(baseline).toBeLessThan(20);
    });

    it("should not grow listeners after creating and cleaning up emitters", () => {
      const initialCount = getProcessListenerCount();

      // Simulate creating multiple emitters (like transports would)
      const emitters: EventEmitter[] = [];
      for (let i = 0; i < 10; i++) {
        const emitter = new EventEmitter();
        emitter.on("data", () => {});
        emitter.on("error", () => {});
        emitters.push(emitter);
      }

      // Clean up
      for (const emitter of emitters) {
        emitter.removeAllListeners();
      }

      const finalCount = getProcessListenerCount();

      // Process listeners should not have grown
      expect(finalCount).toBe(initialCount);
    });
  });

  describe("ScopedListenerConfig in Practice", () => {
    it("should restore defaults after scoped operation", () => {
      const initialDefault = EventEmitter.defaultMaxListeners;
      const initialProcess = process.getMaxListeners();

      const config = new ScopedListenerConfig(50);
      config.apply();

      // Simulate assessment work
      const emitter = new EventEmitter();
      for (let i = 0; i < 20; i++) {
        emitter.on(`event${i}`, () => {});
      }
      emitter.removeAllListeners();

      config.restore();

      // Verify restoration
      expect(EventEmitter.defaultMaxListeners).toBe(initialDefault);
      expect(process.getMaxListeners()).toBe(initialProcess);
    });

    it("should restore defaults even on error", () => {
      const initialDefault = EventEmitter.defaultMaxListeners;
      const initialProcess = process.getMaxListeners();

      const config = new ScopedListenerConfig(50);

      try {
        config.apply();
        throw new Error("Simulated assessment error");
      } catch {
        // Expected
      } finally {
        config.restore();
      }

      expect(EventEmitter.defaultMaxListeners).toBe(initialDefault);
      expect(process.getMaxListeners()).toBe(initialProcess);
    });

    it("should allow expected listener count without warnings", () => {
      // This test verifies that our budget allows the expected listeners
      const config = new ScopedListenerConfig(50);
      config.apply();

      try {
        const emitter = new EventEmitter();
        emitter.setMaxListeners(20); // Our calculated budget

        // Add listeners up to the budget (simulating SDK)
        for (let i = 0; i < 7; i++) {
          emitter.on("sdkEvent", () => {});
        }
        for (let i = 0; i < 3; i++) {
          emitter.on("cliEvent", () => {});
        }
        for (let i = 0; i < 10; i++) {
          emitter.on("marginEvent", () => {});
        }

        // Should not throw or warn
        expect(emitter.listenerCount("sdkEvent")).toBe(7);
        expect(emitter.listenerCount("cliEvent")).toBe(3);
        expect(emitter.listenerCount("marginEvent")).toBe(10);

        emitter.removeAllListeners();
      } finally {
        config.restore();
      }
    });
  });

  describe("Regression Prevention", () => {
    it("should detect if someone adds global modification back", () => {
      // This test will fail if someone adds back:
      // EventEmitter.defaultMaxListeners = 300;
      // at module load time

      // The default should be 10 (Node.js default) unless explicitly changed
      // If this test starts failing, it means global modification was re-added
      expect(originalDefaultMaxListeners).toBeLessThanOrEqual(50);
    });

    it("should catch excessive listener budget constants", () => {
      // If someone increases the budgets excessively, this will fail
      const totalBudget = Object.values(LISTENER_BUDGETS).reduce(
        (sum, val) => sum + val,
        0,
      );

      // Total budget should be reasonable
      // If all constants are added together, should still be under 50
      expect(totalBudget).toBeLessThan(50);
    });
  });
});
