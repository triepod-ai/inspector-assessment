/**
 * Tests for Performance Configuration Zod Schemas
 *
 * @module assessment/config/__tests__/performanceConfigSchemas
 */

// Uses Jest globals (describe, test, expect)
import {
  PerformanceConfigSchema,
  validatePerformanceConfigWithZod,
  parsePerformanceConfig,
  safeParsePerformanceConfig,
} from "../performanceConfigSchemas";
import { DEFAULT_PERFORMANCE_CONFIG } from "../performanceConfig";

describe("PerformanceConfigSchema", () => {
  describe("valid configurations", () => {
    test("accepts empty object (all fields optional)", () => {
      const result = PerformanceConfigSchema.safeParse({});
      expect(result.success).toBe(true);
    });

    test("accepts DEFAULT_PERFORMANCE_CONFIG", () => {
      const result = PerformanceConfigSchema.safeParse(
        DEFAULT_PERFORMANCE_CONFIG,
      );
      expect(result.success).toBe(true);
    });

    test("accepts valid partial config", () => {
      const config = {
        batchFlushIntervalMs: 100,
        functionalityBatchSize: 10,
      };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(true);
    });

    test("accepts boundary values", () => {
      const config = {
        batchFlushIntervalMs: 50, // min
        functionalityBatchSize: 100, // max
        securityBatchSize: 1, // min
        testTimeoutMs: 300000, // max
        securityTestTimeoutMs: 100, // min
        queueWarningThreshold: 1000000, // max
        eventEmitterMaxListeners: 10, // min
      };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(true);
    });
  });

  describe("invalid configurations", () => {
    test("rejects batchFlushIntervalMs below minimum", () => {
      const config = { batchFlushIntervalMs: 49 };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(false);
    });

    test("rejects batchFlushIntervalMs above maximum", () => {
      const config = { batchFlushIntervalMs: 10001 };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(false);
    });

    test("rejects functionalityBatchSize below minimum", () => {
      const config = { functionalityBatchSize: 0 };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(false);
    });

    test("rejects functionalityBatchSize above maximum", () => {
      const config = { functionalityBatchSize: 101 };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(false);
    });

    test("rejects non-integer values", () => {
      const config = { batchFlushIntervalMs: 100.5 };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(false);
    });

    test("rejects string values", () => {
      const config = { batchFlushIntervalMs: "100" };
      const result = PerformanceConfigSchema.safeParse(config);
      expect(result.success).toBe(false);
    });
  });
});

describe("validatePerformanceConfigWithZod", () => {
  test("returns empty array for valid config", () => {
    const errors = validatePerformanceConfigWithZod(DEFAULT_PERFORMANCE_CONFIG);
    expect(errors).toEqual([]);
  });

  test("returns errors for invalid config", () => {
    const errors = validatePerformanceConfigWithZod({
      batchFlushIntervalMs: 10, // below min
      functionalityBatchSize: 200, // above max
    });
    expect(errors).toHaveLength(2);
    expect(errors[0]).toContain("batchFlushIntervalMs");
    expect(errors[1]).toContain("functionalityBatchSize");
  });

  test("returns error for non-integer value", () => {
    const errors = validatePerformanceConfigWithZod({
      testTimeoutMs: 5000.5,
    });
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("testTimeoutMs");
  });
});

describe("parsePerformanceConfig", () => {
  test("parses valid config", () => {
    const config = { batchFlushIntervalMs: 100 };
    const parsed = parsePerformanceConfig(config);
    expect(parsed.batchFlushIntervalMs).toBe(100);
  });

  test("throws ZodError for invalid config", () => {
    expect(() =>
      parsePerformanceConfig({ batchFlushIntervalMs: 10 }),
    ).toThrow();
  });
});

describe("safeParsePerformanceConfig", () => {
  test("returns success for valid config", () => {
    const result = safeParsePerformanceConfig({ batchFlushIntervalMs: 100 });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.batchFlushIntervalMs).toBe(100);
    }
  });

  test("returns error for invalid config", () => {
    const result = safeParsePerformanceConfig({ batchFlushIntervalMs: 10 });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.errors).toHaveLength(1);
    }
  });
});
