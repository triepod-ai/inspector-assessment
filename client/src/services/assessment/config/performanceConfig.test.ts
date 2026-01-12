/**
 * Performance Config Tests
 * Verify PerformanceConfig defaults, validation, and loading (Issue #37)
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import {
  DEFAULT_PERFORMANCE_CONFIG,
  PERFORMANCE_PRESETS,
  validatePerformanceConfig,
  mergeWithDefaults,
  loadPerformanceConfig,
} from "./performanceConfig";
import type { Logger } from "../lib/logger";

const createMockLogger = (): Logger & {
  warn: jest.Mock;
  error: jest.Mock;
} => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  child: jest.fn().mockReturnThis(),
  isLevelEnabled: jest.fn().mockReturnValue(true),
});

describe("DEFAULT_PERFORMANCE_CONFIG", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should have all expected default values", () => {
    expect(DEFAULT_PERFORMANCE_CONFIG).toEqual({
      batchFlushIntervalMs: 500,
      functionalityBatchSize: 5,
      securityBatchSize: 10,
      testTimeoutMs: 5000,
      securityTestTimeoutMs: 5000,
      queueWarningThreshold: 10000,
      eventEmitterMaxListeners: 50,
    });
  });

  it("should be immutable (frozen)", () => {
    expect(Object.isFrozen(DEFAULT_PERFORMANCE_CONFIG)).toBe(true);
  });
});

describe("PERFORMANCE_PRESETS", () => {
  it("should have default, fast, and resourceConstrained presets", () => {
    expect(PERFORMANCE_PRESETS.default).toBeDefined();
    expect(PERFORMANCE_PRESETS.fast).toBeDefined();
    expect(PERFORMANCE_PRESETS.resourceConstrained).toBeDefined();
  });

  it("fast preset should have larger batch sizes", () => {
    expect(PERFORMANCE_PRESETS.fast.functionalityBatchSize).toBeGreaterThan(
      DEFAULT_PERFORMANCE_CONFIG.functionalityBatchSize,
    );
    expect(PERFORMANCE_PRESETS.fast.securityBatchSize).toBeGreaterThan(
      DEFAULT_PERFORMANCE_CONFIG.securityBatchSize,
    );
  });

  it("resourceConstrained preset should have smaller values", () => {
    expect(
      PERFORMANCE_PRESETS.resourceConstrained.functionalityBatchSize,
    ).toBeLessThan(DEFAULT_PERFORMANCE_CONFIG.functionalityBatchSize);
    expect(
      PERFORMANCE_PRESETS.resourceConstrained.queueWarningThreshold,
    ).toBeLessThan(DEFAULT_PERFORMANCE_CONFIG.queueWarningThreshold);
  });
});

describe("validatePerformanceConfig", () => {
  it("should return empty array for valid config", () => {
    const errors = validatePerformanceConfig({
      batchFlushIntervalMs: 500,
      functionalityBatchSize: 5,
      securityBatchSize: 10,
    });
    expect(errors).toHaveLength(0);
  });

  it("should return empty array for empty partial config", () => {
    const errors = validatePerformanceConfig({});
    expect(errors).toHaveLength(0);
  });

  it("should reject batchFlushIntervalMs below minimum", () => {
    const errors = validatePerformanceConfig({ batchFlushIntervalMs: 10 });
    expect(
      errors.some(
        (e) => e.includes("batchFlushIntervalMs") && e.includes(">="),
      ),
    ).toBe(true);
  });

  it("should reject batchFlushIntervalMs above maximum", () => {
    const errors = validatePerformanceConfig({ batchFlushIntervalMs: 50000 });
    expect(
      errors.some(
        (e) => e.includes("batchFlushIntervalMs") && e.includes("<="),
      ),
    ).toBe(true);
  });

  it("should reject functionalityBatchSize below minimum", () => {
    const errors = validatePerformanceConfig({ functionalityBatchSize: 0 });
    expect(
      errors.some(
        (e) => e.includes("functionalityBatchSize") && e.includes(">="),
      ),
    ).toBe(true);
  });

  it("should reject securityBatchSize above maximum", () => {
    const errors = validatePerformanceConfig({ securityBatchSize: 200 });
    expect(
      errors.some((e) => e.includes("securityBatchSize") && e.includes("<=")),
    ).toBe(true);
  });

  it("should reject testTimeoutMs below minimum", () => {
    const errors = validatePerformanceConfig({ testTimeoutMs: 50 });
    expect(
      errors.some((e) => e.includes("testTimeoutMs") && e.includes(">=")),
    ).toBe(true);
  });

  it("should reject queueWarningThreshold below minimum", () => {
    const errors = validatePerformanceConfig({ queueWarningThreshold: 50 });
    expect(
      errors.some(
        (e) => e.includes("queueWarningThreshold") && e.includes(">="),
      ),
    ).toBe(true);
  });

  it("should reject eventEmitterMaxListeners below minimum", () => {
    const errors = validatePerformanceConfig({ eventEmitterMaxListeners: 5 });
    expect(
      errors.some(
        (e) => e.includes("eventEmitterMaxListeners") && e.includes(">="),
      ),
    ).toBe(true);
  });

  it("should return multiple errors for multiple invalid values", () => {
    const errors = validatePerformanceConfig({
      batchFlushIntervalMs: 1,
      functionalityBatchSize: 0,
      securityBatchSize: 1000,
    });
    expect(errors.length).toBeGreaterThanOrEqual(3);
  });
});

describe("mergeWithDefaults", () => {
  it("should return defaults for empty partial", () => {
    const merged = mergeWithDefaults({});
    expect(merged).toEqual(DEFAULT_PERFORMANCE_CONFIG);
  });

  it("should override specified values", () => {
    const merged = mergeWithDefaults({
      batchFlushIntervalMs: 1000,
      functionalityBatchSize: 20,
    });

    expect(merged.batchFlushIntervalMs).toBe(1000);
    expect(merged.functionalityBatchSize).toBe(20);
    // Others should be defaults
    expect(merged.securityBatchSize).toBe(
      DEFAULT_PERFORMANCE_CONFIG.securityBatchSize,
    );
    expect(merged.testTimeoutMs).toBe(DEFAULT_PERFORMANCE_CONFIG.testTimeoutMs);
  });

  it("should preserve all default values not overridden", () => {
    const merged = mergeWithDefaults({ testTimeoutMs: 10000 });

    expect(merged.batchFlushIntervalMs).toBe(
      DEFAULT_PERFORMANCE_CONFIG.batchFlushIntervalMs,
    );
    expect(merged.functionalityBatchSize).toBe(
      DEFAULT_PERFORMANCE_CONFIG.functionalityBatchSize,
    );
    expect(merged.securityBatchSize).toBe(
      DEFAULT_PERFORMANCE_CONFIG.securityBatchSize,
    );
    expect(merged.testTimeoutMs).toBe(10000);
    expect(merged.securityTestTimeoutMs).toBe(
      DEFAULT_PERFORMANCE_CONFIG.securityTestTimeoutMs,
    );
    expect(merged.queueWarningThreshold).toBe(
      DEFAULT_PERFORMANCE_CONFIG.queueWarningThreshold,
    );
    expect(merged.eventEmitterMaxListeners).toBe(
      DEFAULT_PERFORMANCE_CONFIG.eventEmitterMaxListeners,
    );
  });
});

describe("loadPerformanceConfig", () => {
  const tempDir = os.tmpdir();

  it("should return defaults when no path provided", () => {
    const config = loadPerformanceConfig();
    expect(config).toEqual(DEFAULT_PERFORMANCE_CONFIG);
  });

  it("should return defaults when path is undefined", () => {
    const config = loadPerformanceConfig(undefined);
    expect(config).toEqual(DEFAULT_PERFORMANCE_CONFIG);
  });

  it("should load and merge valid JSON config", () => {
    const configPath = path.join(tempDir, "test-perf-config.json");
    const customConfig = {
      batchFlushIntervalMs: 1000,
      securityBatchSize: 20,
    };

    fs.writeFileSync(configPath, JSON.stringify(customConfig));

    try {
      const config = loadPerformanceConfig(configPath);
      expect(config.batchFlushIntervalMs).toBe(1000);
      expect(config.securityBatchSize).toBe(20);
      // Defaults should be preserved
      expect(config.functionalityBatchSize).toBe(
        DEFAULT_PERFORMANCE_CONFIG.functionalityBatchSize,
      );
    } finally {
      fs.unlinkSync(configPath);
    }
  });

  it("should throw on invalid JSON", () => {
    const configPath = path.join(tempDir, "invalid-json.json");
    fs.writeFileSync(configPath, "{ invalid json }");

    try {
      expect(() => loadPerformanceConfig(configPath)).toThrow(
        "Invalid JSON in performance config",
      );
    } finally {
      fs.unlinkSync(configPath);
    }
  });

  it("should throw on invalid config values", () => {
    const configPath = path.join(tempDir, "invalid-values.json");
    const invalidConfig = { batchFlushIntervalMs: 1 }; // Below minimum

    fs.writeFileSync(configPath, JSON.stringify(invalidConfig));

    try {
      expect(() => loadPerformanceConfig(configPath)).toThrow(
        "Invalid performance config",
      );
    } finally {
      fs.unlinkSync(configPath);
    }
  });

  it("should warn and use defaults when file not found (with logger)", () => {
    const mockLogger = createMockLogger();
    const config = loadPerformanceConfig("/nonexistent/path.json", mockLogger);

    expect(config).toEqual(DEFAULT_PERFORMANCE_CONFIG);
    expect(mockLogger.warn).toHaveBeenCalledWith(
      "Could not load performance config, using defaults",
      expect.objectContaining({ configPath: "/nonexistent/path.json" }),
    );
  });

  it("should use defaults when file not found (no logger)", () => {
    const config = loadPerformanceConfig("/nonexistent/path.json");
    expect(config).toEqual(DEFAULT_PERFORMANCE_CONFIG);
  });

  it("should log debug message when config loaded successfully", () => {
    const configPath = path.join(tempDir, "debug-test.json");
    const mockLogger = createMockLogger();
    fs.writeFileSync(configPath, JSON.stringify({ testTimeoutMs: 8000 }));

    try {
      const config = loadPerformanceConfig(configPath, mockLogger);
      expect(config.testTimeoutMs).toBe(8000);
      expect(mockLogger.debug).toHaveBeenCalledWith(
        "Loaded performance config",
        expect.objectContaining({ configPath }),
      );
    } finally {
      fs.unlinkSync(configPath);
    }
  });
});
