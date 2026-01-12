/**
 * Tests for Shared Zod Schemas
 *
 * Validates the single source of truth schemas used across CLI and client.
 *
 * @module lib/__tests__/sharedSchemas
 */

// Uses Jest globals (describe, test, expect)
import {
  LogLevelSchema,
  TransportTypeSchema,
  ReportFormatSchema,
  PERF_CONFIG_RANGES,
  TIMEOUT_RANGES,
  ZOD_SCHEMA_VERSION,
  getLogLevelValues,
  getTransportTypeValues,
  getReportFormatValues,
} from "../assessment/sharedSchemas";

describe("sharedSchemas", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("ZOD_SCHEMA_VERSION", () => {
    test("is a positive integer", () => {
      expect(ZOD_SCHEMA_VERSION).toBeGreaterThan(0);
      expect(Number.isInteger(ZOD_SCHEMA_VERSION)).toBe(true);
    });

    test("is version 1 (update test when version changes)", () => {
      expect(ZOD_SCHEMA_VERSION).toBe(1);
    });
  });

  describe("LogLevelSchema", () => {
    test("accepts valid log levels", () => {
      const validLevels = ["silent", "error", "warn", "info", "debug"];
      for (const level of validLevels) {
        const result = LogLevelSchema.safeParse(level);
        expect(result.success).toBe(true);
      }
    });

    test("rejects invalid log levels", () => {
      const invalidLevels = ["SILENT", "ERROR", "verbose", "trace", "", null];
      for (const level of invalidLevels) {
        const result = LogLevelSchema.safeParse(level);
        expect(result.success).toBe(false);
      }
    });
  });

  describe("TransportTypeSchema", () => {
    test("accepts valid transport types", () => {
      const validTypes = ["stdio", "http", "sse"];
      for (const type of validTypes) {
        const result = TransportTypeSchema.safeParse(type);
        expect(result.success).toBe(true);
      }
    });

    test("rejects invalid transport types", () => {
      const invalidTypes = ["STDIO", "websocket", "grpc", "", null];
      for (const type of invalidTypes) {
        const result = TransportTypeSchema.safeParse(type);
        expect(result.success).toBe(false);
      }
    });
  });

  describe("ReportFormatSchema", () => {
    test("accepts valid report formats", () => {
      const validFormats = ["json", "markdown"];
      for (const format of validFormats) {
        const result = ReportFormatSchema.safeParse(format);
        expect(result.success).toBe(true);
      }
    });

    test("rejects invalid report formats", () => {
      const invalidFormats = ["JSON", "html", "pdf", "", null];
      for (const format of invalidFormats) {
        const result = ReportFormatSchema.safeParse(format);
        expect(result.success).toBe(false);
      }
    });
  });

  describe("PERF_CONFIG_RANGES", () => {
    test("has valid min/max for all fields", () => {
      const fields = Object.keys(PERF_CONFIG_RANGES) as Array<
        keyof typeof PERF_CONFIG_RANGES
      >;
      expect(fields.length).toBeGreaterThan(0);

      for (const field of fields) {
        const range = PERF_CONFIG_RANGES[field];
        expect(range.min).toBeDefined();
        expect(range.max).toBeDefined();
        expect(range.min).toBeLessThanOrEqual(range.max);
        expect(range.min).toBeGreaterThanOrEqual(0);
      }
    });

    test("contains expected performance fields", () => {
      expect(PERF_CONFIG_RANGES.batchFlushIntervalMs).toBeDefined();
      expect(PERF_CONFIG_RANGES.functionalityBatchSize).toBeDefined();
      expect(PERF_CONFIG_RANGES.securityBatchSize).toBeDefined();
      expect(PERF_CONFIG_RANGES.testTimeoutMs).toBeDefined();
      expect(PERF_CONFIG_RANGES.securityTestTimeoutMs).toBeDefined();
      expect(PERF_CONFIG_RANGES.queueWarningThreshold).toBeDefined();
      expect(PERF_CONFIG_RANGES.eventEmitterMaxListeners).toBeDefined();
    });

    test("has reasonable default ranges", () => {
      // Batch flush interval: 50-10000ms
      expect(PERF_CONFIG_RANGES.batchFlushIntervalMs.min).toBe(50);
      expect(PERF_CONFIG_RANGES.batchFlushIntervalMs.max).toBe(10000);

      // Batch sizes: 1-100
      expect(PERF_CONFIG_RANGES.functionalityBatchSize.min).toBe(1);
      expect(PERF_CONFIG_RANGES.functionalityBatchSize.max).toBe(100);

      // Timeouts: 100ms - 5min
      expect(PERF_CONFIG_RANGES.testTimeoutMs.min).toBe(100);
      expect(PERF_CONFIG_RANGES.testTimeoutMs.max).toBe(300000);
    });
  });

  describe("TIMEOUT_RANGES", () => {
    test("has valid min/max for all fields", () => {
      const fields = Object.keys(TIMEOUT_RANGES) as Array<
        keyof typeof TIMEOUT_RANGES
      >;
      expect(fields.length).toBeGreaterThan(0);

      for (const field of fields) {
        const range = TIMEOUT_RANGES[field];
        expect(range.min).toBeDefined();
        expect(range.max).toBeDefined();
        expect(range.min).toBeLessThanOrEqual(range.max);
        expect(range.min).toBeGreaterThan(0);
      }
    });

    test("contains expected timeout fields", () => {
      expect(TIMEOUT_RANGES.testTimeout).toBeDefined();
      expect(TIMEOUT_RANGES.securityTestTimeout).toBeDefined();
      expect(TIMEOUT_RANGES.connectionTimeout).toBeDefined();
    });
  });

  describe("Helper functions", () => {
    test("getLogLevelValues returns all log levels", () => {
      const values = getLogLevelValues();
      expect(values).toEqual(["silent", "error", "warn", "info", "debug"]);
    });

    test("getTransportTypeValues returns all transport types", () => {
      const values = getTransportTypeValues();
      expect(values).toEqual(["stdio", "http", "sse"]);
    });

    test("getReportFormatValues returns all report formats", () => {
      const values = getReportFormatValues();
      expect(values).toEqual(["json", "markdown"]);
    });
  });
});
