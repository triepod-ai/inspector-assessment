/**
 * Unit tests for the structured logger.
 */

import {
  createLogger,
  createSilentLogger,
  DEFAULT_LOGGING_CONFIG,
  Logger,
  LogLevel,
} from "./logger";

describe("Logger", () => {
  let consoleLogSpy: jest.SpyInstance;
  let logs: string[];

  beforeEach(() => {
    logs = [];
    consoleLogSpy = jest.spyOn(console, "log").mockImplementation((msg) => {
      logs.push(String(msg));
    });
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  describe("createLogger", () => {
    it("should create a logger with default configuration", () => {
      const logger = createLogger("TestModule");
      expect(logger).toBeDefined();
      expect(typeof logger.debug).toBe("function");
      expect(typeof logger.info).toBe("function");
      expect(typeof logger.warn).toBe("function");
      expect(typeof logger.error).toBe("function");
      expect(typeof logger.child).toBe("function");
      expect(typeof logger.isLevelEnabled).toBe("function");
    });

    it("should prefix messages with module name", () => {
      const logger = createLogger("TestModule");
      logger.info("test message");

      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain("[TestModule]");
      expect(logs[0]).toContain("test message");
    });
  });

  describe("level filtering", () => {
    it("should suppress debug messages at info level (default)", () => {
      const logger = createLogger("TestModule");

      logger.debug("debug message");
      logger.info("info message");
      logger.warn("warn message");
      logger.error("error message");

      expect(logs).toHaveLength(3);
      expect(logs[0]).toContain("info message");
      expect(logs[1]).toContain("warn message");
      expect(logs[2]).toContain("error message");
    });

    it("should show all messages at debug level", () => {
      const logger = createLogger("TestModule", { level: "debug" });

      logger.debug("debug message");
      logger.info("info message");
      logger.warn("warn message");
      logger.error("error message");

      expect(logs).toHaveLength(4);
      expect(logs[0]).toContain("debug message");
      expect(logs[1]).toContain("info message");
      expect(logs[2]).toContain("warn message");
      expect(logs[3]).toContain("error message");
    });

    it("should only show errors at error level", () => {
      const logger = createLogger("TestModule", { level: "error" });

      logger.debug("debug message");
      logger.info("info message");
      logger.warn("warn message");
      logger.error("error message");

      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain("error message");
    });

    it("should suppress all messages at silent level", () => {
      const logger = createLogger("TestModule", { level: "silent" });

      logger.debug("debug message");
      logger.info("info message");
      logger.warn("warn message");
      logger.error("error message");

      expect(logs).toHaveLength(0);
    });

    it("should show warn and error at warn level", () => {
      const logger = createLogger("TestModule", { level: "warn" });

      logger.debug("debug message");
      logger.info("info message");
      logger.warn("warn message");
      logger.error("error message");

      expect(logs).toHaveLength(2);
      expect(logs[0]).toContain("warn message");
      expect(logs[1]).toContain("error message");
    });
  });

  describe("context serialization", () => {
    it("should serialize context objects as JSON", () => {
      const logger = createLogger("TestModule");
      logger.info("test message", { toolCount: 5, duration: 1234 });

      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain('{"toolCount":5,"duration":1234}');
    });

    it("should handle empty context", () => {
      const logger = createLogger("TestModule");
      logger.info("test message", {});

      expect(logs).toHaveLength(1);
      expect(logs[0]).toBe("[TestModule] test message");
    });

    it("should handle undefined context", () => {
      const logger = createLogger("TestModule");
      logger.info("test message");

      expect(logs).toHaveLength(1);
      expect(logs[0]).toBe("[TestModule] test message");
    });

    it("should handle nested objects in context", () => {
      const logger = createLogger("TestModule");
      logger.info("test message", {
        config: { timeout: 5000, retries: 3 },
        tools: ["tool1", "tool2"],
      });

      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain('"config":{"timeout":5000,"retries":3}');
      expect(logs[0]).toContain('"tools":["tool1","tool2"]');
    });

    it("should serialize Error objects with name, message, and stack", () => {
      const logger = createLogger("TestModule");
      const error = new Error("Test error");
      logger.error("operation failed", { error });

      expect(logs).toHaveLength(1);
      const output = logs[0];
      expect(output).toContain('"name":"Error"');
      expect(output).toContain('"message":"Test error"');
      expect(output).toContain('"stack":');
    });
  });

  describe("JSON format", () => {
    it("should output JSON when format is json", () => {
      const logger = createLogger("TestModule", { format: "json" });
      logger.info("test message", { key: "value" });

      expect(logs).toHaveLength(1);

      const parsed = JSON.parse(logs[0]);
      expect(parsed.level).toBe("info");
      expect(parsed.prefix).toBe("TestModule");
      expect(parsed.message).toBe("test message");
      expect(parsed.context).toEqual({ key: "value" });
    });

    it("should include timestamp in JSON when enabled", () => {
      const logger = createLogger("TestModule", {
        format: "json",
        includeTimestamp: true,
      });
      logger.info("test message");

      expect(logs).toHaveLength(1);

      const parsed = JSON.parse(logs[0]);
      expect(parsed.timestamp).toBeDefined();
      expect(typeof parsed.timestamp).toBe("string");
      // Verify it's a valid ISO timestamp
      expect(() => new Date(parsed.timestamp)).not.toThrow();
    });

    it("should not include context field when context is empty", () => {
      const logger = createLogger("TestModule", { format: "json" });
      logger.info("test message");

      expect(logs).toHaveLength(1);

      const parsed = JSON.parse(logs[0]);
      expect(parsed.context).toBeUndefined();
    });
  });

  describe("timestamp", () => {
    it("should include timestamp when enabled in text format", () => {
      const logger = createLogger("TestModule", { includeTimestamp: true });
      logger.info("test message");

      expect(logs).toHaveLength(1);
      // Timestamp format: [2024-01-15T10:30:00.000Z]
      expect(logs[0]).toMatch(/^\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it("should not include timestamp by default", () => {
      const logger = createLogger("TestModule");
      logger.info("test message");

      expect(logs).toHaveLength(1);
      expect(logs[0]).not.toMatch(/^\[\d{4}-\d{2}-\d{2}T/);
    });
  });

  describe("child logger", () => {
    it("should create child logger with combined prefix", () => {
      const parent = createLogger("ParentModule");
      const child = parent.child("ChildComponent");

      child.info("child message");

      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain("[ParentModule:ChildComponent]");
      expect(logs[0]).toContain("child message");
    });

    it("should inherit configuration from parent", () => {
      const parent = createLogger("ParentModule", { level: "debug" });
      const child = parent.child("ChildComponent");

      child.debug("debug from child");

      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain("debug from child");
    });

    it("should support nested children", () => {
      const parent = createLogger("A");
      const child = parent.child("B");
      const grandchild = child.child("C");

      grandchild.info("nested message");

      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain("[A:B:C]");
    });
  });

  describe("isLevelEnabled", () => {
    it("should return true for enabled levels", () => {
      const logger = createLogger("TestModule", { level: "info" });

      expect(logger.isLevelEnabled("error")).toBe(true);
      expect(logger.isLevelEnabled("warn")).toBe(true);
      expect(logger.isLevelEnabled("info")).toBe(true);
    });

    it("should return false for disabled levels", () => {
      const logger = createLogger("TestModule", { level: "info" });

      expect(logger.isLevelEnabled("debug")).toBe(false);
    });

    it("should return false for all levels when silent", () => {
      const logger = createLogger("TestModule", { level: "silent" });

      expect(logger.isLevelEnabled("error")).toBe(false);
      expect(logger.isLevelEnabled("warn")).toBe(false);
      expect(logger.isLevelEnabled("info")).toBe(false);
      expect(logger.isLevelEnabled("debug")).toBe(false);
    });

    it("should return true for all levels when debug", () => {
      const logger = createLogger("TestModule", { level: "debug" });

      expect(logger.isLevelEnabled("error")).toBe(true);
      expect(logger.isLevelEnabled("warn")).toBe(true);
      expect(logger.isLevelEnabled("info")).toBe(true);
      expect(logger.isLevelEnabled("debug")).toBe(true);
    });
  });

  describe("createSilentLogger", () => {
    it("should create a logger that produces no output", () => {
      const logger = createSilentLogger();

      logger.debug("debug");
      logger.info("info");
      logger.warn("warn");
      logger.error("error");

      expect(logs).toHaveLength(0);
    });
  });

  describe("DEFAULT_LOGGING_CONFIG", () => {
    it("should have sensible defaults", () => {
      expect(DEFAULT_LOGGING_CONFIG.level).toBe("info");
      expect(DEFAULT_LOGGING_CONFIG.format).toBe("text");
      expect(DEFAULT_LOGGING_CONFIG.includeTimestamp).toBe(false);
    });
  });

  describe("output stream", () => {
    it("should output to console.log (stdout), not console.error (stderr)", () => {
      const consoleErrorSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});

      const logger = createLogger("TestModule");
      logger.info("test message");
      logger.error("error message"); // Even errors go to stdout!

      expect(consoleLogSpy).toHaveBeenCalledTimes(2);
      expect(consoleErrorSpy).not.toHaveBeenCalled();

      consoleErrorSpy.mockRestore();
    });
  });
});
