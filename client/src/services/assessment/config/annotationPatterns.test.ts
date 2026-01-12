/**
 * Annotation Patterns BC Tests
 * Verify loadPatternConfig works with and without logger parameter (Issue #32)
 */
import {
  loadPatternConfig,
  DEFAULT_ANNOTATION_PATTERNS,
} from "./annotationPatterns";
import type { Logger } from "../lib/logger";

const createMockLogger = (): Logger & { warn: jest.Mock } => ({
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  child: jest.fn().mockReturnThis(),
  isLevelEnabled: jest.fn().mockReturnValue(true),
});

describe("loadPatternConfig", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Backwards Compatibility - Logger Parameter", () => {
    it("should return defaults without config path (no logger)", () => {
      const config = loadPatternConfig();
      expect(config).toEqual(DEFAULT_ANNOTATION_PATTERNS);
    });

    it("should return defaults without config path (with logger)", () => {
      const mockLogger = createMockLogger();
      const config = loadPatternConfig(undefined, mockLogger);
      expect(config).toEqual(DEFAULT_ANNOTATION_PATTERNS);
      expect(mockLogger.warn).not.toHaveBeenCalled();
    });

    it("should warn via logger when config file not found", () => {
      const mockLogger = createMockLogger();
      const config = loadPatternConfig("/nonexistent/path.json", mockLogger);

      // Should fall back to defaults
      expect(config).toEqual(DEFAULT_ANNOTATION_PATTERNS);
      // Should log warning
      expect(mockLogger.warn).toHaveBeenCalledWith(
        "Could not load pattern config, using defaults",
        expect.objectContaining({ configPath: "/nonexistent/path.json" }),
      );
    });

    it("should not throw when config file not found and no logger", () => {
      // Without logger, should silently fall back to defaults
      const config = loadPatternConfig("/nonexistent/path.json");
      expect(config).toEqual(DEFAULT_ANNOTATION_PATTERNS);
    });
  });
});
