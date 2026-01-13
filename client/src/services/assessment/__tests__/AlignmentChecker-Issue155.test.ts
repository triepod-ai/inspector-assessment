/**
 * AlignmentChecker Tests for Issue #155
 *
 * Tests for annotation debug mode and expanded annotation search locations.
 *
 * Issue #155: Tool annotation detection returns 0% for servers with runtime annotations
 *
 * This test suite verifies:
 * 1. Debug mode can be enabled/disabled via setAnnotationDebugMode()
 * 2. Annotation extraction from _meta location
 * 3. Annotation extraction from annotations.hints nested location
 * 4. Debug logging is conditional on debug mode flag
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  extractAnnotations,
  setAnnotationDebugMode,
  isAnnotationDebugEnabled,
} from "../modules/annotations/AlignmentChecker";

describe("AlignmentChecker - Issue #155 Debug Mode", () => {
  beforeEach(() => {
    // Reset debug mode before each test
    setAnnotationDebugMode(false);
  });

  afterEach(() => {
    // Ensure debug mode is off after tests
    setAnnotationDebugMode(false);
  });

  describe("setAnnotationDebugMode()", () => {
    it("should enable debug mode when set to true", () => {
      setAnnotationDebugMode(true);
      expect(isAnnotationDebugEnabled()).toBe(true);
    });

    it("should disable debug mode when set to false", () => {
      setAnnotationDebugMode(true);
      setAnnotationDebugMode(false);
      expect(isAnnotationDebugEnabled()).toBe(false);
    });

    it("should default to disabled", () => {
      expect(isAnnotationDebugEnabled()).toBe(false);
    });
  });

  describe("extractAnnotations() - _meta location (Priority 4)", () => {
    it("should detect annotations in _meta object", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        _meta: {
          readOnlyHint: true,
          destructiveHint: false,
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(false);
      expect(result.source).toBe("mcp");
    });

    it("should detect non-suffixed annotations in _meta", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        _meta: {
          readOnly: true,
          destructive: true,
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should extract all hint types from _meta", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        _meta: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(false);
      expect(result.idempotentHint).toBe(true);
      expect(result.openWorldHint).toBe(false);
      expect(result.source).toBe("mcp");
    });
  });

  describe("extractAnnotations() - annotations.hints location (Priority 5)", () => {
    it("should detect annotations nested in annotations.hints", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        annotations: {
          hints: {
            readOnlyHint: true,
            destructiveHint: false,
          },
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(false);
      expect(result.source).toBe("mcp");
    });

    it("should prefer top-level annotations over nested hints", () => {
      // Priority 1 (annotations object) should take precedence over Priority 5 (annotations.hints)
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        annotations: {
          readOnlyHint: false, // Top-level
          hints: {
            readOnlyHint: true, // Nested - should be ignored
          },
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(false); // Should use top-level value
      expect(result.source).toBe("mcp");
    });

    it("should extract all hint types from annotations.hints", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        annotations: {
          hints: {
            readOnlyHint: true,
            destructiveHint: true,
            idempotentHint: false,
            openWorldHint: true,
          },
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(true);
      expect(result.idempotentHint).toBe(false);
      expect(result.openWorldHint).toBe(true);
      expect(result.source).toBe("mcp");
    });
  });

  describe("extractAnnotations() - Priority Order", () => {
    it("should prefer annotations object (Priority 1) over direct properties (Priority 2)", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnlyHint: true },
        readOnlyHint: false, // Direct property should be ignored
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should use direct properties (Priority 2) when annotations object is absent", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        readOnlyHint: true,
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should return source: none when no annotations found", () => {
      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBeUndefined();
      expect(result.destructiveHint).toBeUndefined();
      expect(result.source).toBe("none");
    });
  });

  describe("Debug logging behavior", () => {
    it("should not log when debug mode is disabled", () => {
      const consoleSpy = jest.spyOn(console, "log").mockImplementation();

      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnlyHint: true },
      } as unknown as Tool;

      setAnnotationDebugMode(false);
      extractAnnotations(tool);

      expect(consoleSpy).not.toHaveBeenCalledWith(
        expect.stringContaining("[DEBUG-ANNOTATIONS]"),
        expect.anything(),
        expect.anything(),
        expect.anything(),
        expect.anything(),
        expect.anything(),
      );

      consoleSpy.mockRestore();
    });

    it("should log with [DEBUG-ANNOTATIONS] prefix when enabled", () => {
      const consoleSpy = jest.spyOn(console, "log").mockImplementation();

      const tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnlyHint: true },
      } as unknown as Tool;

      setAnnotationDebugMode(true);
      extractAnnotations(tool);

      // Verify the [DEBUG-ANNOTATIONS] prefix was logged
      // Note: expect.anything() doesn't match undefined, so check first 2 args
      expect(consoleSpy).toHaveBeenCalled();
      const call = consoleSpy.mock.calls[0];
      expect(call[0]).toBe("[DEBUG-ANNOTATIONS]");
      expect(call[1]).toBe("test_tool");

      consoleSpy.mockRestore();
    });
  });
});
