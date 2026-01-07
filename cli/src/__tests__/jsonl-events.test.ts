/**
 * JSONL Events Module Unit Tests
 *
 * Tests for JSONL event emission functions used for real-time monitoring.
 */

import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@jest/globals";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { SpyInstance } from "jest-mock";
import {
  emitJSONL,
  emitServerConnected,
  emitToolDiscovered,
  emitToolsDiscoveryComplete,
  emitAssessmentComplete,
  emitTestBatch,
  emitVulnerabilityFound,
  emitAnnotationMissing,
  emitAnnotationMisaligned,
  emitAnnotationReviewRecommended,
  emitAnnotationAligned,
  emitModulesConfigured,
  extractToolParams,
  type ToolParam,
} from "../lib/jsonl-events.js";

describe("JSONL Event Emission", () => {
  let consoleErrorSpy: SpyInstance<typeof console.error>;
  let emittedEvents: Record<string, unknown>[];

  beforeEach(() => {
    emittedEvents = [];
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(((
      msg: unknown,
    ) => {
      try {
        emittedEvents.push(JSON.parse(msg as string));
      } catch {
        // Not JSON, ignore
      }
    }) as typeof console.error);
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  describe("emitJSONL", () => {
    it("should emit event to stderr as JSON", () => {
      emitJSONL({ event: "test", data: "value" });
      expect(consoleErrorSpy).toHaveBeenCalled();
      expect(emittedEvents[0]).toHaveProperty("event", "test");
      expect(emittedEvents[0]).toHaveProperty("data", "value");
    });

    it("should include version field", () => {
      emitJSONL({ event: "test" });
      expect(emittedEvents[0]).toHaveProperty("version");
    });

    it("should handle complex nested objects", () => {
      emitJSONL({
        event: "complex",
        nested: { a: 1, b: [2, 3] },
      });
      expect(emittedEvents[0]).toHaveProperty("nested.a", 1);
    });
  });

  describe("emitServerConnected", () => {
    it("should emit server_connected event", () => {
      emitServerConnected("test-server", "http");
      expect(emittedEvents[0]).toHaveProperty("event", "server_connected");
      expect(emittedEvents[0]).toHaveProperty("serverName", "test-server");
      expect(emittedEvents[0]).toHaveProperty("transport", "http");
    });

    it("should handle different transport types", () => {
      emitServerConnected("server1", "stdio");
      emitServerConnected("server2", "sse");
      emitServerConnected("server3", "http");

      expect(emittedEvents[0]).toHaveProperty("transport", "stdio");
      expect(emittedEvents[1]).toHaveProperty("transport", "sse");
      expect(emittedEvents[2]).toHaveProperty("transport", "http");
    });
  });

  describe("emitToolDiscovered", () => {
    it("should emit tool_discovered event with basic info", () => {
      const tool: Tool = {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {},
        },
      };
      emitToolDiscovered(tool);

      expect(emittedEvents[0]).toHaveProperty("event", "tool_discovered");
      expect(emittedEvents[0]).toHaveProperty("name", "test_tool");
      expect(emittedEvents[0]).toHaveProperty("description", "A test tool");
    });

    it("should handle tool without description", () => {
      const tool: Tool = {
        name: "no_desc_tool",
        inputSchema: { type: "object" },
      };
      emitToolDiscovered(tool);

      expect(emittedEvents[0]).toHaveProperty("name", "no_desc_tool");
      expect(emittedEvents[0]).toHaveProperty("description", null);
    });

    it("should extract parameters from inputSchema", () => {
      const tool: Tool = {
        name: "param_tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Search query" },
            limit: { type: "number" },
          },
          required: ["query"],
        },
      };
      emitToolDiscovered(tool);

      const params = emittedEvents[0].params as ToolParam[];
      expect(params.length).toBe(2);
      expect(params.find((p) => p.name === "query")).toMatchObject({
        name: "query",
        type: "string",
        required: true,
        description: "Search query",
      });
      expect(params.find((p) => p.name === "limit")).toMatchObject({
        name: "limit",
        type: "number",
        required: false,
      });
    });

    it("should include annotations when present", () => {
      const tool: Tool = {
        name: "annotated_tool",
        inputSchema: { type: "object" },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      };
      emitToolDiscovered(tool);

      const annotations = emittedEvents[0].annotations as Record<
        string,
        boolean
      >;
      expect(annotations).not.toBeNull();
      expect(annotations.readOnlyHint).toBe(true);
      expect(annotations.destructiveHint).toBe(false);
    });

    it("should have null annotations when not present", () => {
      const tool: Tool = {
        name: "no_annotations",
        inputSchema: { type: "object" },
      };
      emitToolDiscovered(tool);

      expect(emittedEvents[0].annotations).toBeNull();
    });
  });

  describe("emitToolsDiscoveryComplete", () => {
    it("should emit tools_discovery_complete with count", () => {
      emitToolsDiscoveryComplete(15);
      expect(emittedEvents[0]).toHaveProperty(
        "event",
        "tools_discovery_complete",
      );
      expect(emittedEvents[0]).toHaveProperty("count", 15);
    });

    it("should handle zero tools", () => {
      emitToolsDiscoveryComplete(0);
      expect(emittedEvents[0]).toHaveProperty("count", 0);
    });
  });

  describe("emitAssessmentComplete", () => {
    it("should emit assessment_complete with all fields", () => {
      emitAssessmentComplete("PASS", 1500, 120000, "/tmp/results.json");

      expect(emittedEvents[0]).toHaveProperty("event", "assessment_complete");
      expect(emittedEvents[0]).toHaveProperty("overallStatus", "PASS");
      expect(emittedEvents[0]).toHaveProperty("totalTests", 1500);
      expect(emittedEvents[0]).toHaveProperty("executionTime", 120000);
      expect(emittedEvents[0]).toHaveProperty(
        "outputPath",
        "/tmp/results.json",
      );
    });

    it("should handle FAIL status", () => {
      emitAssessmentComplete("FAIL", 200, 60000, "/tmp/fail.json");
      expect(emittedEvents[0]).toHaveProperty("overallStatus", "FAIL");
    });
  });

  describe("emitTestBatch", () => {
    it("should emit test_batch with progress info", () => {
      emitTestBatch("security", 100, 500, 50, 30000);

      expect(emittedEvents[0]).toHaveProperty("event", "test_batch");
      expect(emittedEvents[0]).toHaveProperty("module", "security");
      expect(emittedEvents[0]).toHaveProperty("completed", 100);
      expect(emittedEvents[0]).toHaveProperty("total", 500);
      expect(emittedEvents[0]).toHaveProperty("batchSize", 50);
      expect(emittedEvents[0]).toHaveProperty("elapsed", 30000);
    });

    it("should handle final batch", () => {
      emitTestBatch("functionality", 100, 100, 10, 5000);
      expect(emittedEvents[0]).toHaveProperty("completed", 100);
      expect(emittedEvents[0]).toHaveProperty("total", 100);
    });
  });

  describe("emitVulnerabilityFound", () => {
    it("should emit vulnerability_found with all fields", () => {
      emitVulnerabilityFound(
        "exec_tool",
        "Command Injection",
        "high",
        "Response executed shell command",
        "HIGH",
        true,
        "; rm -rf /",
      );

      expect(emittedEvents[0]).toHaveProperty("event", "vulnerability_found");
      expect(emittedEvents[0]).toHaveProperty("tool", "exec_tool");
      expect(emittedEvents[0]).toHaveProperty("pattern", "Command Injection");
      expect(emittedEvents[0]).toHaveProperty("confidence", "high");
      expect(emittedEvents[0]).toHaveProperty(
        "evidence",
        "Response executed shell command",
      );
      expect(emittedEvents[0]).toHaveProperty("riskLevel", "HIGH");
      expect(emittedEvents[0]).toHaveProperty("requiresReview", true);
      expect(emittedEvents[0]).toHaveProperty("payload", "; rm -rf /");
    });

    it("should omit payload when not provided", () => {
      emitVulnerabilityFound(
        "tool",
        "SQLi",
        "medium",
        "evidence",
        "MEDIUM",
        false,
      );
      expect(emittedEvents[0]).not.toHaveProperty("payload");
    });

    it("should handle different confidence levels", () => {
      emitVulnerabilityFound("t1", "p1", "high", "e1", "HIGH", true);
      emitVulnerabilityFound("t2", "p2", "medium", "e2", "MEDIUM", false);
      emitVulnerabilityFound("t3", "p3", "low", "e3", "LOW", false);

      expect(emittedEvents[0]).toHaveProperty("confidence", "high");
      expect(emittedEvents[1]).toHaveProperty("confidence", "medium");
      expect(emittedEvents[2]).toHaveProperty("confidence", "low");
    });
  });

  describe("emitAnnotationMissing", () => {
    it("should emit annotation_missing with tool info", () => {
      const params: ToolParam[] = [
        { name: "file", type: "string", required: true },
      ];
      emitAnnotationMissing(
        "delete_file",
        "Delete File",
        "Deletes a file",
        params,
        {
          expectedReadOnly: false,
          expectedDestructive: true,
          reason: "delete operation implies destructive",
        },
      );

      expect(emittedEvents[0]).toHaveProperty("event", "annotation_missing");
      expect(emittedEvents[0]).toHaveProperty("tool", "delete_file");
      expect(emittedEvents[0]).toHaveProperty("title", "Delete File");
      expect(emittedEvents[0]).toHaveProperty("description", "Deletes a file");
      expect(emittedEvents[0]).toHaveProperty("parameters", params);
      expect(emittedEvents[0]).toHaveProperty("inferredBehavior");
    });

    it("should omit optional fields when undefined", () => {
      emitAnnotationMissing("tool", undefined, undefined, [], {
        expectedReadOnly: true,
        expectedDestructive: false,
        reason: "test",
      });

      expect(emittedEvents[0]).not.toHaveProperty("title");
      expect(emittedEvents[0]).not.toHaveProperty("description");
    });
  });

  describe("emitAnnotationMisaligned", () => {
    it("should emit annotation_misaligned with all fields", () => {
      const params: ToolParam[] = [];
      emitAnnotationMisaligned(
        "write_tool",
        "Write Data",
        "Writes to disk",
        params,
        "readOnlyHint",
        true,
        false,
        0.95,
        "Tool performs write operations",
      );

      expect(emittedEvents[0]).toHaveProperty("event", "annotation_misaligned");
      expect(emittedEvents[0]).toHaveProperty("tool", "write_tool");
      expect(emittedEvents[0]).toHaveProperty("field", "readOnlyHint");
      expect(emittedEvents[0]).toHaveProperty("actual", true);
      expect(emittedEvents[0]).toHaveProperty("expected", false);
      expect(emittedEvents[0]).toHaveProperty("confidence", 0.95);
      expect(emittedEvents[0]).toHaveProperty(
        "reason",
        "Tool performs write operations",
      );
    });

    it("should handle undefined actual value", () => {
      emitAnnotationMisaligned(
        "tool",
        undefined,
        undefined,
        [],
        "destructiveHint",
        undefined,
        true,
        0.8,
        "reason",
      );
      // JSON.stringify omits undefined values, so the property won't exist
      expect(emittedEvents[0]).not.toHaveProperty("actual");
    });
  });

  describe("emitAnnotationReviewRecommended", () => {
    it("should emit annotation_review_recommended with all fields", () => {
      emitAnnotationReviewRecommended(
        "cache_tool",
        "Cache Manager",
        "Manages cache",
        [],
        "readOnlyHint",
        undefined,
        false,
        "medium",
        true,
        "Cache operations are ambiguous",
      );

      expect(emittedEvents[0]).toHaveProperty(
        "event",
        "annotation_review_recommended",
      );
      expect(emittedEvents[0]).toHaveProperty("tool", "cache_tool");
      expect(emittedEvents[0]).toHaveProperty("confidence", "medium");
      expect(emittedEvents[0]).toHaveProperty("isAmbiguous", true);
    });
  });

  describe("emitAnnotationAligned", () => {
    it("should emit annotation_aligned with annotations", () => {
      emitAnnotationAligned("read_tool", "high", {
        readOnlyHint: true,
        destructiveHint: false,
      });

      expect(emittedEvents[0]).toHaveProperty("event", "annotation_aligned");
      expect(emittedEvents[0]).toHaveProperty("tool", "read_tool");
      expect(emittedEvents[0]).toHaveProperty("confidence", "high");
      expect(emittedEvents[0]).toHaveProperty("annotations");
    });
  });

  describe("emitModulesConfigured", () => {
    it("should emit modules_configured with enabled and skipped", () => {
      emitModulesConfigured(
        ["security", "functionality"],
        ["temporal"],
        "skip-modules",
      );

      expect(emittedEvents[0]).toHaveProperty("event", "modules_configured");
      expect(emittedEvents[0]).toHaveProperty("enabled", [
        "security",
        "functionality",
      ]);
      expect(emittedEvents[0]).toHaveProperty("skipped", ["temporal"]);
      expect(emittedEvents[0]).toHaveProperty("reason", "skip-modules");
    });

    it("should handle only-modules reason", () => {
      emitModulesConfigured(["security"], [], "only-modules");
      expect(emittedEvents[0]).toHaveProperty("reason", "only-modules");
    });

    it("should handle default reason", () => {
      emitModulesConfigured(["security", "functionality"], [], "default");
      expect(emittedEvents[0]).toHaveProperty("reason", "default");
    });
  });
});

describe("extractToolParams", () => {
  it("should return empty array for null schema", () => {
    expect(extractToolParams(null)).toEqual([]);
  });

  it("should return empty array for undefined schema", () => {
    expect(extractToolParams(undefined)).toEqual([]);
  });

  it("should return empty array for non-object schema", () => {
    expect(extractToolParams("string")).toEqual([]);
  });

  it("should return empty array for schema without properties", () => {
    expect(extractToolParams({ type: "object" })).toEqual([]);
  });

  it("should extract parameters with all fields", () => {
    const schema = {
      type: "object",
      properties: {
        name: { type: "string", description: "User name" },
        age: { type: "number" },
      },
      required: ["name"],
    };

    const params = extractToolParams(schema);
    expect(params.length).toBe(2);

    const nameParam = params.find((p) => p.name === "name");
    expect(nameParam).toEqual({
      name: "name",
      type: "string",
      required: true,
      description: "User name",
    });

    const ageParam = params.find((p) => p.name === "age");
    expect(ageParam).toEqual({
      name: "age",
      type: "number",
      required: false,
    });
  });

  it("should handle schema without required array", () => {
    const schema = {
      type: "object",
      properties: {
        optional: { type: "string" },
      },
    };

    const params = extractToolParams(schema);
    expect(params[0].required).toBe(false);
  });

  it("should default to 'any' type when not specified", () => {
    const schema = {
      type: "object",
      properties: {
        unknown: {},
      },
    };

    const params = extractToolParams(schema);
    expect(params[0].type).toBe("any");
  });

  it("should not include description when not present", () => {
    const schema = {
      type: "object",
      properties: {
        simple: { type: "boolean" },
      },
    };

    const params = extractToolParams(schema);
    expect(params[0]).not.toHaveProperty("description");
  });
});
