/**
 * JSONL Event Emission Tests
 *
 * Regression tests for the JSONL progress output feature (v1.9.0).
 * Tests all 5 event types and the extractToolParams helper.
 */

import { jest } from "@jest/globals";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  emitJSONL,
  emitServerConnected,
  emitToolDiscovered,
  emitToolsDiscoveryComplete,
  emitAssessmentComplete,
  extractToolParams,
} from "../lib/jsonl-events";

describe("JSONL Event Helpers", () => {
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  // Helper to get the last emitted event
  function getLastEvent(): Record<string, unknown> {
    const lastCall = consoleErrorSpy.mock.calls[0];
    return JSON.parse(lastCall[0]);
  }

  // ========================================================================
  // emitJSONL
  // ========================================================================

  describe("emitJSONL", () => {
    it("emits valid JSON to stderr", () => {
      emitJSONL({ test: "value", number: 42 });

      expect(consoleErrorSpy).toHaveBeenCalledTimes(1);
      const output = consoleErrorSpy.mock.calls[0][0];
      expect(() => JSON.parse(output)).not.toThrow();
    });

    it("preserves all fields in output", () => {
      const event = { event: "test", field1: "value1", field2: 123 };
      emitJSONL(event);

      // Use toMatchObject since emitJSONL now adds version field automatically
      expect(getLastEvent()).toMatchObject(event);
    });

    it("includes version field in all events", () => {
      emitJSONL({ event: "test" });

      const output = getLastEvent();
      expect(output.version).toBeDefined();
    });

    it("includes schemaVersion field in all events", () => {
      emitJSONL({ event: "test" });

      const output = getLastEvent();
      expect(output.schemaVersion).toBe(1);
    });
  });

  // ========================================================================
  // emitServerConnected
  // ========================================================================

  describe("emitServerConnected", () => {
    it("emits valid JSON with event, serverName, transport", () => {
      emitServerConnected("test-server", "http");

      const event = getLastEvent();
      expect(event).toMatchObject({
        event: "server_connected",
        serverName: "test-server",
        transport: "http",
      });
      expect(event.version).toBeDefined();
    });

    it("handles stdio transport", () => {
      emitServerConnected("my-server", "stdio");

      const event = getLastEvent();
      expect(event.transport).toBe("stdio");
    });

    it("handles http transport", () => {
      emitServerConnected("my-server", "http");

      const event = getLastEvent();
      expect(event.transport).toBe("http");
    });

    it("handles sse transport", () => {
      emitServerConnected("my-server", "sse");

      const event = getLastEvent();
      expect(event.transport).toBe("sse");
    });
  });

  // ========================================================================
  // emitToolDiscovered
  // ========================================================================

  describe("emitToolDiscovered", () => {
    it("emits valid JSON with event, name, description, params", () => {
      const tool: Tool = {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
          required: ["query"],
        },
      };

      emitToolDiscovered(tool);

      const event = getLastEvent();
      expect(event.event).toBe("tool_discovered");
      expect(event.name).toBe("test_tool");
      expect(event.description).toBe("A test tool");
      expect(event.params).toEqual([
        { name: "query", type: "string", required: true },
      ]);
    });

    it("handles null description", () => {
      const tool: Tool = {
        name: "no_desc_tool",
        inputSchema: { type: "object", properties: {} },
      };

      emitToolDiscovered(tool);

      const event = getLastEvent();
      expect(event.description).toBeNull();
    });

    it("handles undefined description", () => {
      const tool: Tool = {
        name: "undefined_desc_tool",
        description: undefined,
        inputSchema: { type: "object", properties: {} },
      };

      emitToolDiscovered(tool);

      const event = getLastEvent();
      expect(event.description).toBeNull();
    });

    it("extracts required params correctly", () => {
      const tool: Tool = {
        name: "required_params_tool",
        inputSchema: {
          type: "object",
          properties: {
            required_field: { type: "string" },
            optional_field: { type: "number" },
          },
          required: ["required_field"],
        },
      };

      emitToolDiscovered(tool);

      const event = getLastEvent();
      const params = event.params as Array<{ name: string; required: boolean }>;
      const requiredParam = params.find((p) => p.name === "required_field");
      const optionalParam = params.find((p) => p.name === "optional_field");

      expect(requiredParam?.required).toBe(true);
      expect(optionalParam?.required).toBe(false);
    });

    it("includes param descriptions when present", () => {
      const tool: Tool = {
        name: "described_params_tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Search query text" },
            limit: { type: "number" },
          },
        },
      };

      emitToolDiscovered(tool);

      const event = getLastEvent();
      const params = event.params as Array<{
        name: string;
        description?: string;
      }>;
      const queryParam = params.find((p) => p.name === "query");
      const limitParam = params.find((p) => p.name === "limit");

      expect(queryParam?.description).toBe("Search query text");
      expect(limitParam?.description).toBeUndefined();
    });

    it("handles tools with no params", () => {
      const tool: Tool = {
        name: "no_params_tool",
        inputSchema: { type: "object" },
      };

      emitToolDiscovered(tool);

      const event = getLastEvent();
      expect(event.params).toEqual([]);
    });

    it("handles tools with empty properties", () => {
      const tool: Tool = {
        name: "empty_props_tool",
        inputSchema: { type: "object", properties: {} },
      };

      emitToolDiscovered(tool);

      const event = getLastEvent();
      expect(event.params).toEqual([]);
    });
  });

  // ========================================================================
  // emitToolsDiscoveryComplete
  // ========================================================================

  describe("emitToolsDiscoveryComplete", () => {
    it("emits valid JSON with event and count", () => {
      emitToolsDiscoveryComplete(17);

      const event = getLastEvent();
      expect(event).toMatchObject({
        event: "tools_discovery_complete",
        count: 17,
      });
      expect(event.version).toBeDefined();
    });

    it("handles zero tools", () => {
      emitToolsDiscoveryComplete(0);

      const event = getLastEvent();
      expect(event.count).toBe(0);
    });

    it("handles large tool counts", () => {
      emitToolsDiscoveryComplete(1000);

      const event = getLastEvent();
      expect(event.count).toBe(1000);
    });
  });

  // ========================================================================
  // emitAssessmentComplete
  // ========================================================================

  describe("emitAssessmentComplete", () => {
    it("emits valid JSON with all required fields", () => {
      emitAssessmentComplete("PASS", 234, 5000, "/tmp/results.json");

      const event = getLastEvent();
      expect(event).toMatchObject({
        event: "assessment_complete",
        overallStatus: "PASS",
        totalTests: 234,
        executionTime: 5000,
        outputPath: "/tmp/results.json",
      });
      expect(event.version).toBeDefined();
    });

    it("includes correct overallStatus for PASS", () => {
      emitAssessmentComplete("PASS", 100, 1000, "/tmp/pass.json");

      const event = getLastEvent();
      expect(event.overallStatus).toBe("PASS");
    });

    it("includes correct overallStatus for FAIL", () => {
      emitAssessmentComplete("FAIL", 100, 1000, "/tmp/fail.json");

      const event = getLastEvent();
      expect(event.overallStatus).toBe("FAIL");
    });

    it("includes totalTests count", () => {
      emitAssessmentComplete("PASS", 728, 10000, "/tmp/results.json");

      const event = getLastEvent();
      expect(event.totalTests).toBe(728);
    });

    it("includes executionTime in ms", () => {
      emitAssessmentComplete("PASS", 100, 19287, "/tmp/results.json");

      const event = getLastEvent();
      expect(event.executionTime).toBe(19287);
    });

    it("includes correct outputPath", () => {
      const outputPath = "/tmp/inspector-full-assessment-my-server.json";
      emitAssessmentComplete("PASS", 100, 1000, outputPath);

      const event = getLastEvent();
      expect(event.outputPath).toBe(outputPath);
    });
  });

  // ========================================================================
  // extractToolParams
  // ========================================================================

  describe("extractToolParams", () => {
    it("extracts params from valid inputSchema", () => {
      const schema = {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          limit: { type: "number" },
        },
        required: ["query"],
      };

      const params = extractToolParams(schema);

      expect(params).toEqual([
        {
          name: "query",
          type: "string",
          required: true,
          description: "Search query",
        },
        { name: "limit", type: "number", required: false },
      ]);
    });

    it("handles missing properties", () => {
      const schema = { type: "object" };

      const params = extractToolParams(schema);

      expect(params).toEqual([]);
    });

    it("handles missing required array", () => {
      const schema = {
        type: "object",
        properties: {
          field1: { type: "string" },
        },
      };

      const params = extractToolParams(schema);

      expect(params).toEqual([
        { name: "field1", type: "string", required: false },
      ]);
    });

    it("handles null schema", () => {
      const params = extractToolParams(null);

      expect(params).toEqual([]);
    });

    it("handles undefined schema", () => {
      const params = extractToolParams(undefined);

      expect(params).toEqual([]);
    });

    it("handles empty properties object", () => {
      const schema = {
        type: "object",
        properties: {},
        required: [],
      };

      const params = extractToolParams(schema);

      expect(params).toEqual([]);
    });

    it("handles missing type in property", () => {
      const schema = {
        type: "object",
        properties: {
          noTypeField: { description: "Field without type" },
        },
      };

      const params = extractToolParams(schema);

      expect(params).toEqual([
        {
          name: "noTypeField",
          type: "any",
          required: false,
          description: "Field without type",
        },
      ]);
    });

    it("handles non-object schema", () => {
      const params = extractToolParams("not an object");

      expect(params).toEqual([]);
    });

    it("handles array in required field", () => {
      const schema = {
        type: "object",
        properties: {
          a: { type: "string" },
          b: { type: "string" },
          c: { type: "string" },
        },
        required: ["a", "c"],
      };

      const params = extractToolParams(schema);

      expect(params).toContainEqual({
        name: "a",
        type: "string",
        required: true,
      });
      expect(params).toContainEqual({
        name: "b",
        type: "string",
        required: false,
      });
      expect(params).toContainEqual({
        name: "c",
        type: "string",
        required: true,
      });
    });
  });
});

// ============================================================================
// Valid JSON Output Tests
// ============================================================================

describe("Valid JSON Output", () => {
  let consoleErrorSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  it("all events produce valid JSON that can be parsed", () => {
    // Emit all event types
    emitServerConnected("test", "http");
    emitToolDiscovered({
      name: "test",
      inputSchema: { type: "object", properties: { x: { type: "string" } } },
    });
    emitToolsDiscoveryComplete(1);
    emitAssessmentComplete("PASS", 10, 100, "/tmp/test.json");

    // Verify all outputs are valid JSON
    for (const call of consoleErrorSpy.mock.calls) {
      const output = call[0];
      expect(() => JSON.parse(output)).not.toThrow();
    }
  });

  it("all events have event field", () => {
    emitServerConnected("test", "http");
    emitToolDiscovered({ name: "test", inputSchema: { type: "object" } });
    emitToolsDiscoveryComplete(1);
    emitAssessmentComplete("PASS", 10, 100, "/tmp/test.json");

    for (const call of consoleErrorSpy.mock.calls) {
      const event = JSON.parse(call[0]);
      expect(event).toHaveProperty("event");
      expect(typeof event.event).toBe("string");
    }
  });

  it("event types are correct for each function", () => {
    emitServerConnected("test", "http");
    emitToolDiscovered({ name: "test", inputSchema: { type: "object" } });
    emitToolsDiscoveryComplete(1);
    emitAssessmentComplete("PASS", 10, 100, "/tmp/test.json");

    const events = consoleErrorSpy.mock.calls.map((call) =>
      JSON.parse(call[0]),
    );

    expect(events[0].event).toBe("server_connected");
    expect(events[1].event).toBe("tool_discovered");
    expect(events[2].event).toBe("tools_discovery_complete");
    expect(events[3].event).toBe("assessment_complete");
  });
});
