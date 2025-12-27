/**
 * TemporalAssessor Test Suite
 * Tests rug pull vulnerability detection through temporal behavior analysis
 */

import { TemporalAssessor } from "../modules/TemporalAssessor";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { AssessmentContext } from "../AssessmentOrchestrator";

// Helper to access private methods
const getPrivateMethod = <T>(instance: T, methodName: string) => {
  return (instance as any)[methodName].bind(instance);
};

// Default test configuration
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  testTimeout: 5000,
  skipBrokenTools: false,
  delayBetweenTests: 0,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
    temporal: true,
  },
  temporalInvocations: 5, // Small number for fast tests
  ...overrides,
});

// Mock tool factory
const createTool = (
  name: string,
  schema: Record<string, unknown> = {},
): Tool => ({
  name,
  description: `Test tool: ${name}`,
  inputSchema: {
    type: "object",
    properties: {},
    required: [],
    ...schema,
  },
});

// Mock context factory
const createMockContext = (
  tools: Tool[],
  callToolFn: (name: string, args: unknown) => Promise<unknown>,
): AssessmentContext =>
  ({
    tools,
    callTool: callToolFn,
  }) as unknown as AssessmentContext;

describe("TemporalAssessor", () => {
  describe("normalizeResponse", () => {
    let assessor: TemporalAssessor;
    let normalizeResponse: (response: unknown) => string;

    beforeEach(() => {
      assessor = new TemporalAssessor(createConfig());
      normalizeResponse = getPrivateMethod(assessor, "normalizeResponse");
    });

    it("normalizes ISO timestamps", () => {
      const input = { timestamp: "2025-12-27T10:30:00.123Z" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<TIMESTAMP>"');
      expect(result).not.toContain("2025-12-27");
    });

    it("normalizes ISO timestamps without Z suffix", () => {
      const input = { time: "2025-01-15T08:45:30.999" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<TIMESTAMP>"');
      expect(result).not.toContain("2025-01-15");
    });

    it("normalizes unix timestamps (13-digit)", () => {
      const input = { ts: "1735294200000" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<TIMESTAMP>"');
      expect(result).not.toContain("1735294200000");
    });

    it("normalizes UUIDs (lowercase)", () => {
      // Use a field name other than 'id' to avoid string ID normalization
      const input = { uuid: "550e8400-e29b-41d4-a716-446655440000" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<UUID>"');
      expect(result).not.toContain("550e8400");
    });

    it("normalizes UUIDs (uppercase)", () => {
      const input = { uuid: "550E8400-E29B-41D4-A716-446655440000" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<UUID>"');
      expect(result).not.toContain("550E8400");
    });

    it("normalizes numeric id fields", () => {
      const input = { id: 12345 };
      const result = normalizeResponse(input);
      expect(result).toContain('"id": <NUMBER>');
      expect(result).not.toContain("12345");
    });

    it("normalizes Id fields (capitalized)", () => {
      const input = { userId: 99, Id: 42 };
      const result = normalizeResponse(input);
      expect(result).toContain('"Id": <NUMBER>');
    });

    it("normalizes nested JSON with escaped quotes", () => {
      // Simulates MCP response with JSON in content[].text
      const input = {
        content: [{ text: '{"id": 42, "count": 10}' }],
      };
      const result = normalizeResponse(input);
      // The escaped JSON should have normalized numbers
      expect(result).toContain('\\"id\\": <NUMBER>');
      expect(result).toContain('\\"count\\": <NUMBER>');
    });

    it("normalizes counter fields (total_items)", () => {
      const input = { total_items: 100 };
      const result = normalizeResponse(input);
      expect(result).toContain('"total_items": <NUMBER>');
      expect(result).not.toContain("100");
    });

    it("normalizes counter fields (count)", () => {
      const input = { count: 5 };
      const result = normalizeResponse(input);
      expect(result).toContain('"count": <NUMBER>');
    });

    it("normalizes counter fields (invocation_count)", () => {
      const input = { invocation_count: 25 };
      const result = normalizeResponse(input);
      expect(result).toContain('"invocation_count": <NUMBER>');
    });

    it("normalizes counter fields (sequence)", () => {
      const input = { sequence: 3 };
      const result = normalizeResponse(input);
      expect(result).toContain('"sequence": <NUMBER>');
    });

    it("normalizes counter fields (index)", () => {
      const input = { index: 0 };
      const result = normalizeResponse(input);
      expect(result).toContain('"index": <NUMBER>');
    });

    it("normalizes request_id fields", () => {
      const input = { request_id: "req-abc123-xyz" };
      const result = normalizeResponse(input);
      expect(result).toContain('"request_id": "<ID>"');
      expect(result).not.toContain("abc123");
    });

    it("normalizes requestId fields (camelCase)", () => {
      const input = { requestId: "REQ-12345" };
      const result = normalizeResponse(input);
      expect(result).toContain('"requestId": "<ID>"');
    });

    it("normalizes trace_id fields", () => {
      const input = { trace_id: "trace-xyz-789" };
      const result = normalizeResponse(input);
      expect(result).toContain('"trace_id": "<ID>"');
    });

    it("normalizes string id fields", () => {
      const input = { id: "user_abc123" };
      const result = normalizeResponse(input);
      expect(result).toContain('"id": "<ID>"');
    });

    it("preserves non-varying data", () => {
      const input = { status: "success", message: "Operation completed" };
      const result = normalizeResponse(input);
      expect(result).toContain('"status":"success"');
      expect(result).toContain('"message":"Operation completed"');
    });

    it("handles null", () => {
      // null serializes to "null" string
      expect(() => normalizeResponse(null)).not.toThrow();
      expect(normalizeResponse(null)).toBe("null");
    });

    it("handles empty objects and arrays", () => {
      expect(normalizeResponse({})).toBe("{}");
      expect(normalizeResponse([])).toBe("[]");
    });
  });

  describe("analyzeResponses", () => {
    let assessor: TemporalAssessor;
    let analyzeResponses: (
      tool: Tool,
      responses: Array<{
        invocation: number;
        response: unknown;
        error?: string;
        timestamp: number;
      }>,
    ) => any;

    beforeEach(() => {
      assessor = new TemporalAssessor(createConfig());
      analyzeResponses = getPrivateMethod(assessor, "analyzeResponses");
    });

    it("returns not vulnerable when all responses match", () => {
      const tool = createTool("test_tool");
      const responses = Array(5)
        .fill(null)
        .map((_, i) => ({
          invocation: i + 1,
          response: { result: "same" },
          timestamp: Date.now(),
        }));

      const result = analyzeResponses(tool, responses);

      expect(result.vulnerable).toBe(false);
      expect(result.deviationCount).toBe(0);
      expect(result.errorCount).toBe(0);
      expect(result.pattern).toBeNull();
      expect(result.severity).toBe("NONE");
    });

    it("detects deviation at specific invocation", () => {
      const tool = createTool("test_tool");
      const responses = [
        { invocation: 1, response: { result: "safe" }, timestamp: 1 },
        { invocation: 2, response: { result: "safe" }, timestamp: 2 },
        { invocation: 3, response: { result: "malicious!" }, timestamp: 3 },
        { invocation: 4, response: { result: "malicious!" }, timestamp: 4 },
      ];

      const result = analyzeResponses(tool, responses);

      expect(result.vulnerable).toBe(true);
      expect(result.firstDeviationAt).toBe(3);
      expect(result.deviationCount).toBe(2);
      expect(result.pattern).toBe("RUG_PULL_TEMPORAL");
      expect(result.severity).toBe("HIGH");
    });

    it("treats errors as deviations", () => {
      const tool = createTool("test_tool");
      const responses = [
        { invocation: 1, response: { result: "ok" }, timestamp: 1 },
        {
          invocation: 2,
          response: null,
          error: "Connection refused",
          timestamp: 2,
        },
      ];

      const result = analyzeResponses(tool, responses);

      expect(result.vulnerable).toBe(true);
      expect(result.firstDeviationAt).toBe(2);
      expect(result.errorCount).toBe(1);
      expect(result.deviationCount).toBe(1);
    });

    it("handles empty responses array", () => {
      const tool = createTool("test_tool");
      const result = analyzeResponses(tool, []);

      expect(result.vulnerable).toBe(false);
      expect(result.totalInvocations).toBe(0);
      expect(result.firstDeviationAt).toBeNull();
    });

    it("includes safe and malicious examples in evidence", () => {
      const tool = createTool("test_tool");
      const responses = [
        { invocation: 1, response: { safe: true }, timestamp: 1 },
        { invocation: 2, response: { safe: true }, timestamp: 2 },
        { invocation: 3, response: { malicious: true }, timestamp: 3 },
      ];

      const result = analyzeResponses(tool, responses);

      expect(result.evidence).toBeDefined();
      expect(result.evidence.safeResponseExample).toEqual({ safe: true });
      expect(result.evidence.maliciousResponseExample).toEqual({
        malicious: true,
      });
    });

    it("does not include evidence when not vulnerable", () => {
      const tool = createTool("test_tool");
      const responses = [
        { invocation: 1, response: { ok: true }, timestamp: 1 },
        { invocation: 2, response: { ok: true }, timestamp: 2 },
      ];

      const result = analyzeResponses(tool, responses);

      expect(result.evidence).toBeUndefined();
    });

    it("handles single response (no deviations possible)", () => {
      const tool = createTool("test_tool");
      const responses = [
        { invocation: 1, response: { result: "only one" }, timestamp: 1 },
      ];

      const result = analyzeResponses(tool, responses);

      expect(result.vulnerable).toBe(false);
      expect(result.totalInvocations).toBe(1);
    });

    it("ignores naturally varying data in comparisons", () => {
      const tool = createTool("test_tool");
      const responses = [
        {
          invocation: 1,
          response: { id: 1, timestamp: "2025-01-01T00:00:00Z" },
          timestamp: 1,
        },
        {
          invocation: 2,
          response: { id: 2, timestamp: "2025-01-01T00:00:01Z" },
          timestamp: 2,
        },
        {
          invocation: 3,
          response: { id: 3, timestamp: "2025-01-01T00:00:02Z" },
          timestamp: 3,
        },
      ];

      const result = analyzeResponses(tool, responses);

      // Should NOT be flagged as vulnerable because IDs and timestamps are normalized
      expect(result.vulnerable).toBe(false);
    });
  });

  describe("generateSafePayload", () => {
    let assessor: TemporalAssessor;
    let generateSafePayload: (tool: Tool) => Record<string, unknown>;

    beforeEach(() => {
      assessor = new TemporalAssessor(createConfig());
      generateSafePayload = getPrivateMethod(assessor, "generateSafePayload");
    });

    it("generates test string for string properties", () => {
      const tool = createTool("tool", {
        properties: { name: { type: "string" } },
        required: ["name"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ name: "test" });
    });

    it("generates 1 for number properties", () => {
      const tool = createTool("tool", {
        properties: { count: { type: "number" } },
        required: ["count"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ count: 1 });
    });

    it("generates 1 for integer properties", () => {
      const tool = createTool("tool", {
        properties: { age: { type: "integer" } },
        required: ["age"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ age: 1 });
    });

    it("generates false for boolean properties", () => {
      const tool = createTool("tool", {
        properties: { active: { type: "boolean" } },
        required: ["active"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ active: false });
    });

    it("generates empty array for array properties", () => {
      const tool = createTool("tool", {
        properties: { items: { type: "array" } },
        required: ["items"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ items: [] });
    });

    it("generates empty object for object properties", () => {
      const tool = createTool("tool", {
        properties: { config: { type: "object" } },
        required: ["config"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ config: {} });
    });

    it("only populates required properties", () => {
      const tool = createTool("tool", {
        properties: {
          required_param: { type: "string" },
          optional_param: { type: "string" },
        },
        required: ["required_param"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ required_param: "test" });
      expect(result).not.toHaveProperty("optional_param");
    });

    it("returns empty payload for empty schema", () => {
      const tool = createTool("tool", {});

      const result = generateSafePayload(tool);

      expect(result).toEqual({});
    });

    it("returns empty payload for no required properties", () => {
      const tool = createTool("tool", {
        properties: {
          optional1: { type: "string" },
          optional2: { type: "number" },
        },
        required: [],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({});
    });

    it("handles unknown types as string", () => {
      const tool = createTool("tool", {
        properties: { custom: { type: "custom_type" } },
        required: ["custom"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({ custom: "test" });
    });

    it("handles multiple required properties", () => {
      const tool = createTool("tool", {
        properties: {
          name: { type: "string" },
          count: { type: "number" },
          active: { type: "boolean" },
        },
        required: ["name", "count", "active"],
      });

      const result = generateSafePayload(tool);

      expect(result).toEqual({
        name: "test",
        count: 1,
        active: false,
      });
    });
  });

  describe("isDestructiveTool", () => {
    let assessor: TemporalAssessor;
    let isDestructiveTool: (tool: Tool) => boolean;

    beforeEach(() => {
      assessor = new TemporalAssessor(createConfig());
      isDestructiveTool = getPrivateMethod(assessor, "isDestructiveTool");
    });

    const DESTRUCTIVE_PATTERNS = [
      "create",
      "write",
      "delete",
      "remove",
      "update",
      "insert",
      "post",
      "put",
      "send",
      "submit",
      "execute",
      "run",
    ];

    DESTRUCTIVE_PATTERNS.forEach((pattern) => {
      it(`detects "${pattern}" as destructive`, () => {
        const tool = createTool(`${pattern}_something`);
        expect(isDestructiveTool(tool)).toBe(true);
      });

      it(`detects "${pattern}" at end of name as destructive`, () => {
        const tool = createTool(`something_${pattern}`);
        expect(isDestructiveTool(tool)).toBe(true);
      });
    });

    it("is case insensitive", () => {
      expect(isDestructiveTool(createTool("CreateUser"))).toBe(true);
      expect(isDestructiveTool(createTool("DELETE_ITEM"))).toBe(true);
      expect(isDestructiveTool(createTool("PostMessage"))).toBe(true);
    });

    it("returns false for read-only tools", () => {
      expect(isDestructiveTool(createTool("get_user"))).toBe(false);
      expect(isDestructiveTool(createTool("list_items"))).toBe(false);
      expect(isDestructiveTool(createTool("read_file"))).toBe(false);
      expect(isDestructiveTool(createTool("fetch_data"))).toBe(false);
      expect(isDestructiveTool(createTool("search_records"))).toBe(false);
    });

    it("returns false for query tools", () => {
      expect(isDestructiveTool(createTool("query_database"))).toBe(false);
      expect(isDestructiveTool(createTool("find_users"))).toBe(false);
      expect(isDestructiveTool(createTool("count_items"))).toBe(false);
    });

    it("detects destructive patterns anywhere in name", () => {
      expect(isDestructiveTool(createTool("bulk_delete_users"))).toBe(true);
      expect(isDestructiveTool(createTool("async_update_config"))).toBe(true);
    });
  });

  describe("assess - integration", () => {
    it("returns PASS when all tools have consistent behavior", async () => {
      const config = createConfig({ temporalInvocations: 5 });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("safe_tool")];
      const context = createMockContext(tools, async () => ({ result: "ok" }));

      const result = await assessor.assess(context);

      expect(result.status).toBe("PASS");
      expect(result.rugPullsDetected).toBe(0);
      expect(result.toolsTested).toBe(1);
      expect(result.invocationsPerTool).toBe(5);
    });

    it("returns FAIL when rug pull detected", async () => {
      const config = createConfig({ temporalInvocations: 15 });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("rug_pull_tool")];

      let callCount = 0;
      const context = createMockContext(tools, async () => {
        callCount++;
        return callCount <= 10 ? { safe: true } : { malicious: true };
      });

      const result = await assessor.assess(context);

      expect(result.status).toBe("FAIL");
      expect(result.rugPullsDetected).toBe(1);
      expect(result.details[0].vulnerable).toBe(true);
      expect(result.details[0].firstDeviationAt).toBe(11);
    });

    it("returns NEED_MORE_INFO when no tools to test", async () => {
      const config = createConfig();
      const assessor = new TemporalAssessor(config);
      const context = createMockContext([], async () => ({}));

      const result = await assessor.assess(context);

      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.toolsTested).toBe(0);
    });

    it("only tests selected tools when configured", async () => {
      const config = createConfig({
        temporalInvocations: 3,
        selectedToolsForTesting: ["tool_a"],
      });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("tool_a"), createTool("tool_b")];

      let toolsCalled: string[] = [];
      const context = createMockContext(tools, async (name: string) => {
        toolsCalled.push(name);
        return { ok: true };
      });

      await assessor.assess(context);

      // Only tool_a should have been called
      expect(toolsCalled.every((t) => t === "tool_a")).toBe(true);
      expect(toolsCalled.includes("tool_b")).toBe(false);
    });

    it("uses reduced invocations for destructive tools", async () => {
      const config = createConfig({ temporalInvocations: 25 });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("delete_item")];

      let invocationCount = 0;
      const context = createMockContext(tools, async () => {
        invocationCount++;
        return { deleted: true };
      });

      await assessor.assess(context);

      // Destructive tools should have max 5 invocations
      expect(invocationCount).toBeLessThanOrEqual(5);
    });

    it("handles tool errors gracefully", async () => {
      const config = createConfig({ temporalInvocations: 5 });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("error_tool")];

      let callCount = 0;
      const context = createMockContext(tools, async () => {
        callCount++;
        if (callCount === 3) {
          throw new Error("Connection timeout");
        }
        return { ok: true };
      });

      const result = await assessor.assess(context);

      // Error on 3rd call should be treated as deviation
      expect(result.details[0].errorCount).toBe(1);
      expect(result.details[0].vulnerable).toBe(true);
    });

    it("generates recommendations for vulnerable tools", async () => {
      const config = createConfig({ temporalInvocations: 5 });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("bad_tool")];

      let callCount = 0;
      const context = createMockContext(tools, async () => {
        callCount++;
        return callCount <= 2 ? { safe: true } : { unsafe: true };
      });

      const result = await assessor.assess(context);

      expect(result.recommendations.length).toBeGreaterThan(0);
      expect(result.recommendations.some((r) => r.includes("bad_tool"))).toBe(
        true,
      );
    });

    it("tracks test count correctly", async () => {
      const config = createConfig({ temporalInvocations: 5 });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("tool_a"), createTool("tool_b")];
      const context = createMockContext(tools, async () => ({ ok: true }));

      await assessor.assess(context);

      // 2 tools * 5 invocations = 10 tests
      expect(assessor.getTestCount()).toBe(10);
    });
  });

  describe("edge cases", () => {
    it("handles tools with no inputSchema", async () => {
      const config = createConfig({ temporalInvocations: 3 });
      const assessor = new TemporalAssessor(config);
      const tool: Tool = {
        name: "minimal_tool",
        description: "Minimal tool",
        inputSchema: { type: "object" },
      };
      const context = createMockContext([tool], async () => ({ ok: true }));

      const result = await assessor.assess(context);

      expect(result.status).toBe("PASS");
    });

    it("handles responses with complex nested structures", async () => {
      const config = createConfig({ temporalInvocations: 3 });
      const assessor = new TemporalAssessor(config);
      const tools = [createTool("complex_tool")];

      const complexResponse = {
        data: {
          users: [
            { id: 1, name: "Alice" },
            { id: 2, name: "Bob" },
          ],
          metadata: {
            timestamp: "2025-01-01T00:00:00Z",
            requestId: "req-123",
          },
        },
      };

      const context = createMockContext(tools, async () =>
        JSON.parse(JSON.stringify(complexResponse)),
      );

      const result = await assessor.assess(context);

      expect(result.status).toBe("PASS");
    });
  });
});
