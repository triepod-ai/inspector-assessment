/**
 * TemporalAssessor Test Suite (Core)
 *
 * Tests rug pull vulnerability detection through temporal behavior analysis.
 *
 * This is the core test file containing:
 * - analyzeResponses: Core deviation detection logic
 * - generateSafePayload: Safe test data generation
 * - isDestructiveTool: Destructive tool detection
 * - assess (integration): End-to-end assessment tests
 * - edge cases: Unusual but valid scenarios
 *
 * Related test files:
 * - TemporalAssessor-StatefulTools.test.ts: Stateful tool handling (31 tests)
 * - TemporalAssessor-SecondaryContent.test.ts: Rug pull content detection (39 tests)
 * - TemporalAssessor-DefinitionMutation.test.ts: Definition mutation tracking (13 tests)
 * - TemporalAssessor-VarianceClassification.test.ts: Resource-creating variance (15 tests)
 * - TemporalAssessor-ResponseNormalization.test.ts: Response normalization (23 tests)
 */

import { TemporalAssessor } from "../modules/TemporalAssessor";
import { VarianceClassifier } from "../modules/temporal";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  getPrivateMethod,
  createConfig,
  createTool,
  createMockContext,
} from "@/test/utils/testUtils";

describe("TemporalAssessor", () => {
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
    ) => unknown;

    beforeEach(() => {
      assessor = new TemporalAssessor(createConfig());
      analyzeResponses = getPrivateMethod(assessor, "analyzeResponses");
    });

    afterEach(() => {
      jest.clearAllMocks();
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

      const result = analyzeResponses(tool, responses) as {
        vulnerable: boolean;
        deviationCount: number;
        errorCount: number;
        pattern: string | null;
        severity: string;
      };

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

      const result = analyzeResponses(tool, responses) as {
        vulnerable: boolean;
        firstDeviationAt: number;
        deviationCount: number;
        pattern: string;
        severity: string;
      };

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

      const result = analyzeResponses(tool, responses) as {
        vulnerable: boolean;
        firstDeviationAt: number;
        errorCount: number;
        deviationCount: number;
      };

      expect(result.vulnerable).toBe(true);
      expect(result.firstDeviationAt).toBe(2);
      expect(result.errorCount).toBe(1);
      expect(result.deviationCount).toBe(1);
    });

    it("handles empty responses array", () => {
      const tool = createTool("test_tool");
      const result = analyzeResponses(tool, []) as {
        vulnerable: boolean;
        totalInvocations: number;
        firstDeviationAt: number | null;
      };

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

      const result = analyzeResponses(tool, responses) as {
        evidence: {
          safeResponseExample: unknown;
          maliciousResponseExample: unknown;
        };
      };

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

      const result = analyzeResponses(tool, responses) as {
        evidence: unknown;
      };

      expect(result.evidence).toBeUndefined();
    });

    it("handles single response (no deviations possible)", () => {
      const tool = createTool("test_tool");
      const responses = [
        { invocation: 1, response: { result: "only one" }, timestamp: 1 },
      ];

      const result = analyzeResponses(tool, responses) as {
        vulnerable: boolean;
        totalInvocations: number;
      };

      expect(result.vulnerable).toBe(false);
      expect(result.totalInvocations).toBe(1);
    });

    // Issue: add_observations should use schema comparison (stateful accumulation)
    it("passes accumulation operations with incrementing counters (schema comparison)", () => {
      const tool = createTool("add_observations");
      const responses = [
        {
          invocation: 1,
          response: { addedObservations: ["obs1"], total_observations: 1 },
          timestamp: 1,
        },
        {
          invocation: 2,
          response: { addedObservations: ["obs2"], total_observations: 2 },
          timestamp: 2,
        },
        {
          invocation: 3,
          response: { addedObservations: ["obs3"], total_observations: 3 },
          timestamp: 3,
        },
      ];

      const result = analyzeResponses(tool, responses) as {
        vulnerable: boolean;
        note: string;
      };

      // Should pass because add_observations is stateful (schema comparison)
      expect(result.vulnerable).toBe(false);
      expect(result.note).toBe(
        "Stateful tool - content variation expected, schema consistent",
      );
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

      const result = analyzeResponses(tool, responses) as {
        vulnerable: boolean;
      };

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
    let varianceClassifier: VarianceClassifier;
    let isDestructiveTool: (tool: Tool) => boolean;

    beforeEach(() => {
      varianceClassifier = new VarianceClassifier();
      isDestructiveTool = (tool: Tool) =>
        varianceClassifier.isDestructiveTool(tool);
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

      const toolsCalled: string[] = [];
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
