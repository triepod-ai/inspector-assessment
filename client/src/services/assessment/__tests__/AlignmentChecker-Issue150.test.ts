/**
 * AlignmentChecker Issue #150 Tests
 *
 * Tests annotation extraction with non-suffixed property names.
 * Some MCP servers use `readOnly` instead of `readOnlyHint`, and `destructive`
 * instead of `destructiveHint`. This test ensures both formats are detected.
 *
 * @group unit
 * @group annotations
 * @group issue-150
 */

import { extractAnnotations } from "../modules/annotations/AlignmentChecker";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("extractAnnotations - Issue #150", () => {
  describe("annotations object", () => {
    it("should detect readOnlyHint (standard MCP spec)", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnlyHint: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should detect readOnly (non-suffixed fallback)", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnly: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should prioritize readOnlyHint over readOnly when both present", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnlyHint: false, readOnly: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(false); // *Hint takes priority
    });

    it("should detect destructiveHint (standard MCP spec)", () => {
      const tool = {
        name: "delete_user",
        description: "Deletes user",
        inputSchema: { type: "object", properties: {} },
        annotations: { destructiveHint: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.destructiveHint).toBe(true);
    });

    it("should detect destructive (non-suffixed fallback)", () => {
      const tool = {
        name: "delete_user",
        description: "Deletes user",
        inputSchema: { type: "object", properties: {} },
        annotations: { destructive: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.destructiveHint).toBe(true);
    });

    it("should detect all four annotation types without suffix", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: {
          readOnly: true,
          destructive: false,
          idempotent: true,
          openWorld: false,
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(false);
      expect(result.idempotentHint).toBe(true);
      expect(result.openWorldHint).toBe(false);
      expect(result.source).toBe("mcp");
    });

    it("should handle false values correctly (not undefined)", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnly: false },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(false);
      expect(result.source).toBe("mcp");
    });
  });

  describe("direct properties", () => {
    it("should detect readOnly on tool directly", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        readOnly: true,
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should detect destructive on tool directly", () => {
      const tool = {
        name: "delete_tool",
        description: "Deletes",
        inputSchema: { type: "object", properties: {} },
        destructive: true,
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.destructiveHint).toBe(true);
    });

    it("should detect readOnlyHint on tool directly (standard)", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        readOnlyHint: true,
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });
  });

  describe("metadata object", () => {
    it("should detect readOnly in metadata", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        metadata: { readOnly: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should detect destructive in metadata", () => {
      const tool = {
        name: "delete_tool",
        description: "Deletes",
        inputSchema: { type: "object", properties: {} },
        metadata: { destructive: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.destructiveHint).toBe(true);
    });

    it("should detect readOnlyHint in metadata (standard)", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        metadata: { readOnlyHint: true },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });
  });

  describe("priority order", () => {
    it("should prefer annotations object over direct properties", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnly: true },
        readOnly: false,
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true); // From annotations
    });

    it("should prefer direct properties over metadata", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        readOnly: true,
        metadata: { readOnly: false },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true); // From direct
    });
  });

  describe("no annotations", () => {
    it("should return source: none when no annotations present", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.source).toBe("none");
      expect(result.readOnlyHint).toBeUndefined();
      expect(result.destructiveHint).toBeUndefined();
    });

    it("should return source: none when annotations object is empty", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: {},
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.source).toBe("none");
    });
  });

  describe("Tomba MCP real-world scenario", () => {
    it("should correctly detect 100% coverage for Tomba-style annotations", () => {
      // Simulating Tomba MCP tools with readOnly: true (not readOnlyHint)
      const tools = [
        {
          name: "tomba_domain_search",
          description: "Search domain for emails",
          inputSchema: {
            type: "object",
            properties: { domain: { type: "string" } },
          },
          annotations: { readOnly: true },
        },
        {
          name: "tomba_email_finder",
          description: "Find email by name",
          inputSchema: {
            type: "object",
            properties: { name: { type: "string" } },
          },
          annotations: { readOnly: true },
        },
        {
          name: "tomba_email_verifier",
          description: "Verify email address",
          inputSchema: {
            type: "object",
            properties: { email: { type: "string" } },
          },
          annotations: { readOnly: true },
        },
      ] as unknown as Tool[];

      const results = tools.map(extractAnnotations);

      // All tools should be detected as annotated
      expect(results.every((r) => r.source === "mcp")).toBe(true);
      expect(results.every((r) => r.readOnlyHint === true)).toBe(true);

      // Calculate coverage like the module does
      const annotatedCount = results.filter(
        (r) => r.readOnlyHint !== undefined || r.destructiveHint !== undefined,
      ).length;
      const coverage = (annotatedCount / tools.length) * 100;

      expect(coverage).toBe(100); // Was 0% before fix
    });
  });

  describe("mixed format scenarios", () => {
    it("should handle tool with readOnlyHint and destructive (mixed)", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: {
          readOnlyHint: true,
          destructive: false, // Non-suffixed
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(false);
      expect(result.source).toBe("mcp");
    });
  });

  describe("malformed input handling", () => {
    it("should ignore non-boolean string values", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnly: "true" }, // String instead of boolean
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      // Non-boolean values are ignored (type validation)
      expect(result.readOnlyHint).toBeUndefined();
      expect(result.source).toBe("none");
    });

    it("should ignore numeric values", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnly: 1, destructive: 0 }, // Numbers instead of booleans
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      // Non-boolean values are ignored (type validation)
      expect(result.readOnlyHint).toBeUndefined();
      expect(result.destructiveHint).toBeUndefined();
      expect(result.source).toBe("none");
    });

    it("should ignore null values", () => {
      const tool = {
        name: "test_tool",
        description: "Test",
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnly: null },
      } as unknown as Tool;

      const result = extractAnnotations(tool);
      expect(result.readOnlyHint).toBeUndefined();
      expect(result.source).toBe("none");
    });
  });
});
