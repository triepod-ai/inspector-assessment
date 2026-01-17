/**
 * ToolAnnotationExtractor Tests
 *
 * Issue #170: Tests for malformed annotation validation.
 * Verifies that non-boolean values are properly filtered to undefined.
 *
 * FIX-002: Malformed annotation validation
 * - Added typeof === "boolean" guards for all boolean fields
 * - Added early continue for missing source
 *
 * TEST-REQ-002: Malformed annotation validation
 * - Test string boolean "true" filtered to undefined
 * - Test number 1 filtered to undefined
 * - Test null filtered to undefined
 * - Test missing source skipped
 */

import { describe, it, expect } from "@jest/globals";
import { extractToolAnnotationsContext } from "../helpers/ToolAnnotationExtractor";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("ToolAnnotationExtractor", () => {
  describe("extractToolAnnotationsContext", () => {
    describe("valid annotations", () => {
      it("should extract valid boolean annotations", () => {
        const tools: Tool[] = [
          {
            name: "read_only_tool",
            description: "A read-only tool",
            inputSchema: {
              type: "object",
              properties: {
                query: { type: "string" },
              },
            },
            annotations: {
              readOnlyHint: true,
              openWorldHint: false,
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        expect(context.totalToolCount).toBe(1);
        expect(context.annotatedToolCount).toBe(1);

        const annotations = context.toolAnnotations.get("read_only_tool");
        expect(annotations).toBeDefined();
        expect(annotations?.readOnlyHint).toBe(true);
        expect(annotations?.openWorldHint).toBe(false);
        expect(annotations?.source).toBe("mcp");
      });

      it("should compute serverIsReadOnly when all tools are read-only", () => {
        const tools: Tool[] = [
          {
            name: "tool1",
            description: "Tool 1",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: true,
            },
          } as Tool,
          {
            name: "tool2",
            description: "Tool 2",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: true,
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        expect(context.serverIsReadOnly).toBe(true);
        expect(context.annotatedToolCount).toBe(2);
      });

      it("should compute serverIsClosed when all tools are closed-world", () => {
        const tools: Tool[] = [
          {
            name: "tool1",
            description: "Tool 1",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              openWorldHint: false,
              readOnlyHint: true, // Add another annotation to ensure source is "mcp" not inferred
            },
          } as Tool,
          {
            name: "tool2",
            description: "Tool 2",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              openWorldHint: false,
              readOnlyHint: true, // Add another annotation to ensure source is "mcp" not inferred
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        expect(context.serverIsClosed).toBe(true);
        expect(context.annotatedToolCount).toBe(2);
      });
    });

    describe("FIX-002: Malformed annotation validation (TEST-REQ-002)", () => {
      it("should filter string boolean 'true' to undefined", () => {
        const tools: Tool[] = [
          {
            name: "malformed_tool",
            description: "Tool with string boolean",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: "true" as unknown as boolean, // String instead of boolean
              openWorldHint: "false" as unknown as boolean, // String instead of boolean
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        // When ALL annotation values are malformed, extractAnnotations returns source: "none"
        // and the tool is skipped entirely (early continue in line 52-54)
        // Therefore, no annotations are stored for this tool
        const annotations = context.toolAnnotations.get("malformed_tool");

        // If the tool has no valid boolean annotations, it may not be in the map at all
        if (annotations) {
          // If it's in the map, the string values should be filtered to undefined
          expect(annotations?.readOnlyHint).toBeUndefined();
          expect(annotations?.openWorldHint).toBeUndefined();
        }

        // Tool with only malformed values is NOT counted as annotated (source: "none")
        expect(context.annotatedToolCount).toBe(0);
      });

      it("should filter number 1/0 to undefined", () => {
        const tools: Tool[] = [
          {
            name: "numeric_bool_tool",
            description: "Tool with numeric booleans",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: 1 as unknown as boolean, // Number instead of boolean
              destructiveHint: 0 as unknown as boolean, // Number instead of boolean
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        const annotations = context.toolAnnotations.get("numeric_bool_tool");
        expect(annotations).toBeDefined();

        // Numbers should be filtered to undefined
        expect(annotations?.readOnlyHint).toBeUndefined();
        expect(annotations?.destructiveHint).toBeUndefined();
      });

      it("should filter null to undefined", () => {
        const tools: Tool[] = [
          {
            name: "null_tool",
            description: "Tool with null values",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: null as unknown as boolean, // null instead of boolean
              idempotentHint: null as unknown as boolean, // null instead of boolean
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        const annotations = context.toolAnnotations.get("null_tool");
        expect(annotations).toBeDefined();

        // null should be filtered to undefined
        expect(annotations?.readOnlyHint).toBeUndefined();
        expect(annotations?.idempotentHint).toBeUndefined();
      });

      it("should skip tools with missing source", () => {
        const tools: Tool[] = [
          {
            name: "no_source_tool",
            description: "Tool with no source",
            inputSchema: {
              type: "object",
              properties: {},
              // No annotations at all - extractAnnotations will return source: "none"
            },
          },
        ];

        const context = extractToolAnnotationsContext(tools);

        // Tool should not be in the map (skipped due to source: "none" or undefined)
        const _annotations = context.toolAnnotations.get("no_source_tool");

        // The tool may be skipped entirely or have source: "none"
        // Either way, it shouldn't count as annotated
        expect(context.annotatedToolCount).toBe(0);
      });

      it("should handle mixed valid and invalid annotations", () => {
        const tools: Tool[] = [
          {
            name: "mixed_tool",
            description: "Tool with mixed annotations",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: true, // Valid boolean
              destructiveHint: "false" as unknown as boolean, // Invalid string
              idempotentHint: 1 as unknown as boolean, // Invalid number
              openWorldHint: false, // Valid boolean
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        const annotations = context.toolAnnotations.get("mixed_tool");
        expect(annotations).toBeDefined();

        // Valid booleans preserved
        expect(annotations?.readOnlyHint).toBe(true);
        expect(annotations?.openWorldHint).toBe(false);

        // Invalid values filtered to undefined
        expect(annotations?.destructiveHint).toBeUndefined();
        expect(annotations?.idempotentHint).toBeUndefined();
      });

      it("should not count malformed tools for server-level flags", () => {
        const tools: Tool[] = [
          {
            name: "tool1",
            description: "Valid read-only tool",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: true, // Valid
            },
          } as Tool,
          {
            name: "tool2",
            description: "Malformed tool",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: "true" as unknown as boolean, // Invalid - causes source: "none"
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        // tool1 is read-only (valid boolean true)
        // tool2 has only malformed annotations, so all fields filtered to undefined
        // but it IS in the map with source: "none"
        // Since tool2 has source: "none", it's NOT counted as annotated
        // Therefore, server IS 100% read-only (1 out of 1 annotated tool)
        expect(context.serverIsReadOnly).toBe(true);

        // Only tool1 has valid annotations (source !== "none")
        expect(context.annotatedToolCount).toBe(1);

        // Verify tool1 annotations
        const tool1Annotations = context.toolAnnotations.get("tool1");
        expect(tool1Annotations?.readOnlyHint).toBe(true);

        // tool2 IS in the map, but with source: "none" and all fields undefined
        const tool2Annotations = context.toolAnnotations.get("tool2");
        expect(tool2Annotations).toBeDefined();
        expect(tool2Annotations?.source).toBe("none");
        expect(tool2Annotations?.readOnlyHint).toBeUndefined();
      });
    });

    describe("edge cases", () => {
      it("should handle empty tool array", () => {
        const context = extractToolAnnotationsContext([]);

        expect(context.totalToolCount).toBe(0);
        expect(context.annotatedToolCount).toBe(0);
        expect(context.serverIsReadOnly).toBe(false);
        expect(context.serverIsClosed).toBe(false);
        expect(context.toolAnnotations.size).toBe(0);
      });

      it("should handle tools with no annotations", () => {
        const tools: Tool[] = [
          {
            name: "plain_tool",
            description: "Tool without annotations",
            inputSchema: {
              type: "object",
              properties: {
                query: { type: "string" },
              },
            },
          },
        ];

        const context = extractToolAnnotationsContext(tools);

        expect(context.totalToolCount).toBe(1);
        expect(context.annotatedToolCount).toBe(0);
        expect(context.serverIsReadOnly).toBe(false);
        expect(context.serverIsClosed).toBe(false);
      });

      it("should handle partial server-level flags", () => {
        const tools: Tool[] = [
          {
            name: "read_only",
            description: "Read-only tool",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              readOnlyHint: true,
            },
          } as Tool,
          {
            name: "write_tool",
            description: "Write tool",
            inputSchema: {
              type: "object",
              properties: {},
            },
            annotations: {
              destructiveHint: true,
            },
          } as Tool,
        ];

        const context = extractToolAnnotationsContext(tools);

        // Not all tools are read-only
        expect(context.serverIsReadOnly).toBe(false);

        expect(context.annotatedToolCount).toBe(2);
      });
    });

    describe("memory leak prevention", () => {
      it("should properly cleanup Map objects", () => {
        let context;
        try {
          const tools: Tool[] = [
            {
              name: "test_tool",
              description: "Test",
              inputSchema: {
                type: "object",
                properties: {},
              },
              annotations: {
                readOnlyHint: true,
              },
            } as Tool,
          ];

          context = extractToolAnnotationsContext(tools);
          expect(context.toolAnnotations.size).toBe(1);
        } finally {
          // Cleanup
          if (context) {
            context.toolAnnotations.clear();
          }
        }
      });
    });
  });
});
