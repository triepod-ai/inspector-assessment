/**
 * Issue #207/#204: Runtime Annotation Verification Tests
 *
 * Tests for servers that define annotations in code rather than manifest.json.
 * This addresses the gap where MeetGeek-style servers with runtime annotations
 * were incorrectly reported as having 0% annotation coverage.
 *
 * @see GitHub Issue #207, #204
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  verifyRuntimeAnnotations,
  type RuntimeAnnotationVerification,
  type AnnotationLocation,
} from "../helpers/RuntimeAnnotationVerifier";
import { extractAnnotations } from "../modules/annotations/AlignmentChecker";
import { ToolAnnotationAssessor } from "../modules/ToolAnnotationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";

describe("Runtime Annotation Verification - Issue #207/#204", () => {
  describe("verifyRuntimeAnnotations", () => {
    it("should return empty verification for no tools", () => {
      const result = verifyRuntimeAnnotations([]);

      expect(result.verified).toBe(true);
      expect(result.totalTools).toBe(0);
      expect(result.toolsWithRuntimeAnnotations).toBe(0);
      expect(result.toolsWithoutAnnotations).toBe(0);
      expect(result.runtimeCoveragePercent).toBe(0);
      expect(result.toolDetails).toHaveLength(0);
    });

    it("should detect annotations in annotations object (MCP spec)", () => {
      const tools: Tool[] = [
        {
          name: "get_meetings",
          description: "Retrieves meeting list",
          inputSchema: { type: "object", properties: {} },
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
          },
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.verified).toBe(true);
      expect(result.totalTools).toBe(1);
      expect(result.toolsWithRuntimeAnnotations).toBe(1);
      expect(result.runtimeCoveragePercent).toBe(100);
      expect(result.toolDetails[0].location).toBe("annotations_object");
      expect(result.toolDetails[0].foundHints).toContain("readOnlyHint");
      expect(result.toolDetails[0].foundHints).toContain("destructiveHint");
    });

    it("should detect annotations as direct properties (SDK interceptor preserved)", () => {
      // Simulate what tools-with-hints.ts produces after SDK strips annotations object
      // but interceptor preserves as direct properties
      const tools: Tool[] = [
        {
          name: "get_meetings",
          description: "Retrieves meeting list",
          inputSchema: { type: "object", properties: {} },
          // Direct properties (preserved by tools-with-hints.ts)
          readOnlyHint: true,
          destructiveHint: false,
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.verified).toBe(true);
      expect(result.toolsWithRuntimeAnnotations).toBe(1);
      expect(result.runtimeCoveragePercent).toBe(100);
      expect(result.toolDetails[0].location).toBe("direct_properties");
      expect(result.toolDetails[0].foundHints).toContain("readOnlyHint");
    });

    it("should detect annotations in metadata object", () => {
      const tools: Tool[] = [
        {
          name: "get_data",
          description: "Gets data",
          inputSchema: { type: "object", properties: {} },
          metadata: {
            readOnlyHint: true,
          },
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.toolsWithRuntimeAnnotations).toBe(1);
      expect(result.toolDetails[0].location).toBe("metadata");
    });

    it("should detect annotations in _meta object", () => {
      const tools: Tool[] = [
        {
          name: "get_info",
          description: "Gets info",
          inputSchema: { type: "object", properties: {} },
          _meta: {
            readOnlyHint: true,
          },
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.toolsWithRuntimeAnnotations).toBe(1);
      expect(result.toolDetails[0].location).toBe("_meta");
    });

    it("should detect annotations in nested annotations.hints object", () => {
      const tools: Tool[] = [
        {
          name: "get_config",
          description: "Gets config",
          inputSchema: { type: "object", properties: {} },
          annotations: {
            hints: {
              readOnlyHint: true,
            },
          },
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.toolsWithRuntimeAnnotations).toBe(1);
      expect(result.toolDetails[0].location).toBe("annotations_hints");
    });

    it("should detect non-suffixed annotation variants (Issue #160)", () => {
      const tools: Tool[] = [
        {
          name: "get_data",
          description: "Gets data",
          inputSchema: { type: "object", properties: {} },
          annotations: {
            readOnly: true, // Non-suffixed
            destructive: false,
          },
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.toolsWithRuntimeAnnotations).toBe(1);
      expect(result.toolDetails[0].foundHints).toContain("readOnly");
      expect(result.toolDetails[0].foundHints).toContain("destructive");
    });

    it("should report 'none' for tools without annotations", () => {
      const tools: Tool[] = [
        {
          name: "unannotated_tool",
          description: "No annotations",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.toolsWithRuntimeAnnotations).toBe(0);
      expect(result.toolsWithoutAnnotations).toBe(1);
      expect(result.toolDetails[0].location).toBe("none");
      expect(result.toolDetails[0].foundHints).toHaveLength(0);
    });

    it("should correctly calculate coverage percentage for mixed tools", () => {
      const tools: Tool[] = [
        {
          name: "annotated_tool",
          description: "Has annotations",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true },
        } as unknown as Tool,
        {
          name: "unannotated_tool",
          description: "No annotations",
          inputSchema: { type: "object", properties: {} },
        },
        {
          name: "another_annotated",
          description: "Also has annotations",
          inputSchema: { type: "object", properties: {} },
          destructiveHint: true,
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.totalTools).toBe(3);
      expect(result.toolsWithRuntimeAnnotations).toBe(2);
      expect(result.toolsWithoutAnnotations).toBe(1);
      expect(result.runtimeCoveragePercent).toBe(67); // 2/3 = 66.67%, rounded to 67
    });
  });

  describe("annotations-in-code-only scenario (MeetGeek pattern)", () => {
    it("should correctly verify server with 100% runtime-annotated tools", () => {
      // Simulate MeetGeek-style server with annotations defined in code
      const tools: Tool[] = [
        {
          name: "get_meetings",
          description: "Get meetings from calendar",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true, destructiveHint: false },
        } as unknown as Tool,
        {
          name: "get_meeting_details",
          description: "Get details of a specific meeting",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true, destructiveHint: false },
        } as unknown as Tool,
        {
          name: "delete_meeting",
          description: "Delete a meeting",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: false, destructiveHint: true },
        } as unknown as Tool,
        {
          name: "update_meeting",
          description: "Update meeting details",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: false, destructiveHint: false },
        } as unknown as Tool,
      ];

      const verification = verifyRuntimeAnnotations(tools);

      expect(verification.verified).toBe(true);
      expect(verification.totalTools).toBe(4);
      expect(verification.toolsWithRuntimeAnnotations).toBe(4);
      expect(verification.toolsWithoutAnnotations).toBe(0);
      expect(verification.runtimeCoveragePercent).toBe(100);

      // All tools should be detected at annotations_object location
      for (const detail of verification.toolDetails) {
        expect(detail.location).toBe("annotations_object");
        expect(detail.foundHints.length).toBeGreaterThan(0);
      }
    });

    it("should handle SDK-preserved direct properties scenario", () => {
      // Simulate what tools-with-hints.ts produces when SDK strips annotations
      // but interceptor preserves them as direct properties
      const tools: Tool[] = [
        {
          name: "get_meetings",
          description: "Get meetings",
          inputSchema: { type: "object", properties: {} },
          readOnlyHint: true, // Direct property (preserved by interceptor)
          destructiveHint: false,
        } as unknown as Tool,
        {
          name: "delete_meeting",
          description: "Delete meeting",
          inputSchema: { type: "object", properties: {} },
          readOnlyHint: false,
          destructiveHint: true,
        } as unknown as Tool,
      ];

      const verification = verifyRuntimeAnnotations(tools);

      expect(verification.toolsWithRuntimeAnnotations).toBe(2);
      expect(verification.runtimeCoveragePercent).toBe(100);

      // Should be detected at direct_properties location
      for (const detail of verification.toolDetails) {
        expect(detail.location).toBe("direct_properties");
      }
    });
  });

  describe("extractAnnotations integration", () => {
    it("should return source: mcp for annotations in annotations object", () => {
      const tool: Tool = {
        name: "get_meetings",
        description: "Retrieves meeting list",
        inputSchema: { type: "object", properties: {} },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(false);
      expect(result.source).toBe("mcp");
    });

    it("should return source: mcp for annotations as direct properties", () => {
      // This is the critical test - direct properties from tools-with-hints.ts
      // should be treated as MCP source, not inferred
      const tool = {
        name: "get_meetings",
        description: "Retrieves meeting list",
        inputSchema: { type: "object", properties: {} },
        readOnlyHint: true,
        destructiveHint: false,
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.destructiveHint).toBe(false);
      expect(result.source).toBe("mcp"); // Should be MCP, not inferred!
    });

    it("should return source: mcp for annotations in metadata", () => {
      const tool = {
        name: "get_data",
        description: "Gets data",
        inputSchema: { type: "object", properties: {} },
        metadata: {
          readOnlyHint: true,
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should return source: mcp for annotations in _meta", () => {
      const tool = {
        name: "get_info",
        description: "Gets info",
        inputSchema: { type: "object", properties: {} },
        _meta: {
          destructiveHint: true,
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.destructiveHint).toBe(true);
      expect(result.source).toBe("mcp");
    });

    it("should handle non-suffixed variants (Issue #150)", () => {
      const tool = {
        name: "get_data",
        description: "Gets data",
        inputSchema: { type: "object", properties: {} },
        annotations: {
          readOnly: true, // Non-suffixed
        },
      } as unknown as Tool;

      const result = extractAnnotations(tool);

      expect(result.readOnlyHint).toBe(true);
      expect(result.source).toBe("mcp");
    });
  });

  describe("annotation location priority", () => {
    it("should prioritize annotations object over direct properties", () => {
      const tools: Tool[] = [
        {
          name: "conflicting_tool",
          description: "Has both locations",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true },
          readOnlyHint: false, // Direct property (should be ignored)
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      // Should report annotations_object as the location
      expect(result.toolDetails[0].location).toBe("annotations_object");
    });

    it("should prioritize direct properties over metadata", () => {
      const tools: Tool[] = [
        {
          name: "conflicting_tool",
          description: "Has both locations",
          inputSchema: { type: "object", properties: {} },
          readOnlyHint: true, // Direct property
          metadata: { readOnlyHint: false }, // Metadata (should be ignored)
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      // Should report direct_properties as the location
      expect(result.toolDetails[0].location).toBe("direct_properties");
    });
  });

  // ══════════════════════════════════════════════════════════════════
  // GAP TESTS - Addressing high and medium priority test gaps from QA review
  // ══════════════════════════════════════════════════════════════════

  describe("GAP-001 (HIGH): Integration test for runtimeVerification in assess() output", () => {
    let assessor: ToolAnnotationAssessor;

    beforeEach(() => {
      const config = createMockAssessmentConfig({});
      assessor = new ToolAnnotationAssessor(config);
    });

    it("should populate runtimeVerification in assess() output with runtime-annotated tools", async () => {
      const tools: Tool[] = [
        {
          name: "get_meetings",
          description: "Get meetings from calendar",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true, destructiveHint: false },
        } as unknown as Tool,
        {
          name: "delete_meeting",
          description: "Delete a meeting",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: false, destructiveHint: true },
        } as unknown as Tool,
        {
          name: "unannotated_tool",
          description: "No annotations",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const context = createMockAssessmentContext({ tools });
      const result = await assessor.assess(context);

      // Verify runtimeVerification is present in output
      expect(result.runtimeVerification).toBeDefined();
      expect(result.runtimeVerification?.verified).toBe(true);
      expect(result.runtimeVerification?.totalTools).toBe(3);
      expect(result.runtimeVerification?.toolsWithRuntimeAnnotations).toBe(2);
      expect(result.runtimeVerification?.toolsWithoutAnnotations).toBe(1);
      expect(result.runtimeVerification?.runtimeCoveragePercent).toBe(67); // 2/3 = 66.67%, rounded to 67

      // Verify tool details are populated
      expect(result.runtimeVerification?.toolDetails).toHaveLength(3);
      const annotatedTools = result.runtimeVerification?.toolDetails.filter(
        (t) => t.location !== "none",
      );
      expect(annotatedTools).toHaveLength(2);
    });

    it("should populate runtimeVerification with 100% coverage for fully annotated server", async () => {
      const tools: Tool[] = [
        {
          name: "get_data",
          description: "Get data",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true },
        } as unknown as Tool,
        {
          name: "update_data",
          description: "Update data",
          inputSchema: { type: "object", properties: {} },
          annotations: { destructiveHint: false },
        } as unknown as Tool,
      ];

      const context = createMockAssessmentContext({ tools });
      const result = await assessor.assess(context);

      expect(result.runtimeVerification?.runtimeCoveragePercent).toBe(100);
      expect(result.runtimeVerification?.toolsWithoutAnnotations).toBe(0);
    });

    it("should populate runtimeVerification with 0% coverage for unannotated server", async () => {
      const tools: Tool[] = [
        {
          name: "tool1",
          description: "Tool 1",
          inputSchema: { type: "object", properties: {} },
        },
        {
          name: "tool2",
          description: "Tool 2",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const context = createMockAssessmentContext({ tools });
      const result = await assessor.assess(context);

      expect(result.runtimeVerification?.runtimeCoveragePercent).toBe(0);
      expect(result.runtimeVerification?.toolsWithRuntimeAnnotations).toBe(0);
      expect(result.runtimeVerification?.toolsWithoutAnnotations).toBe(2);
    });
  });

  describe("GAP-002 (HIGH): Null/undefined tools array handling", () => {
    it("should return safe default for null tools array", () => {
      const result = verifyRuntimeAnnotations(null as any);

      expect(result.verified).toBe(true);
      expect(result.totalTools).toBe(0);
      expect(result.toolsWithRuntimeAnnotations).toBe(0);
      expect(result.toolsWithoutAnnotations).toBe(0);
      expect(result.runtimeCoveragePercent).toBe(0);
      expect(result.toolDetails).toHaveLength(0);
    });

    it("should return safe default for undefined tools array", () => {
      const result = verifyRuntimeAnnotations(undefined as any);

      expect(result.verified).toBe(true);
      expect(result.totalTools).toBe(0);
      expect(result.toolsWithRuntimeAnnotations).toBe(0);
      expect(result.toolsWithoutAnnotations).toBe(0);
      expect(result.runtimeCoveragePercent).toBe(0);
      expect(result.toolDetails).toHaveLength(0);
    });
  });

  describe("GAP-003 (MEDIUM): Empty annotations object handling", () => {
    it("should return location: 'none' for tool with empty annotations object", () => {
      const tools: Tool[] = [
        {
          name: "empty_annotations_tool",
          description: "Has empty annotations",
          inputSchema: { type: "object", properties: {} },
          annotations: {}, // Empty object, no hints
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.totalTools).toBe(1);
      expect(result.toolsWithRuntimeAnnotations).toBe(0);
      expect(result.toolsWithoutAnnotations).toBe(1);
      expect(result.toolDetails[0].location).toBe("none");
      expect(result.toolDetails[0].foundHints).toHaveLength(0);
    });

    it("should return location: 'none' for tool with annotations containing only non-hint properties", () => {
      const tools: Tool[] = [
        {
          name: "non_hint_annotations_tool",
          description: "Has annotations but no hints",
          inputSchema: { type: "object", properties: {} },
          annotations: {
            customField: "value",
            anotherField: 123,
          } as any,
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.toolsWithRuntimeAnnotations).toBe(0);
      expect(result.toolsWithoutAnnotations).toBe(1);
      expect(result.toolDetails[0].location).toBe("none");
    });
  });

  describe("GAP-004 (MEDIUM): Duplicate tool names handling", () => {
    it("should handle duplicate tool names with different annotations", () => {
      const tools: Tool[] = [
        {
          name: "duplicate_tool",
          description: "First instance",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true },
        } as unknown as Tool,
        {
          name: "duplicate_tool",
          description: "Second instance",
          inputSchema: { type: "object", properties: {} },
          destructiveHint: true, // Different annotation location
        } as unknown as Tool,
      ];

      const result = verifyRuntimeAnnotations(tools);

      // Both tools should be counted
      expect(result.totalTools).toBe(2);
      expect(result.toolsWithRuntimeAnnotations).toBe(2);

      // Both should have details (even with same name)
      expect(result.toolDetails).toHaveLength(2);
      expect(result.toolDetails[0].toolName).toBe("duplicate_tool");
      expect(result.toolDetails[1].toolName).toBe("duplicate_tool");

      // Different locations
      expect(result.toolDetails[0].location).toBe("annotations_object");
      expect(result.toolDetails[1].location).toBe("direct_properties");
    });

    it("should handle duplicate tool names where one is annotated and one is not", () => {
      const tools: Tool[] = [
        {
          name: "duplicate_tool",
          description: "Annotated version",
          inputSchema: { type: "object", properties: {} },
          annotations: { readOnlyHint: true },
        } as unknown as Tool,
        {
          name: "duplicate_tool",
          description: "Unannotated version",
          inputSchema: { type: "object", properties: {} },
        },
      ];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.totalTools).toBe(2);
      expect(result.toolsWithRuntimeAnnotations).toBe(1);
      expect(result.toolsWithoutAnnotations).toBe(1);
      expect(result.runtimeCoveragePercent).toBe(50); // 1/2 = 50%
    });
  });

  describe("GAP-005 (MEDIUM): Performance boundary test with large tool count", () => {
    it("should handle 100+ tools with reasonable performance", () => {
      // Generate 150 tools with varying annotation patterns
      const tools: Tool[] = Array.from({ length: 150 }, (_, i) => {
        const toolNumber = i + 1;
        const hasAnnotations = i % 3 !== 0; // ~67% have annotations

        return {
          name: `tool_${toolNumber}`,
          description: `Tool number ${toolNumber}`,
          inputSchema: { type: "object", properties: {} },
          ...(hasAnnotations
            ? {
                annotations: {
                  readOnlyHint: i % 2 === 0,
                  destructiveHint: i % 2 !== 0,
                },
              }
            : {}),
        } as unknown as Tool;
      });

      const startTime = performance.now();
      const result = verifyRuntimeAnnotations(tools);
      const duration = performance.now() - startTime;

      // Performance assertion: should complete in <100ms
      expect(duration).toBeLessThan(100);

      // Correctness assertions
      expect(result.totalTools).toBe(150);
      expect(result.toolsWithRuntimeAnnotations).toBe(100); // 2/3 of 150 = 100
      expect(result.toolsWithoutAnnotations).toBe(50); // 1/3 of 150 = 50
      expect(result.runtimeCoveragePercent).toBe(67); // 100/150 = 66.67%, rounded to 67
      expect(result.toolDetails).toHaveLength(150);

      // Verify all tool details are populated correctly
      const annotatedCount = result.toolDetails.filter(
        (t) => t.location !== "none",
      ).length;
      expect(annotatedCount).toBe(100);
    });

    it("should handle 250 tools without errors or memory issues", () => {
      const tools: Tool[] = Array.from({ length: 250 }, (_, i) => ({
        name: `tool_${i + 1}`,
        description: `Tool ${i + 1}`,
        inputSchema: { type: "object", properties: {} },
        annotations: { readOnlyHint: true },
      })) as unknown as Tool[];

      const result = verifyRuntimeAnnotations(tools);

      expect(result.totalTools).toBe(250);
      expect(result.toolsWithRuntimeAnnotations).toBe(250);
      expect(result.runtimeCoveragePercent).toBe(100);
      expect(result.toolDetails).toHaveLength(250);
    });
  });
});
