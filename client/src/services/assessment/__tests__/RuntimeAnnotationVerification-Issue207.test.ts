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
});
