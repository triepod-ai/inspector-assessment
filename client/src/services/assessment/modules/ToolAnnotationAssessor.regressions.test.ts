import { ToolAnnotationAssessor } from "./ToolAnnotationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockToolWithAnnotations,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("ToolAnnotationAssessor - Regression Tests", () => {
  let assessor: ToolAnnotationAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        toolAnnotations: true,
      },
    });
    assessor = new ToolAnnotationAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Low-Confidence Annotation Trust (Issue Fix)", () => {
    it("should trust explicit annotation when inference is low-confidence", async () => {
      // Tool with generic name (can't infer behavior) but explicit annotation
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "vulnerable_calculator_tool",
          description: "A calculator tool",
          readOnlyHint: true, // Explicit annotation
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      // Should NOT flag REVIEW_RECOMMENDED despite inference being uncertain
      expect(result.toolResults[0].alignmentStatus).not.toBe(
        "REVIEW_RECOMMENDED",
      );
      // Should be ALIGNED since we trust the explicit annotation
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should flag MISALIGNED for medium-confidence mismatch", async () => {
      // Tool with name pattern suggesting write but annotation says read
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "data_writer_tool",
          description: "Writes data to storage",
          readOnlyHint: true, // Wrong - "writer" suggests write operation
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
    });

    it("should flag ALIGNED for tools with proper annotations and no deceptive keywords", async () => {
      // Tools that would have low-confidence inference but have correct annotations
      const genericTools = [
        "vulnerable_data_leak_tool",
        "vulnerable_unicode_processor_tool",
        "vulnerable_nested_parser_tool",
        "vulnerable_rug_pull_tool",
      ];

      for (const name of genericTools) {
        mockContext.tools = [
          createMockToolWithAnnotations({
            name,
            description: "A hardened tool that stores data safely",
            readOnlyHint: true,
            destructiveHint: false,
          }),
        ];

        const result = await assessor.assess(mockContext);

        // Should be ALIGNED, not REVIEW_RECOMMENDED
        expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      }
    });
  });

  describe("Regression: Fix for False REVIEW_RECOMMENDED (v1.22.5)", () => {
    it("should not flag REVIEW_RECOMMENDED for properly annotated ambiguous tools", async () => {
      // These are the exact tools from the hardened testbed that were
      // incorrectly flagged as REVIEW_RECOMMENDED before v1.22.5 fix
      const ambiguousToolNames = [
        "vulnerable_calculator_tool",
        "vulnerable_data_leak_tool",
        "vulnerable_tool_override_tool",
        "vulnerable_config_modifier_tool",
        "vulnerable_fetcher_tool",
        "vulnerable_unicode_processor_tool",
        "vulnerable_nested_parser_tool",
        "vulnerable_rug_pull_tool",
        "vulnerable_deserializer_tool",
      ];

      for (const name of ambiguousToolNames) {
        mockContext.tools = [
          createMockToolWithAnnotations({
            name,
            description: `Hardened version of ${name}`,
            readOnlyHint: true,
            destructiveHint: false,
          }),
        ];

        const result = await assessor.assess(mockContext);

        expect(result.toolResults[0].alignmentStatus).not.toBe(
          "REVIEW_RECOMMENDED",
        );
      }
    });

    it("deception detection should override low-confidence inference", async () => {
      // Even though "vulnerable_system_exec_tool" has an ambiguous "vulnerable_" prefix,
      // the "exec" keyword should trigger MISALIGNED via deception detection
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "vulnerable_system_exec_tool",
          description: "A hardened exec tool (but still contains exec keyword)",
          readOnlyHint: true, // Deceptive despite "hardened" description
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("exec"),
      );
    });

    it("should correctly handle the hardened testbed scenario", async () => {
      // Simulate the exact hardened testbed scenario that was failing before
      mockContext.tools = [
        // Properly annotated tools with ambiguous names - should be ALIGNED
        createMockToolWithAnnotations({
          name: "vulnerable_calculator_tool",
          description: "HARDENED: Stores queries without executing",
          readOnlyHint: true,
          destructiveHint: false,
        }),
        createMockToolWithAnnotations({
          name: "vulnerable_data_leak_tool",
          description: "HARDENED: Queues queries without leaking",
          readOnlyHint: true,
          destructiveHint: false,
        }),
        // Deceptive tools - should be MISALIGNED
        createMockToolWithAnnotations({
          name: "vulnerable_system_exec_tool",
          description: "HARDENED: Logs commands (but name still has exec)",
          readOnlyHint: true, // Deceptive
          destructiveHint: false,
        }),
        createMockToolWithAnnotations({
          name: "vulnerable_package_installer_tool",
          description: "HARDENED: Validates against allowlist",
          readOnlyHint: true, // Deceptive - install keyword
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      // First two should be ALIGNED (trusted annotations, no deceptive keywords)
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      expect(result.toolResults[1].alignmentStatus).toBe("ALIGNED");

      // Last two should be MISALIGNED (deceptive keywords detected)
      expect(result.toolResults[2].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[3].alignmentStatus).toBe("MISALIGNED");

      // Verify alignment breakdown
      expect(result.alignmentBreakdown?.aligned).toBe(2);
      expect(result.alignmentBreakdown?.misaligned).toBe(2);
      expect(result.alignmentBreakdown?.reviewRecommended).toBe(0);
    });
  });
});
