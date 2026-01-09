import { ToolAnnotationAssessor } from "./ToolAnnotationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockToolWithAnnotations,
  createMockTool,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("ToolAnnotationAssessor", () => {
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

  describe("assess", () => {
    it("should pass when all tools have proper annotations", async () => {
      // Arrange
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "get_data",
          description: "Gets data from the server",
          readOnlyHint: true,
          destructiveHint: false,
        }),
        createMockToolWithAnnotations({
          name: "delete_item",
          description: "Deletes an item",
          readOnlyHint: false,
          destructiveHint: true,
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.annotatedCount).toBe(2);
      expect(result.missingAnnotationsCount).toBe(0);
    });

    it("should fail when tools are missing annotations", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({ name: "get_data", description: "Gets data" }),
        createMockTool({ name: "update_data", description: "Updates data" }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.missingAnnotationsCount).toBe(2);
      expect(result.annotatedCount).toBe(0);
    });

    it("should detect misaligned readOnlyHint for read operations", async () => {
      // Arrange - tool name suggests read-only but annotation says otherwise
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "get_user_data",
          description: "Gets user data",
          readOnlyHint: false, // Should be true based on name
          destructiveHint: false,
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.misalignedAnnotationsCount).toBeGreaterThan(0);
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("misaligned"),
      );
    });

    it("should detect misaligned destructiveHint for delete operations", async () => {
      // Arrange - tool name suggests destructive but annotation says otherwise
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "delete_user",
          description: "Deletes a user account",
          readOnlyHint: false,
          destructiveHint: false, // Should be true based on name
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("destructive"),
      );
    });

    it("should infer read-only behavior from tool name patterns", async () => {
      const readOnlyNames = [
        "get_items",
        "list_users",
        "fetch_data",
        "read_file",
        "query_database",
        "search_records",
        "find_match",
      ];

      for (const name of readOnlyNames) {
        mockContext.tools = [createMockTool({ name, description: "Test" })];
        const result = await assessor.assess(mockContext);

        expect(result.toolResults[0].inferredBehavior.expectedReadOnly).toBe(
          true,
        );
      }
    });

    it("should infer destructive behavior from tool name patterns", async () => {
      const destructiveNames = [
        "delete_item",
        "remove_user",
        "destroy_session",
        "drop_table",
        "purge_cache",
        "clear_data",
        "wipe_records",
      ];

      for (const name of destructiveNames) {
        mockContext.tools = [createMockTool({ name, description: "Test" })];
        const result = await assessor.assess(mockContext);

        expect(result.toolResults[0].inferredBehavior.expectedDestructive).toBe(
          true,
        );
      }
    });

    it("should infer CREATE operations as non-destructive regardless of persistence model", async () => {
      // CREATE operations only ADD new data - they should NEVER be destructive
      // This is semantically distinct from UPDATE/MODIFY which change existing data
      const createNames = [
        "create_item",
        "add_user",
        "insert_record",
        "new_document",
        "generate_report",
      ];

      for (const name of createNames) {
        mockContext.tools = [createMockTool({ name, description: "Test" })];
        const result = await assessor.assess(mockContext);

        expect(result.toolResults[0].inferredBehavior.expectedReadOnly).toBe(
          false,
        );
        expect(result.toolResults[0].inferredBehavior.expectedDestructive).toBe(
          false,
        );
      }
    });

    it("should infer UPDATE/MODIFY operations as destructive when persistence is immediate", async () => {
      // UPDATE/MODIFY operations change existing data - they ARE destructive when persisted immediately
      // With only update tools and no save operations, persistence model = immediate
      // Note: "save_data" is excluded because "save" triggers save operation detection → deferred persistence
      const updateNames = ["update_record", "modify_setting", "set_value"];

      for (const name of updateNames) {
        mockContext.tools = [createMockTool({ name, description: "Test" })];
        const result = await assessor.assess(mockContext);

        expect(result.toolResults[0].inferredBehavior.expectedReadOnly).toBe(
          false,
        );
        // These operations are correctly flagged as destructive when persistence is immediate
        expect(result.toolResults[0].inferredBehavior.expectedDestructive).toBe(
          true,
        );
      }
    });

    it("should pass with empty tools list", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.annotatedCount).toBe(0);
      expect(result.missingAnnotationsCount).toBe(0);
    });

    it("should fail when destructive tools lack destructiveHint", async () => {
      // Arrange
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "delete_all_records",
          description: "Deletes all records from the database",
          readOnlyHint: false,
          // destructiveHint intentionally omitted
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("destructive"),
      );
    });

    it("should generate appropriate recommendations for missing annotations", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({ name: "get_data", description: "Gets data" }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations.length).toBeGreaterThan(0);
      expect(result.recommendations).toContainEqual(
        expect.stringContaining("Add annotations"),
      );
    });

    it("should include Policy #17 reference in recommendations", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({ name: "some_tool", description: "Does something" }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContainEqual(
        expect.stringContaining("Policy #17"),
      );
    });
  });

  describe("Ambiguous pattern handling (GitHub Issue #3)", () => {
    it("should trust explicit annotation for store_expression_tool with destructiveHint=true (v1.22.5 fix)", async () => {
      // Arrange - ambiguous "store" verb with destructiveHint=true
      // v1.22.5 fix: Trust explicit annotations when inference is ambiguous/low-confidence
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "store_expression_tool",
          description: "Stores an expression in memory",
          readOnlyHint: false,
          destructiveHint: true, // Explicit annotation - trust it
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - v1.22.5: ALIGNED (trust explicit annotation), not REVIEW_RECOMMENDED
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      expect(result.toolResults[0].inferredBehavior?.isAmbiguous).toBe(true);
      expect(result.toolResults[0].inferredBehavior?.confidence).toBe("low");
      expect(result.status).not.toBe("FAIL"); // Should not fail assessment
    });

    it("SHOULD flag delete_user_tool with readOnlyHint=true as misaligned", async () => {
      // Arrange - clear destructive verb with wrong annotation
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "delete_user_tool",
          description: "Deletes a user from the system",
          readOnlyHint: true, // WRONG - should be flagged
          destructiveHint: false,
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].inferredBehavior?.confidence).toBe("high");
      expect(result.toolResults[0].inferredBehavior?.isAmbiguous).toBe(false);
      expect(result.status).toBe("FAIL"); // Should fail assessment
    });

    it("should trust explicit annotation for process_data_tool with destructiveHint=true (v1.22.5 fix)", async () => {
      // Arrange - ambiguous "process" verb
      // v1.22.5 fix: Trust explicit annotations when inference is ambiguous/low-confidence
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "process_data_tool",
          description: "Processes data",
          readOnlyHint: false,
          destructiveHint: true, // Explicit annotation - trust it
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - v1.22.5: ALIGNED (trust explicit annotation), not REVIEW_RECOMMENDED
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      expect(result.toolResults[0].inferredBehavior?.isAmbiguous).toBe(true);
    });

    it("should mark ambiguous patterns with low confidence", async () => {
      const ambiguousNames = [
        "store_data",
        "queue_message",
        "cache_result",
        "process_input",
        "handle_event",
        "manage_session",
      ];

      for (const name of ambiguousNames) {
        mockContext.tools = [createMockTool({ name, description: "Test" })];
        const result = await assessor.assess(mockContext);

        expect(result.toolResults[0].inferredBehavior?.isAmbiguous).toBe(true);
        expect(result.toolResults[0].inferredBehavior?.confidence).toBe("low");
      }
    });

    it("should mark clear patterns with high confidence", async () => {
      const clearDestructive = [
        "delete_item",
        "remove_user",
        "destroy_session",
      ];
      const clearReadOnly = ["get_data", "list_users", "fetch_config"];

      for (const name of clearDestructive) {
        mockContext.tools = [createMockTool({ name, description: "Test" })];
        const result = await assessor.assess(mockContext);
        expect(result.toolResults[0].inferredBehavior?.confidence).toBe("high");
        expect(result.toolResults[0].inferredBehavior?.isAmbiguous).toBe(false);
      }

      for (const name of clearReadOnly) {
        mockContext.tools = [createMockTool({ name, description: "Test" })];
        const result = await assessor.assess(mockContext);
        expect(result.toolResults[0].inferredBehavior?.confidence).toBe("high");
        expect(result.toolResults[0].inferredBehavior?.isAmbiguous).toBe(false);
      }
    });

    it("should calculate metrics correctly", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "get_data",
          description: "Gets data",
          readOnlyHint: true,
          destructiveHint: false,
        }),
        createMockToolWithAnnotations({
          name: "delete_item",
          description: "Deletes an item",
          readOnlyHint: false,
          destructiveHint: true,
        }),
        createMockTool({ name: "process_data", description: "Processes data" }), // No annotations
      ];

      const result = await assessor.assess(mockContext);

      // Check metrics exist
      expect(result.metrics).toBeDefined();
      expect(result.metrics?.coverage).toBeCloseTo(66.67, 0); // 2/3 annotated
      expect(result.alignmentBreakdown).toBeDefined();
      expect(result.alignmentBreakdown?.aligned).toBe(2);
      expect(result.alignmentBreakdown?.unknown).toBe(1); // process_data has no annotations
    });

    it("should trust explicit annotations for ambiguous tools (v1.22.5 fix)", async () => {
      // All tools have ambiguous patterns with explicit annotations
      // v1.22.5 fix: Trust explicit annotations when inference is ambiguous/low-confidence
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "store_data",
          description: "Stores data",
          readOnlyHint: true, // Explicit annotation - trust it
          destructiveHint: false,
        }),
        createMockToolWithAnnotations({
          name: "cache_result",
          description: "Caches a result",
          readOnlyHint: false,
          destructiveHint: true, // Explicit annotation - trust it
        }),
      ];

      const result = await assessor.assess(mockContext);

      // v1.22.5: Both should be ALIGNED (trust explicit annotations), not REVIEW_RECOMMENDED
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      expect(result.toolResults[1].alignmentStatus).toBe("ALIGNED");
      // Assessment should NOT fail
      expect(result.status).not.toBe("FAIL");
    });
  });
});
