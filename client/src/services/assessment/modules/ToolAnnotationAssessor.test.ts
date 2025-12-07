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

    it("should infer write (non-destructive) behavior from tool name patterns", async () => {
      const writeNames = [
        "create_item",
        "add_user",
        "update_record",
        "modify_setting",
        "save_data",
      ];

      for (const name of writeNames) {
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
});
