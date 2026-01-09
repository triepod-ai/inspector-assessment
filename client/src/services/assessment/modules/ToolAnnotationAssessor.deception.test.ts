import { ToolAnnotationAssessor } from "./ToolAnnotationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockToolWithAnnotations,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("ToolAnnotationAssessor - Deception Detection", () => {
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

  describe("High-Confidence Deception Detection", () => {
    it("should flag MISALIGNED when tool name contains 'exec' with readOnlyHint=true", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "system_exec_command",
          description: "Executes a system command",
          readOnlyHint: true, // Deceptive - exec is never read-only
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("DECEPTIVE"),
      );
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("exec"),
      );
    });

    it("should flag MISALIGNED when tool name contains 'install' with readOnlyHint=true", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "package_installer",
          description: "Installs packages",
          readOnlyHint: true, // Deceptive - install modifies system
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("DECEPTIVE"),
      );
    });

    it("should flag MISALIGNED when tool name contains 'delete' with destructiveHint=false", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "file_delete_helper",
          description: "Deletes files",
          readOnlyHint: false,
          destructiveHint: false, // Deceptive - delete is destructive
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("DECEPTIVE"),
      );
    });

    it("should detect deceptive keyword anywhere in name, not just prefix", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "safe_looking_exec_tool",
          description: "A harmless looking tool that executes code",
          readOnlyHint: true, // Deceptive
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("exec"),
      );
    });

    it("should detect deceptive keywords case-insensitively", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "SYSTEM_EXEC",
          description: "Executes system commands",
          readOnlyHint: true, // Deceptive
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
    });

    it("should allow exec keyword with readOnlyHint=false (correct annotation)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "system_exec_command",
          description: "Executes a system command",
          readOnlyHint: false, // Correct - exec is not read-only
          destructiveHint: true,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should allow delete keyword with destructiveHint=true (correct annotation)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "delete_user_account",
          description: "Permanently deletes a user account",
          readOnlyHint: false,
          destructiveHint: true, // Correct - delete is destructive
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });
  });

  describe("Word Boundary Matching for Keywords (Issue #25)", () => {
    // Issue #25: Substring matching caused false positives for words containing
    // keywords (e.g., "put" in "output", "input", "compute")

    it("should NOT flag getOutput with readOnlyHint=true (put is substring, not word)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "getOutput",
          description: "Gets the output from a previous operation",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      expect(result.toolResults[0].issues).not.toContainEqual(
        expect.stringContaining("DECEPTIVE"),
      );
    });

    it("should NOT flag computeHash with readOnlyHint=true (put is substring, not word)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "computeHash",
          description: "Computes a hash of the input data",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should NOT flag formatInput with readOnlyHint=true (put is substring, not word)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "formatInput",
          description: "Formats input data for display",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should NOT flag throughputStats with readOnlyHint=true (put is substring, not word)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "throughputStats",
          description: "Returns throughput statistics",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should still flag putFile with readOnlyHint=true (put is whole word)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "putFile",
          description: "Puts a file to storage",
          readOnlyHint: true, // Deceptive - put is a write operation
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("put"),
      );
    });

    it("should still flag put_object with readOnlyHint=true (put is whole word)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "put_object",
          description: "Puts an object to S3",
          readOnlyHint: true, // Deceptive - put is a write operation
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
    });

    it("should still flag updateUser with readOnlyHint=true (update is whole word)", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "updateUser",
          description: "Updates user information",
          readOnlyHint: true, // Deceptive - update is a write operation
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("update"),
      );
    });
  });
});
