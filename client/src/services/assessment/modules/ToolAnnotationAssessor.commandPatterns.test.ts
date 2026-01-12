import { ToolAnnotationAssessor } from "./ToolAnnotationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockToolWithAnnotations,
  createMockTool,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("ToolAnnotationAssessor - Command Patterns", () => {
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

  describe("Command Execution Tools (Issue #17)", () => {
    it("should treat run_command as destructive (not write) with high confidence", async () => {
      // Arrange - command execution tool
      // Issue #17: run_command should be destructive, not write
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "run_command",
          description: "Executes arbitrary shell commands",
          readOnlyHint: false,
          destructiveHint: true, // Correct annotation - command execution IS destructive
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - run_command should be inferred as destructive (high confidence)
      expect(result.toolResults[0].inferredBehavior?.expectedDestructive).toBe(
        true,
      );
      expect(result.toolResults[0].inferredBehavior?.confidence).toBe("high");
      expect(result.toolResults[0].inferredBehavior?.isAmbiguous).toBe(false);
      // With destructiveHint=true matching inference, should be ALIGNED
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      expect(result.status).not.toBe("FAIL");
    });

    it("should flag run_command with destructiveHint=false as MISALIGNED", async () => {
      // Arrange - command execution tool with wrong annotation
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "run_command",
          description: "Executes arbitrary shell commands",
          readOnlyHint: false,
          destructiveHint: false, // WRONG - command execution can be destructive
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - should detect the misalignment
      expect(result.toolResults[0].inferredBehavior?.expectedDestructive).toBe(
        true,
      );
      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.status).toBe("FAIL");
    });

    it("should treat various command execution patterns as destructive", async () => {
      // All these command execution patterns should be inferred as destructive
      const commandExecutionTools = [
        "run_command",
        "exec_command",
        "execute_command",
        "shell_command",
        "bash_command",
        "run_shell",
        "exec_shell",
        "cmd_run",
      ];

      for (const toolName of commandExecutionTools) {
        mockContext.tools = [
          createMockTool({ name: toolName, description: "Executes commands" }),
        ];
        const result = await assessor.assess(mockContext);

        // Command execution tools should be inferred as destructive with high confidence
        expect(
          result.toolResults[0].inferredBehavior?.expectedDestructive,
        ).toBe(true);
        expect(result.toolResults[0].inferredBehavior?.confidence).toBe("high");
      }
    });

    it("should NOT affect generic run_ tools (only command execution patterns)", async () => {
      // Generic "run_" tools should still be treated as write (medium confidence)
      const genericRunTools = ["run_tests", "run_migration", "run_build"];

      for (const toolName of genericRunTools) {
        mockContext.tools = [
          createMockTool({ name: toolName, description: "Runs something" }),
        ];
        const result = await assessor.assess(mockContext);

        // Generic run_ should be write (medium confidence), NOT destructive
        // Write operations have expectedDestructive=false
        expect(
          result.toolResults[0].inferredBehavior?.expectedDestructive,
        ).toBe(false);
        expect(result.toolResults[0].inferredBehavior?.confidence).toBe(
          "medium",
        );
      }
    });
  });

  describe("Run Keyword Exemption for Analysis Tools (Issue #18)", () => {
    it("should NOT flag runAccessibilityAudit with readOnlyHint=true as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "runAccessibilityAudit",
          description: "Runs accessibility audit and returns results",
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

    it("should NOT flag runSEOAudit with readOnlyHint=true as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "runSEOAudit",
          description: "Analyzes page for SEO improvements",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should NOT flag runPerformanceAudit with readOnlyHint=true as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "runPerformanceAudit",
          description: "Gets performance metrics for the page",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should NOT flag runAuditMode with readOnlyHint=true as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "runAuditMode",
          description: "Returns static audit workflow prompt",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should NOT flag runHealthCheck with readOnlyHint=true as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "runHealthCheck",
          description: "Checks service health status",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should STILL flag run_command with readOnlyHint=true as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "run_command",
          description: "Executes shell commands",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
      expect(result.toolResults[0].issues).toContainEqual(
        expect.stringContaining("DECEPTIVE"),
      );
    });

    it("should STILL flag run_shell with readOnlyHint=true as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "run_shell",
          description: "Runs shell scripts",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);
      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
    });

    it("should STILL flag generic run_process without analysis suffix as deceptive", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "run_process",
          description: "Runs a process",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);
      expect(result.toolResults[0].alignmentStatus).toBe("MISALIGNED");
    });

    it("should handle exempt suffixes case-insensitively", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "RUNAUDIT",
          description: "Runs an audit",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);
      expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
    });

    it("should handle all exempt suffixes", async () => {
      const exemptTools = [
        "runAudit",
        "runCheck",
        "runMode",
        "runTest",
        "runScan",
        "runAnalyze",
        "runReport",
        "runStatus",
        "runValidate",
        "runVerify",
        "runInspect",
        "runLint",
        "runBenchmark",
        "runDiagnostic",
      ];

      for (const toolName of exemptTools) {
        mockContext.tools = [
          createMockToolWithAnnotations({
            name: toolName,
            description: `Performs ${toolName} operation`,
            readOnlyHint: true,
            destructiveHint: false,
          }),
        ];

        const result = await assessor.assess(mockContext);
        expect(result.toolResults[0].alignmentStatus).toBe("ALIGNED");
      }
    });
  });
});
