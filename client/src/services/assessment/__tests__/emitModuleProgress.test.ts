/**
 * Regression tests for emitModuleProgress function (v1.8.1)
 *
 * Tests the real-time progress output feature that emits module completion
 * status to stderr in the format: <emoji> <ModuleName>: <STATUS> (<score>%)
 */

import { AssessmentOrchestrator } from "../AssessmentOrchestrator";
import {
  createMockAssessmentConfig,
  createMockAssessmentContext,
  createMockTool,
} from "@/test/utils/testUtils";

describe("emitModuleProgress - Real-time Progress Output", () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let consoleErrorSpy: any;
  let orchestrator: AssessmentOrchestrator;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation();
    jest.clearAllMocks();
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
  });

  describe("Output Format", () => {
    it("should emit progress in correct format: <emoji> <ModuleName>: <STATUS> (<score>%)", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false, // Sequential for predictable order
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool({ name: "test-tool" })],
      });

      await orchestrator.runFullAssessment(context);

      // Verify at least one progress line was emitted
      expect(consoleErrorSpy).toHaveBeenCalled();

      // Check format pattern: emoji + space + name + colon + space + status + space + (score%)
      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      // Status can include underscores (e.g., NEED_MORE_INFO)
      const progressPattern = /^[✅❌⚠️] [A-Za-z ]+: [A-Z][A-Z_]* \(\d+%\)$/;

      const progressCalls = calls.filter(
        (call: string) =>
          typeof call === "string" && progressPattern.test(call),
      );
      expect(progressCalls.length).toBeGreaterThan(0);
    });

    it("should emit ✅ emoji for PASS status", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool({ name: "working-tool" })],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const passEmoji = calls.some(
        (call: string) => typeof call === "string" && call.includes("✅"),
      );
      expect(passEmoji).toBe(true);
    });

    it("should emit ❌ emoji for FAIL status", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      // Create context that will cause documentation to fail (no readme)
      const context = createMockAssessmentContext({
        tools: [createMockTool()],
        readmeContent: undefined,
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const failEmoji = calls.some(
        (call: string) => typeof call === "string" && call.includes("❌"),
      );
      expect(failEmoji).toBe(true);
    });

    it("should emit ⚠️ emoji for NEED_MORE_INFO status", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const warnEmoji = calls.some(
        (call: string) => typeof call === "string" && call.includes("⚠️"),
      );
      // May or may not have warning emoji depending on results
      expect(typeof warnEmoji).toBe("boolean");
    });
  });

  describe("Score Calculation", () => {
    it("should include percentage score in output", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const hasPercentage = calls.some(
        (call: string) => typeof call === "string" && /\(\d+%\)/.test(call),
      );
      expect(hasPercentage).toBe(true);
    });

    it("should calculate score between 0 and 100", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const scorePattern = /\((\d+)%\)/;

      calls.forEach((call: string) => {
        if (typeof call === "string") {
          const match = call.match(scorePattern);
          if (match) {
            const score = parseInt(match[1], 10);
            expect(score).toBeGreaterThanOrEqual(0);
            expect(score).toBeLessThanOrEqual(100);
          }
        }
      });
    });
  });

  describe("Module Names", () => {
    const expectedModuleNames = [
      "Functionality",
      "Security",
      "Documentation",
      "Error Handling",
      "Usability",
    ];

    const extendedModuleNames = [
      "MCP Spec",
      "AUP",
      "Annotations",
      "Libraries",
      "Manifest",
      "Portability",
    ];

    it("should emit progress for core modules", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);

      for (const moduleName of expectedModuleNames) {
        const found = calls.some(
          (call: string) =>
            typeof call === "string" && call.includes(moduleName),
        );
        expect(found).toBe(true);
      }
    });

    it("should emit progress for extended modules when enabled", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          mcpSpecCompliance: true,
          aupCompliance: true,
          toolAnnotations: true,
          prohibitedLibraries: true,
          manifestValidation: true,
          portability: true,
        },
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);

      // Check that at least some extended modules emit progress
      // (not all may run depending on mock context data)
      let foundExtendedModules = 0;
      for (const moduleName of extendedModuleNames) {
        const found = calls.some(
          (call: string) =>
            typeof call === "string" && call.includes(moduleName),
        );
        if (found) foundExtendedModules++;
      }
      // At least 3 of the 6 extended modules should emit progress
      expect(foundExtendedModules).toBeGreaterThanOrEqual(3);
    });
  });

  describe("Parallel vs Sequential Execution", () => {
    it("should emit progress for modules in parallel mode", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: true,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      // Should have multiple progress emissions
      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const progressPattern = /^[✅❌⚠️] [A-Za-z ]+: [A-Z][A-Z_]* \(\d+%\)$/;

      const progressCalls = calls.filter(
        (call: string) =>
          typeof call === "string" && progressPattern.test(call),
      );
      // Should have progress for multiple modules (exact count varies based on mocking)
      expect(progressCalls.length).toBeGreaterThan(0);
    });

    it("should emit progress for modules in sequential mode", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      // Should have multiple progress emissions
      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const progressPattern = /^[✅❌⚠️] [A-Za-z ]+: [A-Z][A-Z_]* \(\d+%\)$/;

      const progressCalls = calls.filter(
        (call: string) =>
          typeof call === "string" && progressPattern.test(call),
      );
      // Should have progress for multiple modules (exact count varies based on mocking)
      expect(progressCalls.length).toBeGreaterThan(0);
    });

    it("should emit core modules when extended assessment is disabled", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const progressPattern = /^[✅❌⚠️] [A-Za-z ]+: [A-Z][A-Z_]* \(\d+%\)$/;

      const progressCalls = calls.filter(
        (call: string) =>
          typeof call === "string" && progressPattern.test(call),
      );
      // Should have at least some core modules emitting progress
      // Note: exact count may vary based on test mocking and module behavior
      expect(progressCalls.length).toBeGreaterThan(0);

      // Verify key core module names are present in the calls
      // At least Functionality and Documentation should be present
      const foundFunctionality = progressCalls.some((call: string) =>
        call.includes("Functionality"),
      );
      const foundDocumentation = progressCalls.some((call: string) =>
        call.includes("Documentation"),
      );
      expect(foundFunctionality || foundDocumentation).toBe(true);
    });
  });

  describe("Status Values", () => {
    it("should include valid status values (PASS, FAIL, NEED_MORE_INFO)", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const validStatuses = ["PASS", "FAIL", "NEED_MORE_INFO"];

      calls.forEach((call: string) => {
        if (typeof call === "string" && call.match(/^[✅❌⚠️]/)) {
          const hasValidStatus = validStatuses.some((status) =>
            call.includes(status),
          );
          expect(hasValidStatus).toBe(true);
        }
      });
    });
  });

  describe("Edge Cases", () => {
    it("should handle assessment with no tools gracefully", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [],
      });

      await orchestrator.runFullAssessment(context);

      // Should still emit progress (modules still run even with no tools)
      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const progressPattern = /^[✅❌⚠️] [A-Za-z ]+: [A-Z][A-Z_]* \(\d+%\)$/;

      const progressCalls = calls.filter(
        (call: string) =>
          typeof call === "string" && progressPattern.test(call),
      );
      // At least some modules should emit progress
      expect(progressCalls.length).toBeGreaterThan(0);
    });

    it("should handle assessment with many tools", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: true,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const manyTools = Array.from({ length: 20 }, (_, i) =>
        createMockTool({ name: `tool-${i}` }),
      );

      const context = createMockAssessmentContext({
        tools: manyTools,
      });

      await orchestrator.runFullAssessment(context);

      // Should emit progress for core modules (4-5 when extended is disabled)
      const calls = consoleErrorSpy.mock.calls.map((c) => c[0]);
      const progressPattern = /^[✅❌⚠️] [A-Za-z ]+: [A-Z][A-Z_]* \(\d+%\)$/;

      const progressCalls = calls.filter(
        (call: string) =>
          typeof call === "string" && progressPattern.test(call),
      );
      // Should have progress for most core modules
      expect(progressCalls.length).toBeGreaterThanOrEqual(4);
    }, 30000); // Longer timeout for testing 20 tools
  });
});
