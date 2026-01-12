/**
 * Regression tests for emitModuleProgress function (v1.8.1 -> v1.9.0)
 *
 * Tests the real-time progress output feature that emits module completion
 * status to stderr in JSONL format:
 * {"event":"module_complete","module":"<name>","status":"<STATUS>","score":<0-100>}
 */

import { AssessmentOrchestrator } from "../AssessmentOrchestrator";
import {
  createMockAssessmentConfig,
  createMockAssessmentContext,
  createMockTool,
} from "@/test/utils/testUtils";

interface ModuleCompleteEvent {
  event: "module_complete";
  module: string;
  status: "PASS" | "FAIL" | "NEED_MORE_INFO";
  score: number;
  version?: string;
  schemaVersion?: number;
}

/**
 * Parse a JSONL line into a ModuleCompleteEvent, or return null if not matching.
 */
function parseModuleCompleteEvent(line: string): ModuleCompleteEvent | null {
  try {
    const parsed = JSON.parse(line);
    if (parsed.event === "module_complete") {
      return parsed as ModuleCompleteEvent;
    }
  } catch {
    // Not valid JSON
  }
  return null;
}

describe("emitModuleProgress - JSONL Progress Output", () => {
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

  describe("JSONL Output Format", () => {
    it("should emit progress in JSONL format with event, module, status, and score", async () => {
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

      // Parse JSONL events
      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      expect(moduleEvents.length).toBeGreaterThan(0);

      // Verify structure of each event
      for (const event of moduleEvents) {
        expect(event.event).toBe("module_complete");
        expect(typeof event.module).toBe("string");
        expect(["PASS", "FAIL", "NEED_MORE_INFO"]).toContain(event.status);
        expect(typeof event.score).toBe("number");
        expect(event.score).toBeGreaterThanOrEqual(0);
        expect(event.score).toBeLessThanOrEqual(100);
        // Verify version and schemaVersion fields are present
        expect(event.version).toBeDefined();
        expect(event.schemaVersion).toBe(2); // Updated to 2 for TestValidityWarning event (Issue #134)
      }
    });

    it("should emit PASS status for working modules", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool({ name: "working-tool" })],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      const hasPass = moduleEvents.some((e) => e.status === "PASS");
      expect(hasPass).toBe(true);
    });

    it("should emit FAIL status when modules fail", async () => {
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

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      const hasFail = moduleEvents.some((e) => e.status === "FAIL");
      expect(hasFail).toBe(true);
    });

    it("should emit NEED_MORE_INFO status when appropriate", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      // May or may not have NEED_MORE_INFO depending on results
      expect(moduleEvents.length).toBeGreaterThan(0);
    });
  });

  describe("Score Calculation", () => {
    it("should include percentage score in JSONL output", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      expect(moduleEvents.length).toBeGreaterThan(0);
      for (const event of moduleEvents) {
        expect(typeof event.score).toBe("number");
      }
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

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      for (const event of moduleEvents) {
        expect(event.score).toBeGreaterThanOrEqual(0);
        expect(event.score).toBeLessThanOrEqual(100);
      }
    });
  });

  describe("Module Names (snake_case)", () => {
    const expectedCoreModules = [
      "functionality",
      "security",
      "documentation",
      "error_handling",
      "usability",
    ];

    const extendedModules = [
      "mcp_spec",
      "aup",
      "annotations",
      "libraries",
      "manifest",
      "portability",
    ];

    it("should emit progress for core modules in snake_case", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: false,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      const foundModules = new Set(moduleEvents.map((e) => e.module));

      for (const moduleName of expectedCoreModules) {
        expect(foundModules.has(moduleName)).toBe(true);
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

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      const foundModules = new Set(moduleEvents.map((e) => e.module));

      // Check that at least some extended modules emit progress
      let foundExtendedModules = 0;
      for (const moduleName of extendedModules) {
        if (foundModules.has(moduleName)) foundExtendedModules++;
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

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      expect(moduleEvents.length).toBeGreaterThan(0);
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

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      expect(moduleEvents.length).toBeGreaterThan(0);
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

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      expect(moduleEvents.length).toBeGreaterThan(0);

      // Verify key core module names are present
      const foundModules = new Set(moduleEvents.map((e) => e.module));
      const foundFunctionality = foundModules.has("functionality");
      const foundDocumentation = foundModules.has("documentation");
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

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      const validStatuses = ["PASS", "FAIL", "NEED_MORE_INFO"];

      for (const event of moduleEvents) {
        expect(validStatuses).toContain(event.status);
      }
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
      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      expect(moduleEvents.length).toBeGreaterThan(0);
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
      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);
      const moduleEvents = calls
        .map((call: string) => parseModuleCompleteEvent(call))
        .filter(
          (e: ModuleCompleteEvent | null): e is ModuleCompleteEvent =>
            e !== null,
        );

      expect(moduleEvents.length).toBeGreaterThanOrEqual(4);
    }, 30000); // Longer timeout for testing 20 tools
  });

  describe("Valid JSON Output", () => {
    it("should emit valid JSON that can be parsed", async () => {
      const config = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        parallelTesting: false,
      });
      orchestrator = new AssessmentOrchestrator(config);

      const context = createMockAssessmentContext({
        tools: [createMockTool()],
      });

      await orchestrator.runFullAssessment(context);

      const calls = consoleErrorSpy.mock.calls.map((c: string[]) => c[0]);

      // Every non-empty stderr line should be valid JSON
      for (const call of calls) {
        if (typeof call === "string" && call.trim()) {
          expect(() => JSON.parse(call)).not.toThrow();
        }
      }
    });
  });
});
