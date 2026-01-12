/**
 * Assessment Runner Facade Backward Compatibility Tests
 *
 * Verifies that the facade pattern maintains backward compatibility
 * after the modularization in Issue #94.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/96
 */

import { describe, it, expect } from "@jest/globals";

// Test named imports (the primary consumer pattern)
import {
  loadServerConfig,
  loadSourceFiles,
  connectToServer,
  createCallToolWrapper,
  buildConfig,
  runFullAssessment,
} from "../lib/assessment-runner.js";

// Test namespace import
import * as AssessmentRunner from "../lib/assessment-runner.js";

// Test type imports
import type { SourceFiles, CallToolFn } from "../lib/assessment-runner.js";

describe("Assessment Runner Facade", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Function Exports", () => {
    it("should export loadServerConfig function", () => {
      expect(typeof loadServerConfig).toBe("function");
    });

    it("should export loadSourceFiles function", () => {
      expect(typeof loadSourceFiles).toBe("function");
    });

    it("should export connectToServer function", () => {
      expect(typeof connectToServer).toBe("function");
    });

    it("should export createCallToolWrapper function", () => {
      expect(typeof createCallToolWrapper).toBe("function");
    });

    it("should export buildConfig function", () => {
      expect(typeof buildConfig).toBe("function");
    });

    it("should export runFullAssessment function", () => {
      expect(typeof runFullAssessment).toBe("function");
    });
  });

  describe("Namespace Import Compatibility", () => {
    it("should export all functions via namespace import", () => {
      expect(typeof AssessmentRunner.loadServerConfig).toBe("function");
      expect(typeof AssessmentRunner.loadSourceFiles).toBe("function");
      expect(typeof AssessmentRunner.connectToServer).toBe("function");
      expect(typeof AssessmentRunner.createCallToolWrapper).toBe("function");
      expect(typeof AssessmentRunner.buildConfig).toBe("function");
      expect(typeof AssessmentRunner.runFullAssessment).toBe("function");
    });

    it("should have consistent function references between import styles", () => {
      // Verify that named imports and namespace imports reference the same functions
      expect(loadServerConfig).toBe(AssessmentRunner.loadServerConfig);
      expect(loadSourceFiles).toBe(AssessmentRunner.loadSourceFiles);
      expect(connectToServer).toBe(AssessmentRunner.connectToServer);
      expect(createCallToolWrapper).toBe(
        AssessmentRunner.createCallToolWrapper,
      );
      expect(buildConfig).toBe(AssessmentRunner.buildConfig);
      expect(runFullAssessment).toBe(AssessmentRunner.runFullAssessment);
    });
  });

  describe("Type Exports", () => {
    it("should export SourceFiles type with expected shape", () => {
      // TypeScript compile-time check - if this compiles, the type is exported correctly
      const sourceFiles: SourceFiles = {
        readmeContent: "# Test",
        packageJson: { name: "test" },
        manifestJson: undefined,
        manifestRaw: undefined,
        sourceCodeFiles: new Map(),
      };

      // Runtime verification of the shape
      expect(sourceFiles).toHaveProperty("readmeContent");
      expect(sourceFiles).toHaveProperty("packageJson");
      expect(sourceFiles).toHaveProperty("sourceCodeFiles");
    });

    it("should export CallToolFn type", () => {
      // TypeScript compile-time check - if this compiles, the type is exported correctly
      const mockCallTool: CallToolFn = async (name, params) => {
        return {
          content: [{ type: "text", text: `Called ${name}` }],
          isError: false,
        };
      };

      // Verify the function signature works
      expect(typeof mockCallTool).toBe("function");
    });
  });

  describe("Export Completeness", () => {
    it("should export exactly 6 functions", () => {
      const exportedFunctions = Object.entries(AssessmentRunner).filter(
        ([, value]) => typeof value === "function",
      );

      expect(exportedFunctions.length).toBe(6);
      expect(exportedFunctions.map(([name]) => name).sort()).toEqual([
        "buildConfig",
        "connectToServer",
        "createCallToolWrapper",
        "loadServerConfig",
        "loadSourceFiles",
        "runFullAssessment",
      ]);
    });

    it("should not have unexpected exports", () => {
      const allExports = Object.keys(AssessmentRunner);
      const expectedExports = [
        "loadServerConfig",
        "loadSourceFiles",
        "connectToServer",
        "createCallToolWrapper",
        "buildConfig",
        "runFullAssessment",
      ];

      // All exports should be in the expected list
      for (const exportName of allExports) {
        expect(expectedExports).toContain(exportName);
      }
    });
  });

  describe("Consumer Compatibility", () => {
    it("should support the existing assess-full.ts import pattern", () => {
      // This is the exact import pattern used in assess-full.ts:18
      // import { runFullAssessment } from "./lib/assessment-runner.js";
      expect(runFullAssessment).toBeDefined();
      expect(typeof runFullAssessment).toBe("function");
    });
  });
});
