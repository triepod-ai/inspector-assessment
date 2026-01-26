/**
 * Assessment Runner Index Unit Tests
 *
 * Tests for the facade module exports.
 */

import { jest, describe, it, expect, afterEach } from "@jest/globals";

// Import the barrel/facade module
import * as assessmentRunner from "../../lib/assessment-runner/index.js";

describe("assessment-runner index exports", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("function exports", () => {
    it("should export all 10 public functions", () => {
      expect(typeof assessmentRunner.loadServerConfig).toBe("function");
      expect(typeof assessmentRunner.loadSourceFiles).toBe("function");
      expect(typeof assessmentRunner.resolveSourcePath).toBe("function");
      expect(typeof assessmentRunner.connectToServer).toBe("function");
      expect(typeof assessmentRunner.createCallToolWrapper).toBe("function");
      expect(typeof assessmentRunner.buildConfig).toBe("function");
      expect(typeof assessmentRunner.runFullAssessment).toBe("function");
      // Issue #184: Single module execution
      expect(typeof assessmentRunner.runSingleModule).toBe("function");
      expect(typeof assessmentRunner.getValidModuleNames).toBe("function");
      // Issue #212: Native module detection
      expect(typeof assessmentRunner.detectNativeModules).toBe("function");
    });

    it("should export exactly 10 functions", () => {
      const functionNames = Object.keys(assessmentRunner).filter(
        (key) =>
          typeof assessmentRunner[key as keyof typeof assessmentRunner] ===
          "function",
      );
      expect(functionNames).toHaveLength(10);
      expect(functionNames.sort()).toEqual([
        "buildConfig",
        "connectToServer",
        "createCallToolWrapper",
        "detectNativeModules", // Issue #212
        "getValidModuleNames", // Issue #184
        "loadServerConfig",
        "loadSourceFiles",
        "resolveSourcePath",
        "runFullAssessment",
        "runSingleModule", // Issue #184
      ]);
    });
  });

  describe("type exports", () => {
    // Type exports are compile-time only, but we can verify
    // the module structure doesn't break TypeScript compilation
    it("should export module without errors", () => {
      // If we got here, the module exported successfully
      expect(assessmentRunner).toBeDefined();
    });
  });
});
