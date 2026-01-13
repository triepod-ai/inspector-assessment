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
    it("should export all 7 public functions", () => {
      expect(typeof assessmentRunner.loadServerConfig).toBe("function");
      expect(typeof assessmentRunner.loadSourceFiles).toBe("function");
      expect(typeof assessmentRunner.resolveSourcePath).toBe("function");
      expect(typeof assessmentRunner.connectToServer).toBe("function");
      expect(typeof assessmentRunner.createCallToolWrapper).toBe("function");
      expect(typeof assessmentRunner.buildConfig).toBe("function");
      expect(typeof assessmentRunner.runFullAssessment).toBe("function");
    });

    it("should export exactly 7 functions", () => {
      const functionNames = Object.keys(assessmentRunner).filter(
        (key) =>
          typeof assessmentRunner[key as keyof typeof assessmentRunner] ===
          "function",
      );
      expect(functionNames).toHaveLength(7);
      expect(functionNames.sort()).toEqual([
        "buildConfig",
        "connectToServer",
        "createCallToolWrapper",
        "loadServerConfig",
        "loadSourceFiles",
        "resolveSourcePath",
        "runFullAssessment",
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
