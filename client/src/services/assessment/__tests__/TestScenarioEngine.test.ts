/**
 * TestScenarioEngine Test Suite
 * Tests multi-scenario tool testing orchestration
 *
 * Note: TestScenarioEngine is currently dead code (not imported anywhere)
 * but these tests validate its functionality for future integration.
 *
 * This file contains core functionality tests.
 * See related test files for specific feature areas:
 * - TestScenarioEngine.paramGeneration.test.ts - Parameter generation tests
 * - TestScenarioEngine.execution.test.ts - Scenario execution tests
 * - TestScenarioEngine.status.test.ts - Status determination tests
 * - TestScenarioEngine.reporting.test.ts - Report generation tests
 * - TestScenarioEngine.integration.test.ts - End-to-end workflow tests
 */

import { TestScenarioEngine } from "../TestScenarioEngine";
import { getPrivateProperty } from "@/test/utils/testUtils";

describe("TestScenarioEngine", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Constructor and Configuration", () => {
    it("should use default timeout of 5000ms when not specified", () => {
      const engine = new TestScenarioEngine();
      expect(
        getPrivateProperty<TestScenarioEngine, number>(engine, "testTimeout"),
      ).toBe(5000);
    });

    it("should use default delayBetweenTests of 0 when not specified", () => {
      const engine = new TestScenarioEngine();
      expect(
        getPrivateProperty<TestScenarioEngine, number>(
          engine,
          "delayBetweenTests",
        ),
      ).toBe(0);
    });

    it("should accept custom testTimeout value", () => {
      const engine = new TestScenarioEngine(10000);
      expect(
        getPrivateProperty<TestScenarioEngine, number>(engine, "testTimeout"),
      ).toBe(10000);
    });

    it("should accept custom delayBetweenTests value", () => {
      const engine = new TestScenarioEngine(5000, 100);
      expect(
        getPrivateProperty<TestScenarioEngine, number>(
          engine,
          "delayBetweenTests",
        ),
      ).toBe(100);
    });

    it("should handle zero timeout", () => {
      const engine = new TestScenarioEngine(0);
      expect(
        getPrivateProperty<TestScenarioEngine, number>(engine, "testTimeout"),
      ).toBe(0);
    });

    it("should handle large timeout values", () => {
      const engine = new TestScenarioEngine(600000);
      expect(
        getPrivateProperty<TestScenarioEngine, number>(engine, "testTimeout"),
      ).toBe(600000);
    });
  });
});
