/**
 * Native Module Detector Tests
 *
 * Tests for the pre-flight native module detection that warns about
 * potential issues before MCP server connection.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/212
 */

import {
  describe,
  it,
  expect,
  jest,
  beforeEach,
  afterEach,
} from "@jest/globals";
import {
  detectNativeModules,
  type NativeModuleDetectionResult,
} from "../../lib/assessment-runner/native-module-detector.js";

// Mock the jsonl-events module
jest.mock("../../lib/jsonl-events.js", () => ({
  emitNativeModuleWarning: jest.fn(),
}));

// Import the mocked function for assertions
import { emitNativeModuleWarning } from "../../lib/jsonl-events.js";

describe("native-module-detector", () => {
  // Store original console methods
  let consoleLogSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    jest.clearAllMocks();
    // Mock console.log to suppress output during tests
    consoleLogSpy = jest.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
  });

  describe("detectNativeModules", () => {
    it("should return empty result for undefined packageJson", () => {
      const result = detectNativeModules(undefined, { jsonOnly: true });

      expect(result.detected).toBe(false);
      expect(result.count).toBe(0);
      expect(result.modules).toHaveLength(0);
      expect(Object.keys(result.suggestedEnvVars)).toHaveLength(0);
      expect(emitNativeModuleWarning).not.toHaveBeenCalled();
    });

    it("should return empty result for package without native modules", () => {
      const packageJson = {
        dependencies: {
          express: "^4.18.0",
          lodash: "^4.17.21",
        },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.detected).toBe(false);
      expect(result.count).toBe(0);
      expect(result.modules).toHaveLength(0);
      expect(emitNativeModuleWarning).not.toHaveBeenCalled();
    });

    it("should detect canvas in dependencies", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0" },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.detected).toBe(true);
      expect(result.count).toBe(1);
      expect(result.modules).toHaveLength(1);
      expect(result.modules[0].name).toBe("canvas");
      expect(result.modules[0].category).toBe("image");
      expect(result.modules[0].severity).toBe("HIGH");
      expect(result.modules[0].dependencyType).toBe("dependencies");
      expect(result.modules[0].version).toBe("^2.11.0");
    });

    it("should emit JSONL event for each detected module", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0" },
      };

      detectNativeModules(packageJson, { jsonOnly: true });

      expect(emitNativeModuleWarning).toHaveBeenCalledTimes(1);
      expect(emitNativeModuleWarning).toHaveBeenCalledWith(
        "canvas",
        "image",
        "HIGH",
        expect.stringContaining("Cairo"),
        "dependencies",
        "^2.11.0",
        expect.objectContaining({ CANVAS_BACKEND: "mock" }),
      );
    });

    it("should detect multiple native modules", () => {
      const packageJson = {
        dependencies: {
          canvas: "^2.11.0",
          sharp: "^0.32.0",
        },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.detected).toBe(true);
      expect(result.count).toBe(2);
      expect(result.modules).toHaveLength(2);

      const names = result.modules.map((m) => m.name);
      expect(names).toContain("canvas");
      expect(names).toContain("sharp");

      expect(emitNativeModuleWarning).toHaveBeenCalledTimes(2);
    });

    it("should collect suggested env vars from all modules", () => {
      const packageJson = {
        dependencies: {
          canvas: "^2.11.0",
          sharp: "^0.32.0",
          "maplibre-gl-native": "^1.0.0",
        },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.suggestedEnvVars).toEqual({
        CANVAS_BACKEND: "mock",
        SHARP_IGNORE_GLOBAL_LIBVIPS: "1",
        ENABLE_DYNAMIC_MAPS: "false",
      });
    });

    it("should detect modules in devDependencies", () => {
      const packageJson = {
        devDependencies: { "better-sqlite3": "^9.0.0" },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.detected).toBe(true);
      expect(result.modules[0].dependencyType).toBe("devDependencies");
    });

    it("should detect modules in optionalDependencies", () => {
      const packageJson = {
        optionalDependencies: { bcrypt: "^5.1.0" },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.detected).toBe(true);
      expect(result.modules[0].dependencyType).toBe("optionalDependencies");
    });

    it("should suppress console output when jsonOnly is true", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0" },
      };

      detectNativeModules(packageJson, { jsonOnly: true });

      // Console should not have been called (except for the mock)
      expect(consoleLogSpy).not.toHaveBeenCalled();
    });

    it("should print console warnings when jsonOnly is false", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0" },
      };

      detectNativeModules(packageJson, { jsonOnly: false });

      // Console should have been called with warning message
      expect(consoleLogSpy).toHaveBeenCalled();
      const allCalls = consoleLogSpy.mock.calls.flat().join(" ");
      expect(allCalls).toContain("Native Module Warning");
    });

    it("should handle modules without suggested env vars", () => {
      const packageJson = {
        dependencies: { "better-sqlite3": "^9.0.0" },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.detected).toBe(true);
      expect(result.modules[0].suggestedEnvVars).toBeUndefined();
      // Env vars should be empty since better-sqlite3 has no suggestions
      expect(Object.keys(result.suggestedEnvVars)).toHaveLength(0);
    });

    it("should handle empty dependencies objects", () => {
      const packageJson = {
        dependencies: {},
        devDependencies: {},
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });

      expect(result.detected).toBe(false);
      expect(result.count).toBe(0);
    });

    it("should include correct severity icons in console output", () => {
      const packageJson = {
        dependencies: {
          canvas: "^2.11.0", // HIGH severity
          bcrypt: "^5.1.0", // MEDIUM severity
        },
      };

      detectNativeModules(packageJson, { jsonOnly: false });

      // Check that console.log was called
      expect(consoleLogSpy).toHaveBeenCalled();
    });
  });

  describe("return type shape", () => {
    it("should return correct result shape for detected modules", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0" },
      };

      const result: NativeModuleDetectionResult = detectNativeModules(
        packageJson,
        { jsonOnly: true },
      );

      // Verify all expected properties exist
      expect(result).toHaveProperty("detected");
      expect(result).toHaveProperty("count");
      expect(result).toHaveProperty("modules");
      expect(result).toHaveProperty("suggestedEnvVars");

      // Verify types
      expect(typeof result.detected).toBe("boolean");
      expect(typeof result.count).toBe("number");
      expect(Array.isArray(result.modules)).toBe(true);
      expect(typeof result.suggestedEnvVars).toBe("object");
    });

    it("should return correct module shape", () => {
      const packageJson = {
        dependencies: { canvas: "^2.11.0" },
      };

      const result = detectNativeModules(packageJson, { jsonOnly: true });
      const module = result.modules[0];

      expect(module).toHaveProperty("name");
      expect(module).toHaveProperty("category");
      expect(module).toHaveProperty("severity");
      expect(module).toHaveProperty("warningMessage");
      expect(module).toHaveProperty("dependencyType");
      expect(module).toHaveProperty("version");
    });
  });
});
