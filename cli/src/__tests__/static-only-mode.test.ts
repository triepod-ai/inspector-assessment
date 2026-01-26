/**
 * Static-Only Mode Unit Tests
 *
 * Tests for Issue #213: Static/manifest-only validation mode.
 *
 * Tests cover:
 * - CLI flag parsing for --static-only and --fallback-static
 * - Mutual exclusivity validation
 * - Static module configuration
 * - Config builder static mode handling
 */

import {
  describe,
  it,
  expect,
  jest,
  beforeEach,
  afterEach,
} from "@jest/globals";
import { parseArgs } from "../lib/cli-parser.js";
import {
  STATIC_MODULES,
  RUNTIME_MODULES,
  isStaticModule,
  isRuntimeModule,
  filterToStaticModules,
  filterToRuntimeModules,
} from "../lib/static-modules.js";
import { buildConfig } from "../lib/assessment-runner/config-builder.js";

describe("Static-Only Mode CLI Parsing", () => {
  // Suppress console output during tests
  let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;
  let consoleWarnSpy: jest.SpiedFunction<typeof console.warn>;
  let consoleLogSpy: jest.SpiedFunction<typeof console.log>;
  let processExitSpy: jest.SpiedFunction<typeof process.exit>;

  beforeEach(() => {
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    consoleLogSpy = jest.spyOn(console, "log").mockImplementation(() => {});
    processExitSpy = jest
      .spyOn(process, "exit")
      .mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("--static-only flag", () => {
    it("should parse --static-only flag", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
      ]);
      expect(result.staticOnly).toBe(true);
    });

    it("should set staticOnly to undefined when not provided", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--http",
        "http://localhost:8080",
      ]);
      expect(result.staticOnly).toBeUndefined();
    });
  });

  describe("--fallback-static flag", () => {
    it("should parse --fallback-static flag", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--http",
        "http://localhost:8080",
        "--source",
        "/path/to/source",
        "--fallback-static",
      ]);
      expect(result.fallbackStatic).toBe(true);
    });

    it("should set fallbackStatic to undefined when not provided", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--http",
        "http://localhost:8080",
      ]);
      expect(result.fallbackStatic).toBeUndefined();
    });
  });

  describe("Mutual Exclusivity", () => {
    it("should reject --static-only with --fallback-static", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
        "--fallback-static",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("mutually exclusive"),
      );
    });

    it("should reject --static-only without --source", () => {
      const result = parseArgs(["--server", "test-server", "--static-only"]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("requires --source"),
      );
    });

    it("should reject --static-only with --http", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
        "--http",
        "http://localhost:8080",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("cannot be used with --http"),
      );
    });

    it("should reject --static-only with --sse", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
        "--sse",
        "http://localhost:8080/sse",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("cannot be used with --http"),
      );
    });

    it("should reject --static-only with --config", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
        "--config",
        "/path/to/config.json",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("cannot be used with"),
      );
    });

    it("should reject --static-only with --module", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
        "--module",
        "security",
      ]);
      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("cannot be used with --module"),
      );
    });

    it("should allow --static-only with --only-modules", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
        "--only-modules",
        "manifestValidation,prohibitedLibraries",
      ]);
      // Should not error - this is allowed for filtering static modules
      expect(result.staticOnly).toBe(true);
      expect(result.onlyModules).toEqual([
        "manifestValidation",
        "prohibitedLibraries",
      ]);
    });

    it("should allow --static-only with --skip-modules", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        "/path/to/source",
        "--static-only",
        "--skip-modules",
        "portability",
      ]);
      // Should not error - this is allowed for filtering static modules
      expect(result.staticOnly).toBe(true);
      expect(result.skipModules).toEqual(["portability"]);
    });
  });
});

describe("Static Modules Definition", () => {
  describe("STATIC_MODULES constant", () => {
    it("should contain expected static-capable modules", () => {
      expect(STATIC_MODULES).toContain("manifestValidation");
      expect(STATIC_MODULES).toContain("documentation"); // Legacy name for DeveloperExperience
      expect(STATIC_MODULES).toContain("usability"); // Legacy name for DeveloperExperience
      expect(STATIC_MODULES).toContain("prohibitedLibraries");
      expect(STATIC_MODULES).toContain("portability");
      expect(STATIC_MODULES).toContain("externalAPIScanner");
      expect(STATIC_MODULES).toContain("fileModularization");
      expect(STATIC_MODULES).toContain("conformance");
      expect(STATIC_MODULES).toContain("toolAnnotations");
      expect(STATIC_MODULES).toContain("authentication");
      expect(STATIC_MODULES).toContain("aupCompliance");
    });

    it("should not contain runtime-only modules", () => {
      expect(STATIC_MODULES).not.toContain("functionality");
      expect(STATIC_MODULES).not.toContain("security");
      expect(STATIC_MODULES).not.toContain("temporal");
      expect(STATIC_MODULES).not.toContain("protocolCompliance");
    });

    it("should have exactly 11 static modules", () => {
      // documentation + usability (both legacy names for DeveloperExperience)
      expect(STATIC_MODULES.length).toBe(11);
    });
  });

  describe("RUNTIME_MODULES constant", () => {
    it("should contain expected runtime-only modules", () => {
      expect(RUNTIME_MODULES).toContain("functionality");
      expect(RUNTIME_MODULES).toContain("security");
      expect(RUNTIME_MODULES).toContain("temporal");
      expect(RUNTIME_MODULES).toContain("protocolCompliance");
      expect(RUNTIME_MODULES).toContain("resources");
      expect(RUNTIME_MODULES).toContain("prompts");
      expect(RUNTIME_MODULES).toContain("crossCapability");
      expect(RUNTIME_MODULES).toContain("errorHandling");
      expect(RUNTIME_MODULES).toContain("dependencyVulnerability");
    });

    it("should not contain static-capable modules", () => {
      expect(RUNTIME_MODULES).not.toContain("manifestValidation");
      expect(RUNTIME_MODULES).not.toContain("prohibitedLibraries");
      expect(RUNTIME_MODULES).not.toContain("portability");
      expect(RUNTIME_MODULES).not.toContain("documentation");
    });

    it("should have exactly 9 runtime modules", () => {
      // Includes dependencyVulnerability (requires live server for npm/yarn audit)
      expect(RUNTIME_MODULES.length).toBe(9);
    });
  });

  describe("isStaticModule helper", () => {
    it("should return true for static-capable modules", () => {
      expect(isStaticModule("manifestValidation")).toBe(true);
      expect(isStaticModule("prohibitedLibraries")).toBe(true);
      expect(isStaticModule("toolAnnotations")).toBe(true);
    });

    it("should return false for runtime-only modules", () => {
      expect(isStaticModule("functionality")).toBe(false);
      expect(isStaticModule("security")).toBe(false);
      expect(isStaticModule("temporal")).toBe(false);
    });

    it("should return false for unknown modules", () => {
      expect(isStaticModule("unknownModule")).toBe(false);
    });
  });

  describe("isRuntimeModule helper", () => {
    it("should return true for runtime-only modules", () => {
      expect(isRuntimeModule("functionality")).toBe(true);
      expect(isRuntimeModule("security")).toBe(true);
      expect(isRuntimeModule("temporal")).toBe(true);
    });

    it("should return false for static-capable modules", () => {
      expect(isRuntimeModule("manifestValidation")).toBe(false);
      expect(isRuntimeModule("prohibitedLibraries")).toBe(false);
    });
  });

  describe("filterToStaticModules helper", () => {
    it("should filter to only static-capable modules", () => {
      const input = [
        "manifestValidation",
        "functionality",
        "security",
        "prohibitedLibraries",
      ];
      const result = filterToStaticModules(input);
      expect(result).toEqual(["manifestValidation", "prohibitedLibraries"]);
    });

    it("should return empty array when no static modules present", () => {
      const input = ["functionality", "security", "temporal"];
      const result = filterToStaticModules(input);
      expect(result).toEqual([]);
    });
  });

  describe("filterToRuntimeModules helper", () => {
    it("should filter to only runtime-only modules", () => {
      const input = [
        "manifestValidation",
        "functionality",
        "security",
        "prohibitedLibraries",
      ];
      const result = filterToRuntimeModules(input);
      expect(result).toEqual(["functionality", "security"]);
    });

    it("should return empty array when no runtime modules present", () => {
      const input = [
        "manifestValidation",
        "prohibitedLibraries",
        "portability",
      ];
      const result = filterToRuntimeModules(input);
      expect(result).toEqual([]);
    });
  });
});

describe("Config Builder Static Mode", () => {
  // Suppress console output during tests
  let consoleWarnSpy: jest.SpiedFunction<typeof console.warn>;
  let consoleLogSpy: jest.SpiedFunction<typeof console.log>;

  beforeEach(() => {
    consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    consoleLogSpy = jest.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("buildConfig with staticOnly option", () => {
    it("should enable only static-capable modules", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: "/path/to/source",
        staticOnly: true,
      });

      const categories = config.assessmentCategories!;

      // Static modules should be enabled (using legacy property names)
      expect(categories.manifestValidation).toBe(true);
      expect(categories.documentation).toBe(true); // Legacy name for DeveloperExperience
      expect(categories.usability).toBe(true); // Legacy name for DeveloperExperience
      expect(categories.prohibitedLibraries).toBe(true);
      expect(categories.portability).toBe(true);
      expect(categories.externalAPIScanner).toBe(true);
      expect(categories.toolAnnotations).toBe(true);
      expect(categories.authentication).toBe(true);
      expect(categories.aupCompliance).toBe(true);

      // Runtime modules should be disabled
      expect(categories.functionality).toBe(false);
      expect(categories.security).toBe(false);
      expect(categories.temporal).toBe(false);
      expect(categories.protocolCompliance).toBe(false);
    });

    it("should apply --only-modules filter to static modules", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: "/path/to/source",
        staticOnly: true,
        onlyModules: ["manifestValidation", "prohibitedLibraries"],
      });

      const categories = config.assessmentCategories!;

      // Only whitelisted static modules should be enabled
      expect(categories.manifestValidation).toBe(true);
      expect(categories.prohibitedLibraries).toBe(true);

      // Other static modules should be disabled
      expect(categories.portability).toBe(false);
      expect(categories.toolAnnotations).toBe(false);

      // Runtime modules still disabled
      expect(categories.functionality).toBe(false);
      expect(categories.security).toBe(false);
    });

    it("should apply --skip-modules filter to static modules", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: "/path/to/source",
        staticOnly: true,
        skipModules: ["portability", "externalAPIScanner"],
      });

      const categories = config.assessmentCategories!;

      // Skipped modules should be disabled
      expect(categories.portability).toBe(false);
      expect(categories.externalAPIScanner).toBe(false);

      // Other static modules should still be enabled
      expect(categories.manifestValidation).toBe(true);
      expect(categories.prohibitedLibraries).toBe(true);
    });

    it("should ignore runtime modules in --only-modules with static mode", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: "/path/to/source",
        staticOnly: true,
        onlyModules: ["manifestValidation", "security", "functionality"],
      });

      const categories = config.assessmentCategories!;

      // Only static module from whitelist should be enabled
      expect(categories.manifestValidation).toBe(true);

      // Runtime modules from whitelist should still be disabled
      expect(categories.security).toBe(false);
      expect(categories.functionality).toBe(false);
    });

    it("should log static mode info", () => {
      buildConfig({
        serverName: "test-server",
        sourceCodePath: "/path/to/source",
        staticOnly: true,
      });

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("Static-only mode"),
      );
    });
  });

  describe("buildConfig without staticOnly option", () => {
    it("should enable runtime modules by default", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: "/path/to/source",
      });

      const categories = config.assessmentCategories!;

      // Runtime modules should be enabled by default
      expect(categories.functionality).toBe(true);
      expect(categories.security).toBe(true);
    });
  });
});
