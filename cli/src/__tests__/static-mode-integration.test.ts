/**
 * Static Mode Integration Tests
 *
 * Tests for Issue #213: Static/manifest-only validation mode integration.
 *
 * Tests cover:
 * - Source file loading error handling (malformed JSON, missing files)
 * - CLI validation and error messages
 * - Module filtering edge cases
 */

import {
  describe,
  it,
  expect,
  jest,
  beforeEach,
  afterEach,
} from "@jest/globals";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import { loadSourceFiles } from "../lib/assessment-runner/source-loader.js";
import { parseArgs } from "../lib/cli-parser.js";
import { buildConfig } from "../lib/assessment-runner/config-builder.js";
import {
  filterToStaticModules,
  filterToRuntimeModules,
} from "../lib/static-modules.js";

describe("Static Mode Integration", () => {
  let tempDir: string;
  let consoleLogSpy: jest.SpiedFunction<typeof console.log>;
  let consoleWarnSpy: jest.SpiedFunction<typeof console.warn>;
  let consoleErrorSpy: jest.SpiedFunction<typeof console.error>;
  let processExitSpy: jest.SpiedFunction<typeof process.exit>;

  beforeEach(() => {
    // Create temporary directory for test fixtures
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "inspector-test-"));
    consoleLogSpy = jest.spyOn(console, "log").mockImplementation(() => {});
    consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    consoleErrorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    processExitSpy = jest
      .spyOn(process, "exit")
      .mockImplementation(() => undefined as never);
  });

  afterEach(() => {
    // Clean up temporary directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
    jest.restoreAllMocks();
  });

  describe("Source File Loading Errors", () => {
    it("should throw error for malformed package.json", () => {
      // Create source directory with malformed package.json
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        "{ invalid json }",
        "utf-8",
      );

      // Should throw parse error (not caught by loadSourceFiles)
      expect(() => loadSourceFiles(tempDir, false)).toThrow();
    });

    it("should handle malformed manifest.json gracefully", () => {
      // Create source directory with malformed manifest.json
      fs.writeFileSync(
        path.join(tempDir, "manifest.json"),
        "{ invalid json }",
        "utf-8",
      );

      const sourceFiles = loadSourceFiles(tempDir, false);

      // Should log warning about failed parse
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining("Failed to parse manifest.json"),
      );

      // Should have manifestRaw but not manifestJson
      expect(sourceFiles.manifestRaw).toBeDefined();
      expect(sourceFiles.manifestJson).toBeUndefined();
    });

    it("should load valid source files successfully", () => {
      // Create valid source files
      fs.writeFileSync(
        path.join(tempDir, "package.json"),
        JSON.stringify({
          name: "test-server",
          version: "1.0.0",
          dependencies: {},
        }),
        "utf-8",
      );

      fs.writeFileSync(
        path.join(tempDir, "manifest.json"),
        JSON.stringify({
          manifest_version: "0.3",
          mcp_config: {
            tools: [
              {
                name: "test_tool",
                description: "Test tool",
                inputSchema: { type: "object", properties: {} },
              },
            ],
          },
        }),
        "utf-8",
      );

      fs.writeFileSync(
        path.join(tempDir, "README.md"),
        "# Test Server\n\nThis is a test server.",
        "utf-8",
      );

      fs.writeFileSync(
        path.join(tempDir, "index.ts"),
        "// Test source file\nexport function test() {}",
        "utf-8",
      );

      const sourceFiles = loadSourceFiles(tempDir, false);

      // Should load all files successfully
      expect(sourceFiles.packageJson).toBeDefined();
      expect(sourceFiles.manifestJson).toBeDefined();
      expect(sourceFiles.readmeContent).toBeDefined();
      // Should load .ts, .json files (index.ts, package.json, manifest.json)
      expect(sourceFiles.sourceCodeFiles?.size).toBeGreaterThanOrEqual(1);
      expect(sourceFiles.sourceCodeFiles?.has("index.ts")).toBe(true);

      // Validate parsed content
      expect((sourceFiles.packageJson as { name: string }).name).toBe(
        "test-server",
      );
      expect(
        (
          sourceFiles.manifestJson as {
            mcp_config?: { tools?: Array<{ name: string }> };
          }
        ).mcp_config?.tools?.[0]?.name,
      ).toBe("test_tool");
    });

    it("should handle missing files gracefully", () => {
      // Empty directory - no package.json, manifest.json, or README
      const sourceFiles = loadSourceFiles(tempDir, false);

      // Should complete without crashing
      expect(sourceFiles).toBeDefined();
      expect(sourceFiles.packageJson).toBeUndefined();
      expect(sourceFiles.manifestJson).toBeUndefined();
      expect(sourceFiles.readmeContent).toBeUndefined();
      expect(sourceFiles.sourceCodeFiles?.size).toBe(0);
    });

    it("should skip files in .gitignore", () => {
      // Create .gitignore
      fs.writeFileSync(
        path.join(tempDir, ".gitignore"),
        "node_modules\n*.log\ntest.ts",
        "utf-8",
      );

      // Create files that should be ignored
      fs.writeFileSync(path.join(tempDir, "test.ts"), "// Ignored", "utf-8");
      fs.writeFileSync(path.join(tempDir, "debug.log"), "Debug log", "utf-8");

      // Create files that should be loaded
      fs.writeFileSync(path.join(tempDir, "index.ts"), "// Loaded", "utf-8");

      const sourceFiles = loadSourceFiles(tempDir, false);

      // Should only load index.ts
      expect(sourceFiles.sourceCodeFiles?.size).toBe(1);
      expect(sourceFiles.sourceCodeFiles?.has("index.ts")).toBe(true);
      expect(sourceFiles.sourceCodeFiles?.has("test.ts")).toBe(false);
      expect(sourceFiles.sourceCodeFiles?.has("debug.log")).toBe(false);
    });

    it("should handle large files by skipping them", () => {
      // Create a file larger than MAX_SOURCE_FILE_SIZE (100,000 chars)
      const largeContent = "a".repeat(150000);
      fs.writeFileSync(path.join(tempDir, "large.ts"), largeContent, "utf-8");

      // Create a normal file
      fs.writeFileSync(
        path.join(tempDir, "normal.ts"),
        "// Normal file",
        "utf-8",
      );

      const sourceFiles = loadSourceFiles(tempDir, false);

      // Should only load the normal file
      expect(sourceFiles.sourceCodeFiles?.size).toBe(1);
      expect(sourceFiles.sourceCodeFiles?.has("normal.ts")).toBe(true);
      expect(sourceFiles.sourceCodeFiles?.has("large.ts")).toBe(false);
    });
  });

  describe("Module Filtering Edge Cases", () => {
    it("should result in empty array when filtering only runtime modules from static list", () => {
      const runtimeModules = ["functionality", "security", "temporal"];
      const result = filterToStaticModules(runtimeModules);

      expect(result).toEqual([]);
    });

    it("should result in empty array when filtering only static modules from runtime list", () => {
      const staticModules = [
        "manifestValidation",
        "prohibitedLibraries",
        "portability",
      ];
      const result = filterToRuntimeModules(staticModules);

      expect(result).toEqual([]);
    });

    it("should correctly split mixed module list", () => {
      const mixedModules = [
        "functionality",
        "manifestValidation",
        "security",
        "prohibitedLibraries",
        "temporal",
        "portability",
      ];

      const staticResult = filterToStaticModules(mixedModules);
      const runtimeResult = filterToRuntimeModules(mixedModules);

      expect(staticResult).toEqual([
        "manifestValidation",
        "prohibitedLibraries",
        "portability",
      ]);
      expect(runtimeResult).toEqual(["functionality", "security", "temporal"]);

      // Should split perfectly with no overlap
      expect(staticResult.length + runtimeResult.length).toBe(
        mixedModules.length,
      );
    });

    it("should produce zero enabled modules with --only-modules containing only runtime modules", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: tempDir,
        staticOnly: true,
        onlyModules: ["functionality", "security", "temporal"],
      });

      const categories = config.assessmentCategories!;

      // Count enabled modules
      const enabledCount = Object.values(categories).filter(Boolean).length;
      expect(enabledCount).toBe(0);

      // Verify runtime modules are disabled
      expect(categories.functionality).toBe(false);
      expect(categories.security).toBe(false);
      expect(categories.temporal).toBe(false);

      // Verify static modules are also disabled (not in onlyModules)
      expect(categories.manifestValidation).toBe(false);
      expect(categories.prohibitedLibraries).toBe(false);
    });

    it("should produce minimal enabled modules when most static modules are skipped", () => {
      // Note: documentation and usability are deprecated aliases for developerExperience
      // So skipping them doesn't disable those keys in the config object
      // (the keys remain because STATIC_MODULES contains the deprecated names)
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: tempDir,
        staticOnly: true,
        skipModules: [
          "manifestValidation",
          "prohibitedLibraries",
          "portability",
          "externalAPIScanner",
          "fileModularization",
          "conformance",
          "toolAnnotations",
          "authentication",
          "aupCompliance",
        ],
      });

      const categories = config.assessmentCategories!;

      // Most static modules should be disabled
      expect(categories.manifestValidation).toBe(false);
      expect(categories.prohibitedLibraries).toBe(false);
      expect(categories.portability).toBe(false);
      expect(categories.toolAnnotations).toBe(false);
      expect(categories.externalAPIScanner).toBe(false);
      expect(categories.fileModularization).toBe(false);
      expect(categories.conformance).toBe(false);
      expect(categories.authentication).toBe(false);
      expect(categories.aupCompliance).toBe(false);

      // Only documentation and usability (deprecated aliases) may remain enabled
      // This is acceptable behavior - they're in STATIC_MODULES for backward compatibility
      const enabledCount = Object.values(categories).filter(Boolean).length;
      // Should have at most 2 enabled (documentation, usability - both resolve to developerExperience)
      expect(enabledCount).toBeLessThanOrEqual(2);
    });

    it("should handle --only-modules with mix of static and runtime modules in static mode", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: tempDir,
        staticOnly: true,
        onlyModules: [
          "manifestValidation",
          "security", // runtime - should be ignored
          "prohibitedLibraries",
          "functionality", // runtime - should be ignored
        ],
      });

      const categories = config.assessmentCategories!;

      // Only static modules from onlyModules should be enabled
      expect(categories.manifestValidation).toBe(true);
      expect(categories.prohibitedLibraries).toBe(true);

      // Runtime modules should be disabled even if in onlyModules
      expect(categories.security).toBe(false);
      expect(categories.functionality).toBe(false);

      // Other static modules not in onlyModules should be disabled
      expect(categories.portability).toBe(false);
      expect(categories.toolAnnotations).toBe(false);
    });
  });

  describe("CLI Validation Messages", () => {
    it("should show helpful error for --static-only without --source", () => {
      const result = parseArgs(["--server", "test-server", "--static-only"]);

      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("--static-only requires --source"),
      );
    });

    it("should show helpful error for --static-only with --http", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        tempDir,
        "--static-only",
        "--http",
        "http://localhost:8080",
      ]);

      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("cannot be used with --http"),
      );
    });

    it("should show helpful error for --static-only with --fallback-static", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        tempDir,
        "--static-only",
        "--fallback-static",
      ]);

      expect(result.helpRequested).toBe(true);
      expect(consoleErrorSpy).toHaveBeenCalledWith(
        expect.stringContaining("mutually exclusive"),
      );
    });

    it("should allow valid --static-only with --source", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        tempDir,
        "--static-only",
      ]);

      expect(result.staticOnly).toBe(true);
      expect(result.sourceCodePath).toBe(tempDir);
      expect(result.helpRequested).toBeUndefined();
    });

    it("should allow valid --fallback-static with --source and --http", () => {
      const result = parseArgs([
        "--server",
        "test-server",
        "--source",
        tempDir,
        "--http",
        "http://localhost:8080",
        "--fallback-static",
      ]);

      expect(result.fallbackStatic).toBe(true);
      expect(result.httpUrl).toBe("http://localhost:8080");
      expect(result.sourceCodePath).toBe(tempDir);
      expect(result.helpRequested).toBeUndefined();
    });
  });

  describe("Config Builder Integration", () => {
    it("should enable static modules and disable runtime modules in static-only mode", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: tempDir,
        staticOnly: true,
      });

      const categories = config.assessmentCategories!;

      // Count enabled modules
      const enabledModules = Object.entries(categories)
        .filter(([_, enabled]) => enabled)
        .map(([name]) => name);

      const disabledModules = Object.entries(categories)
        .filter(([_, enabled]) => !enabled)
        .map(([name]) => name);

      // All enabled modules should be static-capable
      for (const moduleName of enabledModules) {
        const isStatic =
          moduleName === "manifestValidation" ||
          moduleName === "documentation" ||
          moduleName === "usability" ||
          moduleName === "prohibitedLibraries" ||
          moduleName === "portability" ||
          moduleName === "externalAPIScanner" ||
          moduleName === "fileModularization" ||
          moduleName === "conformance" ||
          moduleName === "toolAnnotations" ||
          moduleName === "authentication" ||
          moduleName === "aupCompliance";

        expect(isStatic).toBe(true);
      }

      // All disabled modules should include runtime-only modules
      expect(disabledModules).toContain("functionality");
      expect(disabledModules).toContain("security");
      expect(disabledModules).toContain("temporal");
      expect(disabledModules).toContain("protocolCompliance");
    });

    it("should log static mode info message", () => {
      buildConfig({
        serverName: "test-server",
        sourceCodePath: tempDir,
        staticOnly: true,
      });

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining("Static-only mode"),
      );
    });

    it("should respect --only-modules filter in static mode", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: tempDir,
        staticOnly: true,
        onlyModules: ["manifestValidation", "prohibitedLibraries"],
      });

      const categories = config.assessmentCategories!;

      // Count enabled modules
      const enabledCount = Object.values(categories).filter(Boolean).length;

      // Should only have 2 enabled modules
      expect(enabledCount).toBe(2);
      expect(categories.manifestValidation).toBe(true);
      expect(categories.prohibitedLibraries).toBe(true);

      // All other modules should be disabled
      expect(categories.portability).toBe(false);
      expect(categories.functionality).toBe(false);
      expect(categories.security).toBe(false);
    });

    it("should respect --skip-modules filter in static mode", () => {
      const config = buildConfig({
        serverName: "test-server",
        sourceCodePath: tempDir,
        staticOnly: true,
        skipModules: ["portability", "externalAPIScanner"],
      });

      const categories = config.assessmentCategories!;

      // Skipped modules should be disabled
      expect(categories.portability).toBe(false);
      expect(categories.externalAPIScanner).toBe(false);

      // Other static modules should be enabled
      expect(categories.manifestValidation).toBe(true);
      expect(categories.prohibitedLibraries).toBe(true);
      expect(categories.toolAnnotations).toBe(true);

      // Runtime modules should be disabled
      expect(categories.functionality).toBe(false);
      expect(categories.security).toBe(false);
    });
  });
});
