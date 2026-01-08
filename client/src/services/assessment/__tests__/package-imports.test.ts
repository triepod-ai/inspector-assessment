/**
 * Package Import Pattern Tests
 *
 * Validates that all documented import patterns from the package.json exports
 * work correctly. These tests ensure npm consumers can use the documented
 * import paths without issues.
 *
 * Package exports tested:
 * - "." -> AssessmentOrchestrator (main entry)
 * - "./types" -> Type definitions (AssessmentContext, etc.)
 * - "./config" -> Configuration presets and types
 * - "./results" -> Result types (MCPDirectoryAssessment, etc.)
 * - "./progress" -> Progress event types
 */

import * as fs from "fs";
import * as path from "path";

// Find project root by looking for package.json with workspaces
const findProjectRoot = (): string => {
  let dir = __dirname;
  let iterations = 0;
  const maxIterations = 20;
  while (dir !== "/" && iterations < maxIterations) {
    const pkgPath = path.join(dir, "package.json");
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
      if (pkg.workspaces) {
        return dir;
      }
    }
    dir = path.dirname(dir);
    iterations++;
  }
  throw new Error("Could not find project root with workspaces");
};

describe("Package Import Patterns", () => {
  const projectRoot = findProjectRoot();
  const rootPkg = JSON.parse(
    fs.readFileSync(path.join(projectRoot, "package.json"), "utf-8"),
  );

  describe("Package Exports Configuration", () => {
    it("should have exports field defined", () => {
      expect(rootPkg.exports).toBeDefined();
      expect(typeof rootPkg.exports).toBe("object");
    });

    it("should have all documented export paths", () => {
      const expectedExports = [
        ".",
        "./types",
        "./config",
        "./results",
        "./progress",
      ];
      for (const exportPath of expectedExports) {
        expect(rootPkg.exports[exportPath]).toBeDefined();
      }
    });

    it("should have types and default for each export", () => {
      for (const [_exportPath, config] of Object.entries(rootPkg.exports)) {
        const exportConfig = config as { types?: string; default?: string };
        expect(exportConfig.types).toBeDefined();
        expect(exportConfig.default).toBeDefined();
        expect(exportConfig.types).toMatch(/\.d\.ts$/);
        expect(exportConfig.default).toMatch(/\.js$/);
      }
    });
  });

  describe("Export Targets Exist", () => {
    it("should have main entry point files", () => {
      const mainExport = rootPkg.exports["."];
      const jsPath = path.join(projectRoot, mainExport.default);
      const dtsPath = path.join(projectRoot, mainExport.types);

      expect(fs.existsSync(jsPath)).toBe(true);
      expect(fs.existsSync(dtsPath)).toBe(true);
    });

    it("should have types subpath files", () => {
      const typesExport = rootPkg.exports["./types"];
      const jsPath = path.join(projectRoot, typesExport.default);
      const dtsPath = path.join(projectRoot, typesExport.types);

      expect(fs.existsSync(jsPath)).toBe(true);
      expect(fs.existsSync(dtsPath)).toBe(true);
    });

    it("should have config subpath files", () => {
      const configExport = rootPkg.exports["./config"];
      const jsPath = path.join(projectRoot, configExport.default);
      const dtsPath = path.join(projectRoot, configExport.types);

      expect(fs.existsSync(jsPath)).toBe(true);
      expect(fs.existsSync(dtsPath)).toBe(true);
    });

    it("should have results subpath files", () => {
      const resultsExport = rootPkg.exports["./results"];
      const jsPath = path.join(projectRoot, resultsExport.default);
      const dtsPath = path.join(projectRoot, resultsExport.types);

      expect(fs.existsSync(jsPath)).toBe(true);
      expect(fs.existsSync(dtsPath)).toBe(true);
    });

    it("should have progress subpath files", () => {
      const progressExport = rootPkg.exports["./progress"];
      const jsPath = path.join(projectRoot, progressExport.default);
      const dtsPath = path.join(projectRoot, progressExport.types);

      expect(fs.existsSync(jsPath)).toBe(true);
      expect(fs.existsSync(dtsPath)).toBe(true);
    });
  });

  describe("Main Entry Point (AssessmentOrchestrator)", () => {
    it("exports AssessmentOrchestrator class", async () => {
      // Use relative import to compiled file (maps to "." export)
      const module = await import("../AssessmentOrchestrator");
      expect(module.AssessmentOrchestrator).toBeDefined();
      expect(typeof module.AssessmentOrchestrator).toBe("function");
    });
  });

  describe("Types Subpath", () => {
    it("exports core type definitions", async () => {
      // Use relative import to compiled file (maps to "./types" export)
      const module = await import("../../../lib/assessment/index");

      // Core types should be exported
      expect(module).toBeDefined();

      // Check for key type re-exports (these are runtime values that TypeScript exports)
      // Note: Pure type exports won't be present at runtime, only values/classes/functions
    });
  });

  describe("Config Subpath", () => {
    it("exports configuration presets", async () => {
      // Use relative import to compiled file (maps to "./config" export)
      const module = await import("../../../lib/assessment/configTypes");

      // Configuration presets should be exported
      expect(module.DEFAULT_ASSESSMENT_CONFIG).toBeDefined();
      expect(module.REVIEWER_MODE_CONFIG).toBeDefined();
      expect(module.DEVELOPER_MODE_CONFIG).toBeDefined();
      expect(module.AUDIT_MODE_CONFIG).toBeDefined();
      expect(module.CLAUDE_ENHANCED_AUDIT_CONFIG).toBeDefined();
    });

    it("configuration presets have required fields", async () => {
      const { DEFAULT_ASSESSMENT_CONFIG } =
        await import("../../../lib/assessment/configTypes");

      expect(DEFAULT_ASSESSMENT_CONFIG.testTimeout).toBeDefined();
      expect(DEFAULT_ASSESSMENT_CONFIG.skipBrokenTools).toBeDefined();
      expect(DEFAULT_ASSESSMENT_CONFIG.assessmentCategories).toBeDefined();
    });
  });

  describe("Results Subpath", () => {
    it("exports result type definitions", async () => {
      // Use relative import to compiled file (maps to "./results" export)
      const module = await import("../../../lib/assessment/resultTypes");

      // Module should load without errors
      expect(module).toBeDefined();
    });
  });

  describe("Progress Subpath", () => {
    it("exports progress type definitions", async () => {
      // Use relative import to compiled file (maps to "./progress" export)
      const module = await import("../../../lib/assessment/progressTypes");

      // Module should load without errors
      expect(module).toBeDefined();
    });
  });
});
