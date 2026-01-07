/**
 * CLI Binary & Local Script Parity Test
 *
 * Verifies that cli/src/assess-full.ts and scripts/run-full-assessment.ts
 * remain synchronized. These files must stay in sync to ensure npm binary
 * and local development script produce identical outputs.
 *
 * Created after v1.21.2 discovered 7 missing display modules in npm binary.
 *
 * Uses TypeScript AST parsing instead of regex for robustness against
 * formatting changes (fixed in v1.21.4 per code review warning W2).
 */

import * as fs from "fs";
import * as path from "path";
import * as ts from "typescript";
/**
 * Cross-layer import for test validation.
 *
 * These imports from client/src are intentional - they provide the canonical
 * source of truth for module configuration. This test validates that CLI files
 * use the same configuration, ensuring parity between npm binary and local script.
 *
 * Type-only usage at test time - no runtime dependency created.
 */
import {
  getAllModulesConfig,
  ASSESSMENT_CATEGORY_METADATA,
} from "../../client/src/lib/assessment/coreTypes";

const CLI_PATH = path.join(__dirname, "../../cli/src/assess-full.ts");
const SCRIPT_PATH = path.join(__dirname, "../run-full-assessment.ts");

/**
 * Extract the modules array from displaySummary function using AST parsing.
 * Robust against formatting changes (whitespace, comments, type annotations).
 */
function extractModulesList(content: string): string[] {
  const sourceFile = ts.createSourceFile(
    "temp.ts",
    content,
    ts.ScriptTarget.Latest,
    true,
  );
  const moduleNames: string[] = [];

  function visit(node: ts.Node) {
    // Look for: const modules: [...] = [...];
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === "modules" &&
      node.initializer &&
      ts.isArrayLiteralExpression(node.initializer)
    ) {
      // Each element should be an array literal like ["Functionality", functionality, "functionality"]
      for (const element of node.initializer.elements) {
        if (
          ts.isArrayLiteralExpression(element) &&
          element.elements.length > 0
        ) {
          const firstElement = element.elements[0];
          // Extract string literal value
          if (ts.isStringLiteral(firstElement)) {
            moduleNames.push(firstElement.text);
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);

  if (moduleNames.length === 0) {
    throw new Error("Could not find modules array in displaySummary");
  }

  return moduleNames;
}

/**
 * Extract destructured variables from displaySummary using AST parsing.
 * Finds: const { var1, var2, ... } = results;
 */
function extractDestructuredVars(content: string): string[] {
  const sourceFile = ts.createSourceFile(
    "temp.ts",
    content,
    ts.ScriptTarget.Latest,
    true,
  );
  const vars: string[] = [];
  let inDisplaySummary = false;

  function visit(node: ts.Node) {
    // Track when we enter displaySummary function
    if (
      ts.isFunctionDeclaration(node) &&
      node.name?.text === "displaySummary"
    ) {
      inDisplaySummary = true;
      ts.forEachChild(node, visit);
      inDisplaySummary = false;
      return;
    }

    // Look for: const { ... } = results;
    if (
      inDisplaySummary &&
      ts.isVariableStatement(node) &&
      node.declarationList.declarations.length === 1
    ) {
      const decl = node.declarationList.declarations[0];
      // Check for object binding pattern assigned from 'results'
      if (
        ts.isObjectBindingPattern(decl.name) &&
        decl.initializer &&
        ts.isIdentifier(decl.initializer) &&
        decl.initializer.text === "results"
      ) {
        // Extract all binding element names
        for (const element of decl.name.elements) {
          if (ts.isBindingElement(element) && ts.isIdentifier(element.name)) {
            vars.push(element.name.text);
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);

  if (vars.length === 0) {
    throw new Error("Could not find destructuring in displaySummary");
  }

  return vars;
}

/**
 * Check if buildConfig() uses getAllModulesConfig() function call.
 * This is the expected pattern after the refactoring in v1.22.x.
 * Completeness is verified via the imported getAllModulesConfig function.
 */
function usesGetAllModulesConfig(content: string): boolean {
  const sourceFile = ts.createSourceFile(
    "temp.ts",
    content,
    ts.ScriptTarget.Latest,
    true,
  );
  let found = false;
  let inBuildConfig = false;

  function visit(node: ts.Node) {
    // Track when we enter buildConfig function
    if (ts.isFunctionDeclaration(node) && node.name?.text === "buildConfig") {
      inBuildConfig = true;
      ts.forEachChild(node, visit);
      inBuildConfig = false;
      return;
    }

    // Look for: const allModules = getAllModulesConfig(...)
    if (
      inBuildConfig &&
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === "allModules" &&
      node.initializer &&
      ts.isCallExpression(node.initializer)
    ) {
      const callExpr = node.initializer;
      if (
        ts.isIdentifier(callExpr.expression) &&
        callExpr.expression.text === "getAllModulesConfig"
      ) {
        found = true;
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return found;
}

/**
 * Unit tests for usesGetAllModulesConfig helper.
 * Validates the AST detection logic with positive and negative cases.
 */
describe("usesGetAllModulesConfig helper", () => {
  it("should return false for object literal pattern (old code)", () => {
    const oldPattern = `
      function buildConfig() {
        const allModules: Record<string, boolean> = {
          functionality: true,
          security: true
        };
        return allModules;
      }
    `;
    expect(usesGetAllModulesConfig(oldPattern)).toBe(false);
  });

  it("should return false for different function name", () => {
    const wrongFn = `
      function buildConfig() {
        const allModules = getSomeOtherConfig({});
        return allModules;
      }
    `;
    expect(usesGetAllModulesConfig(wrongFn)).toBe(false);
  });

  it("should return false when not in buildConfig", () => {
    const wrongLocation = `
      function otherFunction() {
        const allModules = getAllModulesConfig({});
        return allModules;
      }
    `;
    expect(usesGetAllModulesConfig(wrongLocation)).toBe(false);
  });

  it("should return true for correct pattern", () => {
    const correctPattern = `
      function buildConfig() {
        const allModules = getAllModulesConfig({ sourceCodePath });
        return allModules;
      }
    `;
    expect(usesGetAllModulesConfig(correctPattern)).toBe(true);
  });
});

/**
 * Extract JSONL event types emitted.
 */
function extractEmittedEventTypes(content: string): string[] {
  const events: string[] = [];
  const eventRegex = /emit\w+\([^)]*\)|type:\s*["'](\w+)["']/g;
  let match;

  // Find JSONL emit functions
  const emitFnRegex = /function emit(\w+)/g;
  while ((match = emitFnRegex.exec(content)) !== null) {
    events.push(match[1]);
  }

  return [...new Set(events)].sort();
}

describe("CLI Binary & Script Parity", () => {
  let cliContent: string;
  let scriptContent: string;

  beforeAll(() => {
    cliContent = fs.readFileSync(CLI_PATH, "utf-8");
    scriptContent = fs.readFileSync(SCRIPT_PATH, "utf-8");
  });

  describe("displaySummary module lists", () => {
    it("should have identical module display lists", () => {
      const cliModules = extractModulesList(cliContent);
      const scriptModules = extractModulesList(scriptContent);

      expect(cliModules).toEqual(scriptModules);
    });

    it("should have 17 modules in display list", () => {
      const cliModules = extractModulesList(cliContent);
      const expectedModules = [
        "Functionality",
        "Security",
        "Documentation",
        "Error Handling",
        "Usability",
        "MCP Spec Compliance",
        "AUP Compliance",
        "Tool Annotations",
        "Prohibited Libraries",
        "Manifest Validation",
        "Portability",
        "External API Scanner",
        "Authentication",
        "Temporal",
        "Resources",
        "Prompts",
        "Cross-Capability",
      ];

      expect(cliModules).toEqual(expectedModules);
    });
  });

  describe("destructured variables", () => {
    it("should have identical destructured result variables", () => {
      const cliVars = extractDestructuredVars(cliContent);
      const scriptVars = extractDestructuredVars(scriptContent);

      expect(cliVars).toEqual(scriptVars);
    });

    it("should include all assessment module variables", () => {
      const cliVars = extractDestructuredVars(cliContent);

      // Core modules
      expect(cliVars).toContain("functionality");
      expect(cliVars).toContain("security");
      expect(cliVars).toContain("documentation");
      expect(cliVars).toContain("errorHandling");
      expect(cliVars).toContain("usability");

      // Extended modules
      expect(cliVars).toContain("mcpSpecCompliance");
      expect(cliVars).toContain("aupCompliance");
      expect(cliVars).toContain("toolAnnotations");
      expect(cliVars).toContain("prohibitedLibraries");
      expect(cliVars).toContain("manifestValidation");
      expect(cliVars).toContain("portability");
      expect(cliVars).toContain("externalAPIScanner");
      expect(cliVars).toContain("authentication");
      expect(cliVars).toContain("temporal");

      // Capability assessors
      expect(cliVars).toContain("resources");
      expect(cliVars).toContain("prompts");
      expect(cliVars).toContain("crossCapability");
    });
  });

  describe("JSONL event emission", () => {
    it("should have matching JSONL emit functions", () => {
      const cliEvents = extractEmittedEventTypes(cliContent);
      const scriptEvents = extractEmittedEventTypes(scriptContent);

      expect(cliEvents).toEqual(scriptEvents);
    });
  });

  describe("file structure consistency", () => {
    it("should have displaySummary function in both files", () => {
      expect(cliContent).toContain("function displaySummary");
      expect(scriptContent).toContain("function displaySummary");
    });

    it("should have saveResults function in both files", () => {
      expect(cliContent).toContain("function saveResults");
      expect(scriptContent).toContain("function saveResults");
    });

    it("should import ASSESSMENT_CATEGORY_METADATA in both files", () => {
      expect(cliContent).toContain("ASSESSMENT_CATEGORY_METADATA");
      expect(scriptContent).toContain("ASSESSMENT_CATEGORY_METADATA");
    });

    it("should have main function in both files", () => {
      expect(cliContent).toContain("async function main");
      expect(scriptContent).toContain("async function main");
    });
  });

  describe("critical sections exist", () => {
    it("should have security vulnerabilities display in both files", () => {
      expect(cliContent).toContain("SECURITY VULNERABILITIES");
      expect(scriptContent).toContain("SECURITY VULNERABILITIES");
    });

    it("should have AUP findings display in both files", () => {
      expect(cliContent).toContain("AUP FINDINGS");
      expect(scriptContent).toContain("AUP FINDINGS");
    });

    it("should have MODULE STATUS section in both files", () => {
      expect(cliContent).toContain("📊 MODULE STATUS:");
      expect(scriptContent).toContain("📊 MODULE STATUS:");
    });

    it("should have optional marker handling in both files", () => {
      expect(cliContent).toContain("(optional)");
      expect(scriptContent).toContain("(optional)");
    });
  });

  describe("buildConfig allModules completeness", () => {
    // Use the actual getAllModulesConfig function as the source of truth
    // This ensures tests stay in sync with the implementation automatically
    const actualModules = getAllModulesConfig({});
    const EXPECTED_MODULES = Object.keys(actualModules).sort();

    it("should use getAllModulesConfig in CLI buildConfig", () => {
      expect(usesGetAllModulesConfig(cliContent)).toBe(true);
    });

    it("should use getAllModulesConfig in script buildConfig", () => {
      expect(usesGetAllModulesConfig(scriptContent)).toBe(true);
    });

    it("should have all modules via getAllModulesConfig", () => {
      // Verify getAllModulesConfig returns expected count
      // Derived from ASSESSMENT_CATEGORY_METADATA - self-maintaining
      const expectedCount = Object.keys(ASSESSMENT_CATEGORY_METADATA).length;
      expect(EXPECTED_MODULES.length).toBe(expectedCount);
    });

    it("should include authentication module (v1.22.2 regression)", () => {
      // Verify via the actual function
      expect(actualModules).toHaveProperty("authentication");
    });

    it("should include externalAPIScanner module", () => {
      // Verify via the actual function
      expect(actualModules).toHaveProperty("externalAPIScanner");
    });

    it("should have getAllModulesConfig imported in both files", () => {
      // Verify actual import statement, not just string presence
      // Regex ensures we match import syntax, not comments or strings
      const importPattern = /import\s*{[^}]*getAllModulesConfig[^}]*}\s*from/;
      expect(cliContent).toMatch(importPattern);
      expect(scriptContent).toMatch(importPattern);
    });

    it("should derive from ASSESSMENT_CATEGORY_METADATA (verified via function)", () => {
      // Core modules
      expect(actualModules).toHaveProperty("functionality");
      expect(actualModules).toHaveProperty("security");
      expect(actualModules).toHaveProperty("documentation");
      expect(actualModules).toHaveProperty("errorHandling");
      expect(actualModules).toHaveProperty("usability");

      // Extended modules
      expect(actualModules).toHaveProperty("mcpSpecCompliance");
      expect(actualModules).toHaveProperty("aupCompliance");
      expect(actualModules).toHaveProperty("toolAnnotations");
      expect(actualModules).toHaveProperty("prohibitedLibraries");
      expect(actualModules).toHaveProperty("manifestValidation");
      expect(actualModules).toHaveProperty("portability");
      expect(actualModules).toHaveProperty("externalAPIScanner");
      expect(actualModules).toHaveProperty("authentication");
      expect(actualModules).toHaveProperty("temporal");

      // Capability modules
      expect(actualModules).toHaveProperty("resources");
      expect(actualModules).toHaveProperty("prompts");
      expect(actualModules).toHaveProperty("crossCapability");

      // Protocol modules
      expect(actualModules).toHaveProperty("protocolConformance");
    });
  });

  describe("serverInfo capture parity", () => {
    it("should have getServerVersion call in both files", () => {
      expect(cliContent).toContain("getServerVersion");
      expect(scriptContent).toContain("getServerVersion");
    });

    it("should have getServerCapabilities call in both files", () => {
      expect(cliContent).toContain("getServerCapabilities");
      expect(scriptContent).toContain("getServerCapabilities");
    });

    it("should pass serverInfo to context in both files", () => {
      // Verify serverInfo is assigned to context (not just mentioned in comments)
      expect(cliContent).toMatch(/serverInfo[,\s]*$/m);
      expect(scriptContent).toMatch(/serverInfo[,\s]*$/m);
    });

    it("should pass serverCapabilities to context in both files", () => {
      // Verify serverCapabilities is assigned to context
      expect(cliContent).toMatch(/serverCapabilities[:\s]/);
      expect(scriptContent).toMatch(/serverCapabilities[:\s]/);
    });

    it('should have "unknown" fallback for missing server name in both files', () => {
      // Both files should handle missing name with "unknown" fallback
      expect(cliContent).toContain('"unknown"');
      expect(scriptContent).toContain('"unknown"');
    });
  });
});

/**
 * Utility to print differences for debugging.
 * Uncomment to debug parity issues.
 */
// function printDifferences() {
//   const cliContent = fs.readFileSync(CLI_PATH, 'utf-8');
//   const scriptContent = fs.readFileSync(SCRIPT_PATH, 'utf-8');
//
//   const cliModules = extractModulesList(cliContent);
//   const scriptModules = extractModulesList(scriptContent);
//
//   console.log('CLI modules:', cliModules);
//   console.log('Script modules:', scriptModules);
//
//   const missingInCli = scriptModules.filter(m => !cliModules.includes(m));
//   const missingInScript = cliModules.filter(m => !scriptModules.includes(m));
//
//   if (missingInCli.length > 0) {
//     console.log('Missing in CLI:', missingInCli);
//   }
//   if (missingInScript.length > 0) {
//     console.log('Missing in Script:', missingInScript);
//   }
// }
