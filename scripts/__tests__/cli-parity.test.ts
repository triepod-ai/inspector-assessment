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
 * Extract allModules object keys from buildConfig() function using AST parsing.
 * This catches missing modules like the authentication bug fixed in v1.22.2.
 */
function extractAllModulesKeys(content: string): string[] {
  const sourceFile = ts.createSourceFile(
    "temp.ts",
    content,
    ts.ScriptTarget.Latest,
    true,
  );
  const moduleKeys: string[] = [];
  let inBuildConfig = false;

  function visit(node: ts.Node) {
    // Track when we enter buildConfig function
    if (ts.isFunctionDeclaration(node) && node.name?.text === "buildConfig") {
      inBuildConfig = true;
      ts.forEachChild(node, visit);
      inBuildConfig = false;
      return;
    }

    // Look for: const allModules: Record<string, boolean> = { ... }
    if (
      inBuildConfig &&
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === "allModules" &&
      node.initializer &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      // Extract all property names from the object literal
      for (const prop of node.initializer.properties) {
        if (ts.isPropertyAssignment(prop) && ts.isIdentifier(prop.name)) {
          moduleKeys.push(prop.name.text);
        }
        // Handle shorthand properties like { foo } instead of { foo: true }
        if (ts.isShorthandPropertyAssignment(prop)) {
          moduleKeys.push(prop.name.text);
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);

  if (moduleKeys.length === 0) {
    throw new Error("Could not find allModules object in buildConfig");
  }

  return moduleKeys.sort();
}

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
    // All modules from ASSESSMENT_CATEGORY_METADATA (source of truth)
    // This list should match Object.keys(ASSESSMENT_CATEGORY_METADATA) from assessmentTypes.ts
    const EXPECTED_MODULES = [
      "functionality",
      "security",
      "documentation",
      "errorHandling",
      "usability",
      "mcpSpecCompliance",
      "aupCompliance",
      "toolAnnotations",
      "prohibitedLibraries",
      "manifestValidation",
      "portability",
      "externalAPIScanner",
      "authentication",
      "temporal",
      "resources",
      "prompts",
      "crossCapability",
    ].sort();

    it("should have identical allModules keys in buildConfig", () => {
      const cliModules = extractAllModulesKeys(cliContent);
      const scriptModules = extractAllModulesKeys(scriptContent);

      expect(cliModules).toEqual(scriptModules);
    });

    it("should have all 17 modules in allModules (regression test for authentication bug)", () => {
      const cliModules = extractAllModulesKeys(cliContent);

      expect(cliModules.length).toBe(17);
      expect(cliModules).toEqual(EXPECTED_MODULES);
    });

    it("should include authentication module (v1.22.2 regression)", () => {
      const cliModules = extractAllModulesKeys(cliContent);
      const scriptModules = extractAllModulesKeys(scriptContent);

      expect(cliModules).toContain("authentication");
      expect(scriptModules).toContain("authentication");
    });

    it("should include externalAPIScanner in both files", () => {
      const cliModules = extractAllModulesKeys(cliContent);
      const scriptModules = extractAllModulesKeys(scriptContent);

      expect(cliModules).toContain("externalAPIScanner");
      expect(scriptModules).toContain("externalAPIScanner");
    });

    it("should have 1:1 mapping with ASSESSMENT_CATEGORY_METADATA", () => {
      const cliModules = extractAllModulesKeys(cliContent);

      // Every expected module should be in allModules
      for (const module of EXPECTED_MODULES) {
        expect(cliModules).toContain(module);
      }

      // allModules should not have extra modules not in metadata
      for (const module of cliModules) {
        expect(EXPECTED_MODULES).toContain(module);
      }
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
