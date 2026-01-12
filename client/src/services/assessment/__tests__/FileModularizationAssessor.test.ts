/**
 * FileModularizationAssessor Test Suite
 *
 * Tests file modularization detection and scoring for Issue #104
 */

import { FileModularizationAssessor } from "../modules/FileModularizationAssessor";
import {
  createMockAssessmentConfig,
  createMockAssessmentContext,
  getPrivateMethod,
} from "@/test/utils/testUtils";
import type { AssessmentConfiguration } from "@/lib/assessmentTypes";

describe("FileModularizationAssessor", () => {
  let assessor: FileModularizationAssessor;
  let config: AssessmentConfiguration;

  beforeEach(() => {
    config = createMockAssessmentConfig({
      enableSourceCodeAnalysis: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        fileModularization: true,
      },
    });
    assessor = new FileModularizationAssessor(config);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("countToolsInFile", () => {
    let countToolsInFile: (content: string, language: string | null) => number;

    beforeEach(() => {
      countToolsInFile = getPrivateMethod(assessor, "countToolsInFile");
    });

    it("counts Python @mcp.tool decorators", () => {
      const content = `
@mcp.tool
def tool_one():
    pass

@mcp.tool
def tool_two():
    pass
`;
      expect(countToolsInFile(content, "python")).toBe(2);
    });

    it("counts Python *_tool functions", () => {
      const content = `
def vulnerable_calculator_tool():
    pass

async def vulnerable_exec_tool():
    pass

def helper_function():
    pass
`;
      expect(countToolsInFile(content, "python")).toBe(2);
    });

    it("counts TypeScript server.tool() calls", () => {
      const content = `
server.tool("calculator", schema, handler);
server.tool("exec", execSchema, execHandler);
`;
      expect(countToolsInFile(content, "typescript")).toBe(2);
    });

    it("counts TypeScript setRequestHandler() calls", () => {
      const content = `
router.setRequestHandler("get", getHandler);
router.setRequestHandler("set", setHandler);
`;
      expect(countToolsInFile(content, "typescript")).toBe(2);
    });

    it("returns 0 for unknown language", () => {
      const content = "@mcp.tool\ndef tool_one(): pass";
      expect(countToolsInFile(content, null)).toBe(0);
    });

    it("returns 0 for files with no tools", () => {
      const content = `
def helper():
    pass

class Utility:
    pass
`;
      expect(countToolsInFile(content, "python")).toBe(0);
    });
  });

  describe("isSourceFile", () => {
    let isSourceFile: (filePath: string) => boolean;

    beforeEach(() => {
      isSourceFile = getPrivateMethod(assessor, "isSourceFile");
    });

    it("accepts Python files", () => {
      expect(isSourceFile("src/tools.py")).toBe(true);
    });

    it("accepts TypeScript files", () => {
      expect(isSourceFile("src/tools.ts")).toBe(true);
      expect(isSourceFile("src/tools.tsx")).toBe(true);
    });

    it("accepts JavaScript files", () => {
      expect(isSourceFile("src/tools.js")).toBe(true);
      expect(isSourceFile("src/tools.mjs")).toBe(true);
    });

    it("accepts Go and Rust files", () => {
      expect(isSourceFile("src/tools.go")).toBe(true);
      expect(isSourceFile("src/tools.rs")).toBe(true);
    });

    it("rejects node_modules", () => {
      expect(isSourceFile("node_modules/express/index.js")).toBe(false);
    });

    it("rejects test files", () => {
      expect(isSourceFile("src/tools.test.ts")).toBe(false);
      expect(isSourceFile("src/tools.spec.ts")).toBe(false);
      expect(isSourceFile("src/__tests__/tools.ts")).toBe(false);
    });

    it("rejects Python venv", () => {
      expect(isSourceFile(".venv/lib/python3.11/site-packages/foo.py")).toBe(
        false,
      );
      expect(isSourceFile("venv/lib/python3.11/site-packages/foo.py")).toBe(
        false,
      );
    });

    it("rejects build artifacts", () => {
      expect(isSourceFile("dist/index.js")).toBe(false);
      expect(isSourceFile("build/server.js")).toBe(false);
    });
  });

  describe("detectLanguage", () => {
    let detectLanguage: (filePath: string) => string | null;

    beforeEach(() => {
      detectLanguage = getPrivateMethod(assessor, "detectLanguage");
    });

    it("detects Python", () => {
      expect(detectLanguage("tools.py")).toBe("python");
    });

    it("detects TypeScript", () => {
      expect(detectLanguage("tools.ts")).toBe("typescript");
      expect(detectLanguage("tools.tsx")).toBe("typescript");
    });

    it("detects JavaScript", () => {
      expect(detectLanguage("tools.js")).toBe("javascript");
      expect(detectLanguage("tools.mjs")).toBe("javascript");
      expect(detectLanguage("tools.cjs")).toBe("javascript");
    });

    it("detects Go", () => {
      expect(detectLanguage("tools.go")).toBe("go");
    });

    it("detects Rust", () => {
      expect(detectLanguage("tools.rs")).toBe("rust");
    });

    it("returns null for unknown extensions", () => {
      expect(detectLanguage("tools.txt")).toBeNull();
      expect(detectLanguage("tools.json")).toBeNull();
    });
  });

  describe("calculateScore", () => {
    let calculateScore: (
      filesOver1000: number,
      filesOver2000: number,
      filesOver10Tools: number,
      filesOver20Tools: number,
      hasModular: boolean,
      fileAnalyses: Map<
        string,
        { lines: number; toolCount: number; language: string | null }
      >,
    ) => number;

    beforeEach(() => {
      calculateScore = getPrivateMethod(assessor, "calculateScore");
    });

    it("returns 100 for well-modularized codebase", () => {
      const analyses = new Map([
        ["src/tools/auth.py", { lines: 200, toolCount: 3, language: "python" }],
        ["src/tools/data.py", { lines: 300, toolCount: 4, language: "python" }],
        [
          "src/tools/utils.py",
          { lines: 100, toolCount: 2, language: "python" },
        ],
        [
          "src/tools/_common.py",
          { lines: 50, toolCount: 0, language: "python" },
        ],
      ]);
      // +5 for tools/ dir, +3 for multiple files, +2 for _common.py = 110, capped at 100
      expect(calculateScore(0, 0, 0, 0, true, analyses)).toBe(100);
    });

    it("deducts 15 points per file over 2000 lines", () => {
      const analyses = new Map([
        ["src/tools.py", { lines: 2500, toolCount: 5, language: "python" }],
      ]);
      // 100 - 15 (2000+ lines) - 10 (no modular) = 75
      expect(calculateScore(1, 1, 0, 0, false, analyses)).toBe(75);
    });

    it("deducts 8 points per file between 1000-2000 lines", () => {
      const analyses = new Map([
        ["src/tools.py", { lines: 1500, toolCount: 5, language: "python" }],
      ]);
      // 100 - 8 (1000-2000 lines) - 10 (no modular) = 82
      expect(calculateScore(1, 0, 0, 0, false, analyses)).toBe(82);
    });

    it("deducts 12 points per file with >20 tools", () => {
      const analyses = new Map([
        ["src/tools.py", { lines: 500, toolCount: 25, language: "python" }],
      ]);
      // 100 - 12 (>20 tools) - 10 (no modular) = 78
      expect(calculateScore(0, 0, 1, 1, false, analyses)).toBe(78);
    });

    it("deducts 6 points per file with 10-20 tools", () => {
      const analyses = new Map([
        ["src/tools.py", { lines: 500, toolCount: 15, language: "python" }],
      ]);
      // 100 - 6 (10-20 tools) - 10 (no modular) = 84
      expect(calculateScore(0, 0, 1, 0, false, analyses)).toBe(84);
    });

    it("adds 5 points for tools/ subdirectory (capped at 100)", () => {
      const analyses = new Map([
        ["src/tools/auth.py", { lines: 200, toolCount: 3, language: "python" }],
      ]);
      // 100 + 5 (tools/) = 105, but capped at 100
      // hasModular = true (tools/ directory)
      expect(calculateScore(0, 0, 0, 0, true, analyses)).toBe(100);
    });

    it("never returns below 0", () => {
      const analyses = new Map([
        ["src/tools1.py", { lines: 3000, toolCount: 30, language: "python" }],
        ["src/tools2.py", { lines: 3000, toolCount: 30, language: "python" }],
        ["src/tools3.py", { lines: 3000, toolCount: 30, language: "python" }],
        ["src/tools4.py", { lines: 3000, toolCount: 30, language: "python" }],
        ["src/tools5.py", { lines: 3000, toolCount: 30, language: "python" }],
      ]);
      // Would be massive negative but capped at 0
      expect(calculateScore(5, 5, 5, 5, false, analyses)).toBe(0);
    });

    it("never returns above 100", () => {
      const analyses = new Map([
        ["src/tools/auth.py", { lines: 100, toolCount: 2, language: "python" }],
        ["src/tools/data.py", { lines: 100, toolCount: 2, language: "python" }],
        [
          "src/tools/utils.py",
          { lines: 100, toolCount: 2, language: "python" },
        ],
        ["src/tools/api.py", { lines: 100, toolCount: 2, language: "python" }],
        ["src/shared.py", { lines: 50, toolCount: 0, language: "python" }],
      ]);
      // 100 + bonuses = capped at 100
      expect(calculateScore(0, 0, 0, 0, true, analyses)).toBe(100);
    });
  });

  describe("checkModularStructure", () => {
    let checkModularStructure: (
      fileAnalyses: Map<
        string,
        { lines: number; toolCount: number; language: string | null }
      >,
    ) => boolean;

    beforeEach(() => {
      checkModularStructure = getPrivateMethod(
        assessor,
        "checkModularStructure",
      );
    });

    it("returns true for tools/ subdirectory", () => {
      const analyses = new Map([
        ["src/tools/auth.py", { lines: 200, toolCount: 3, language: "python" }],
      ]);
      expect(checkModularStructure(analyses)).toBe(true);
    });

    it("returns true for multiple tool files (>= 3)", () => {
      const analyses = new Map([
        ["src/auth_tools.py", { lines: 200, toolCount: 3, language: "python" }],
        ["src/data_tools.py", { lines: 200, toolCount: 3, language: "python" }],
        ["src/util_tools.py", { lines: 200, toolCount: 3, language: "python" }],
      ]);
      expect(checkModularStructure(analyses)).toBe(true);
    });

    it("returns false for single tool file without tools/ directory", () => {
      const analyses = new Map([
        ["src/tools.py", { lines: 2000, toolCount: 20, language: "python" }],
      ]);
      expect(checkModularStructure(analyses)).toBe(false);
    });

    it("returns false for two tool files (needs 3+)", () => {
      const analyses = new Map([
        ["src/auth.py", { lines: 200, toolCount: 5, language: "python" }],
        ["src/data.py", { lines: 200, toolCount: 5, language: "python" }],
      ]);
      expect(checkModularStructure(analyses)).toBe(false);
    });
  });

  describe("assess integration", () => {
    it("returns NEED_MORE_INFO when source code not available", async () => {
      const context = createMockAssessmentContext({
        sourceCodeFiles: undefined,
        config,
      });

      const result = await assessor.assess(context);

      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.explanation).toContain("Source code analysis not enabled");
      expect(result.metrics.totalSourceFiles).toBe(0);
    });

    it("returns PASS for well-modularized codebase", async () => {
      const sourceCodeFiles = new Map([
        [
          "src/tools/auth.py",
          `
@mcp.tool
def login_tool(): pass

@mcp.tool
def logout_tool(): pass
`,
        ],
        [
          "src/tools/data.py",
          `
@mcp.tool
def get_data_tool(): pass

@mcp.tool
def set_data_tool(): pass
`,
        ],
        [
          "src/tools/utils.py",
          `
@mcp.tool
def helper_tool(): pass
`,
        ],
        [
          "src/tools/_common.py",
          `
def shared_helper(): pass
`,
        ],
      ]);

      const context = createMockAssessmentContext({
        sourceCodeFiles,
        config,
      });

      const result = await assessor.assess(context);

      expect(result.status).toBe("PASS");
      expect(result.metrics.hasModularStructure).toBe(true);
      expect(result.metrics.modularizationScore).toBeGreaterThanOrEqual(90);
      expect(result.metrics.filesOver1000Lines).toBe(0);
      expect(result.metrics.filesOver2000Lines).toBe(0);
    });

    it("returns FAIL for monolithic file >2000 lines", async () => {
      // Create a 2500-line monolithic file with 25 tools
      const toolDefinitions = Array.from(
        { length: 25 },
        (_, i) => `@mcp.tool\ndef tool_${i}(): pass\n`,
      ).join("\n");
      const filler = "# Filler line\n".repeat(2400);
      const monolithicContent = toolDefinitions + filler;

      const sourceCodeFiles = new Map([["src/tools.py", monolithicContent]]);

      const context = createMockAssessmentContext({
        sourceCodeFiles,
        config,
      });

      const result = await assessor.assess(context);

      expect(result.status).toBe("FAIL");
      expect(result.metrics.filesOver2000Lines).toBeGreaterThan(0);
      expect(result.metrics.filesWithOver20Tools).toBeGreaterThan(0);
      expect(result.metrics.hasModularStructure).toBe(false);
      expect(
        result.checks.some(
          (c) => c.checkName === "file_line_count_error" && !c.passed,
        ),
      ).toBe(true);
    });

    it("returns NEED_MORE_INFO for warning threshold violations", async () => {
      // Create a 1500-line file with 15 tools
      const toolDefinitions = Array.from(
        { length: 15 },
        (_, i) => `@mcp.tool\ndef tool_${i}(): pass\n`,
      ).join("\n");
      const filler = "# Filler line\n".repeat(1400);
      const mediumContent = toolDefinitions + filler;

      const sourceCodeFiles = new Map([["src/tools.py", mediumContent]]);

      const context = createMockAssessmentContext({
        sourceCodeFiles,
        config,
      });

      const result = await assessor.assess(context);

      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.metrics.filesOver1000Lines).toBeGreaterThan(0);
      expect(result.metrics.filesOver2000Lines).toBe(0);
      expect(
        result.checks.some(
          (c) => c.checkName === "file_line_count_warning" && !c.passed,
        ),
      ).toBe(true);
    });

    it("includes recommendations for large files", async () => {
      const toolDefinitions = Array.from(
        { length: 25 },
        (_, i) => `@mcp.tool\ndef tool_${i}(): pass\n`,
      ).join("\n");
      const filler = "# Filler line\n".repeat(2400);
      const monolithicContent = toolDefinitions + filler;

      const sourceCodeFiles = new Map([["src/tools.py", monolithicContent]]);

      const context = createMockAssessmentContext({
        sourceCodeFiles,
        config,
      });

      const result = await assessor.assess(context);

      expect(result.recommendations.length).toBeGreaterThan(0);
      expect(
        result.recommendations.some((r) => r.toLowerCase().includes("split")),
      ).toBe(true);
    });

    it("tracks largest files with severity", async () => {
      const toolDefinitions = Array.from(
        { length: 25 },
        (_, i) => `@mcp.tool\ndef tool_${i}(): pass\n`,
      ).join("\n");
      const filler = "# Filler line\n".repeat(2400);
      const monolithicContent = toolDefinitions + filler;

      const sourceCodeFiles = new Map([["src/tools.py", monolithicContent]]);

      const context = createMockAssessmentContext({
        sourceCodeFiles,
        config,
      });

      const result = await assessor.assess(context);

      expect(result.metrics.largestFiles.length).toBeGreaterThan(0);
      const largestFile = result.metrics.largestFiles[0];
      expect(largestFile.path).toBe("src/tools.py");
      expect(largestFile.severity).toBe("HIGH");
      expect(largestFile.toolCount).toBe(25);
    });
  });

  describe("testCount tracking", () => {
    it("counts analyzed source files", async () => {
      const sourceCodeFiles = new Map([
        ["src/auth.py", "@mcp.tool\ndef login(): pass"],
        ["src/data.py", "@mcp.tool\ndef get(): pass"],
        ["src/utils.py", "def helper(): pass"],
      ]);

      const context = createMockAssessmentContext({
        sourceCodeFiles,
        config,
      });

      await assessor.assess(context);

      expect(assessor.getTestCount()).toBe(3);
    });

    it("excludes non-source files from count", async () => {
      const sourceCodeFiles = new Map([
        ["src/auth.py", "@mcp.tool\ndef login(): pass"],
        ["package.json", '{"name": "test"}'],
        ["README.md", "# Test"],
      ]);

      const context = createMockAssessmentContext({
        sourceCodeFiles,
        config,
      });

      await assessor.assess(context);

      expect(assessor.getTestCount()).toBe(1);
    });
  });
});
