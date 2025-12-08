/**
 * Claude Code Bridge Unit Tests
 *
 * Tests for the Claude Code CLI integration layer
 */

import {
  ClaudeCodeBridge,
  ClaudeCodeBridgeConfig,
  DEFAULT_CLAUDE_CODE_CONFIG,
  FULL_CLAUDE_CODE_CONFIG,
} from "./claudeCodeBridge";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Mock child_process
jest.mock("child_process", () => ({
  execSync: jest.fn(),
}));

import { execSync } from "child_process";

const mockedExecSync = execSync as jest.MockedFunction<typeof execSync>;

describe("ClaudeCodeBridge", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Default: Claude CLI is available
    mockedExecSync.mockImplementation((command: string) => {
      if (command === "which claude") {
        return "/usr/local/bin/claude";
      }
      return "";
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("Configuration", () => {
    it("should export DEFAULT_CLAUDE_CODE_CONFIG with features disabled", () => {
      expect(DEFAULT_CLAUDE_CODE_CONFIG.enabled).toBe(false);
      expect(DEFAULT_CLAUDE_CODE_CONFIG.features.aupSemanticAnalysis).toBe(
        false,
      );
      expect(DEFAULT_CLAUDE_CODE_CONFIG.features.behaviorInference).toBe(false);
      expect(
        DEFAULT_CLAUDE_CODE_CONFIG.features.intelligentTestGeneration,
      ).toBe(false);
    });

    it("should export FULL_CLAUDE_CODE_CONFIG with all features enabled", () => {
      expect(FULL_CLAUDE_CODE_CONFIG.enabled).toBe(true);
      expect(FULL_CLAUDE_CODE_CONFIG.features.aupSemanticAnalysis).toBe(true);
      expect(FULL_CLAUDE_CODE_CONFIG.features.behaviorInference).toBe(true);
      expect(FULL_CLAUDE_CODE_CONFIG.features.intelligentTestGeneration).toBe(
        true,
      );
      expect(FULL_CLAUDE_CODE_CONFIG.features.documentationAssessment).toBe(
        true,
      );
    });
  });

  describe("Initialization", () => {
    it("should check Claude CLI availability on construction", () => {
      new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      expect(mockedExecSync).toHaveBeenCalledWith("which claude", {
        stdio: "pipe",
        timeout: 5000,
      });
    });

    it("should handle Claude CLI not available", () => {
      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          throw new Error("Command not found");
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      expect(bridge.isFeatureEnabled("aupSemanticAnalysis")).toBe(false);
    });
  });

  describe("isFeatureEnabled", () => {
    it("should return true for enabled features when Claude is available", () => {
      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      expect(bridge.isFeatureEnabled("aupSemanticAnalysis")).toBe(true);
      expect(bridge.isFeatureEnabled("behaviorInference")).toBe(true);
    });

    it("should return false for disabled features", () => {
      const config: ClaudeCodeBridgeConfig = {
        enabled: true,
        features: {
          aupSemanticAnalysis: true,
          behaviorInference: false,
        },
      };
      const bridge = new ClaudeCodeBridge(config);
      expect(bridge.isFeatureEnabled("aupSemanticAnalysis")).toBe(true);
      expect(bridge.isFeatureEnabled("behaviorInference")).toBe(false);
    });

    it("should return false when bridge is disabled", () => {
      const config: ClaudeCodeBridgeConfig = {
        enabled: false,
        features: {
          aupSemanticAnalysis: true,
        },
      };
      const bridge = new ClaudeCodeBridge(config);
      expect(bridge.isFeatureEnabled("aupSemanticAnalysis")).toBe(false);
    });
  });

  describe("analyzeAUPViolation", () => {
    it("should return null when feature is disabled", async () => {
      const bridge = new ClaudeCodeBridge(DEFAULT_CLAUDE_CODE_CONFIG);
      const result = await bridge.analyzeAUPViolation("flagged text", {
        toolName: "test_tool",
        toolDescription: "Test description",
        category: "A",
        categoryName: "Category A",
        location: "tool_description",
      });
      expect(result).toBeNull();
    });

    it("should call Claude CLI and parse response", async () => {
      const mockResponse = JSON.stringify({
        isViolation: false,
        confidence: 85,
        reasoning: "This is a legitimate security tool",
        category: "A",
        suggestedAction: "allow",
        contextFactors: ["security context", "defensive purpose"],
      });

      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          return mockResponse;
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      const result = await bridge.analyzeAUPViolation("exploit detection", {
        toolName: "security_scanner",
        toolDescription: "Scans for vulnerabilities",
        category: "A",
        categoryName: "Category A",
        location: "tool_description",
      });

      expect(result).not.toBeNull();
      expect(result!.isViolation).toBe(false);
      expect(result!.isConfirmedViolation).toBe(false); // Alias should also be set
      expect(result!.confidence).toBe(85);
      expect(result!.suggestedAction).toBe("allow");
    });

    it("should handle Claude CLI errors gracefully", async () => {
      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          throw new Error("CLI timeout");
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge({
        ...FULL_CLAUDE_CODE_CONFIG,
        maxRetries: 0,
      });
      const result = await bridge.analyzeAUPViolation("text", {
        toolName: "test_tool",
        toolDescription: "Test",
        category: "A",
        categoryName: "Category A",
        location: "tool_description",
      });

      expect(result).toBeNull();
    });

    it("should handle JSON in markdown code blocks", async () => {
      const mockResponse = `Here is the analysis:

\`\`\`json
{
  "isViolation": true,
  "confidence": 90,
  "reasoning": "Clear violation",
  "category": "B",
  "suggestedAction": "block",
  "contextFactors": []
}
\`\`\``;

      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          return mockResponse;
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      const result = await bridge.analyzeAUPViolation("violation text", {
        toolName: "bad_tool",
        toolDescription: "Bad description",
        category: "B",
        categoryName: "Category B",
        location: "tool_description",
      });

      expect(result).not.toBeNull();
      expect(result!.isViolation).toBe(true);
      expect(result!.isConfirmedViolation).toBe(true); // Alias should also be set
      expect(result!.confidence).toBe(90);
    });
  });

  describe("inferToolBehavior", () => {
    const mockTool: Tool = {
      name: "delete_file",
      description: "Deletes a file from the filesystem",
      inputSchema: {
        type: "object",
        properties: {
          path: { type: "string", description: "File path to delete" },
        },
        required: ["path"],
      },
    };

    it("should return null when feature is disabled", async () => {
      const bridge = new ClaudeCodeBridge(DEFAULT_CLAUDE_CODE_CONFIG);
      const result = await bridge.inferToolBehavior(mockTool, {});
      expect(result).toBeNull();
    });

    it("should infer destructive behavior for delete tools", async () => {
      const mockResponse = JSON.stringify({
        expectedReadOnly: false,
        expectedDestructive: true,
        confidence: 95,
        reasoning: "Tool name and description indicate file deletion",
        suggestedAnnotations: {
          readOnlyHint: false,
          destructiveHint: true,
          idempotentHint: true,
        },
        misalignmentDetected: false,
        misalignmentDetails: null,
      });

      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          return mockResponse;
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      const result = await bridge.inferToolBehavior(mockTool, {
        readOnlyHint: true,
      });

      expect(result).not.toBeNull();
      expect(result!.expectedDestructive).toBe(true);
      expect(result!.expectedReadOnly).toBe(false);
      expect(result!.confidence).toBe(95);
    });

    it("should detect annotation misalignment", async () => {
      const mockResponse = JSON.stringify({
        expectedReadOnly: false,
        expectedDestructive: true,
        confidence: 90,
        reasoning: "Tool deletes files but is marked as read-only",
        suggestedAnnotations: {
          readOnlyHint: false,
          destructiveHint: true,
        },
        misalignmentDetected: true,
        misalignmentDetails:
          "Tool is marked readOnlyHint: true but appears to be destructive",
      });

      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          return mockResponse;
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      const result = await bridge.inferToolBehavior(mockTool, {
        readOnlyHint: true,
      });

      expect(result).not.toBeNull();
      expect(result!.misalignmentDetected).toBe(true);
      expect(result!.misalignmentDetails).toContain("readOnlyHint");
    });
  });

  describe("generateTestScenarios", () => {
    const mockTool: Tool = {
      name: "search_database",
      description: "Searches a database with a query",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string" },
          limit: { type: "number" },
        },
        required: ["query"],
      },
    };

    it("should return null when feature is disabled", async () => {
      const bridge = new ClaudeCodeBridge(DEFAULT_CLAUDE_CODE_CONFIG);
      const result = await bridge.generateTestScenarios(mockTool, 3);
      expect(result).toBeNull();
    });

    it("should generate test scenarios", async () => {
      const mockResponse = JSON.stringify({
        scenarios: [
          {
            name: "empty_query",
            description: "Test with empty query string",
            params: { query: "" },
            expectedBehavior: "Should return validation error",
            category: "error_case",
          },
          {
            name: "sql_injection",
            description: "Test SQL injection attempt",
            params: { query: "'; DROP TABLE users; --" },
            expectedBehavior: "Should sanitize or reject input",
            category: "edge_case",
          },
        ],
        reasoning: "These scenarios test input validation and security",
      });

      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          return mockResponse;
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      const result = await bridge.generateTestScenarios(mockTool, 3);

      expect(result).not.toBeNull();
      expect(result!.scenarios).toHaveLength(2);
      expect(result!.scenarios[0].category).toBe("error_case");
      expect(result!.scenarios[1].category).toBe("edge_case");
    });
  });

  describe("assessDocumentation", () => {
    it("should return null when feature is disabled", async () => {
      const bridge = new ClaudeCodeBridge(DEFAULT_CLAUDE_CODE_CONFIG);
      const result = await bridge.assessDocumentation("# README", 5);
      expect(result).toBeNull();
    });

    it("should assess documentation quality", async () => {
      const mockResponse = JSON.stringify({
        score: 75,
        issues: ["Missing installation instructions", "No security section"],
        suggestions: [
          "Add npm install instructions",
          "Document authentication requirements",
        ],
      });

      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          return mockResponse;
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      const result = await bridge.assessDocumentation(
        "# My MCP Server\n\nThis is a server.",
        5,
      );

      expect(result).not.toBeNull();
      expect(result!.score).toBe(75);
      expect(result!.issues).toHaveLength(2);
      expect(result!.suggestions).toHaveLength(2);
    });
  });

  describe("Retry Logic", () => {
    it("should retry on failure", async () => {
      let callCount = 0;
      const mockResponse = JSON.stringify({
        isViolation: false,
        confidence: 80,
        reasoning: "Test",
        category: "A",
        suggestedAction: "allow",
        contextFactors: [],
      });

      mockedExecSync.mockImplementation((command: string) => {
        if (command === "which claude") {
          return "/usr/local/bin/claude";
        }
        if (command.includes("claude --print")) {
          callCount++;
          if (callCount === 1) {
            throw new Error("Temporary failure");
          }
          return mockResponse;
        }
        return "";
      });

      const bridge = new ClaudeCodeBridge({
        ...FULL_CLAUDE_CODE_CONFIG,
        maxRetries: 2,
      });

      const result = await bridge.analyzeAUPViolation("text", {
        toolName: "test",
        toolDescription: "test",
        category: "A",
        categoryName: "Category A",
        location: "tool_description",
      });

      expect(result).not.toBeNull();
      expect(callCount).toBe(2); // First call failed, second succeeded
    });
  });
});
