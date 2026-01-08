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
  HTTP_CLAUDE_CODE_CONFIG,
} from "./claudeCodeBridge";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Mock child_process
jest.mock("child_process", () => ({
  execSync: jest.fn(),
  execFileSync: jest.fn(),
}));

import { execSync, execFileSync } from "child_process";

const mockedExecSync = execSync as jest.MockedFunction<typeof execSync>;
const mockedExecFileSync = execFileSync as jest.MockedFunction<
  typeof execFileSync
>;

describe("ClaudeCodeBridge", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    // Default: Claude CLI is available (checked via execSync)
    mockedExecSync.mockImplementation((command: string) => {
      if (command === "which claude") {
        return "/usr/local/bin/claude";
      }
      return "";
    });
    // Default: execFileSync returns empty (will be overridden in specific tests)
    mockedExecFileSync.mockReturnValue("");
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

      // execFileSync is used for the actual claude command
      mockedExecFileSync.mockReturnValue(mockResponse);

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
      // execFileSync throws error to simulate CLI timeout
      mockedExecFileSync.mockImplementation(() => {
        throw new Error("CLI timeout");
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

      // execFileSync is used for the actual claude command
      mockedExecFileSync.mockReturnValue(mockResponse);

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

      // execFileSync is used for the actual claude command
      mockedExecFileSync.mockReturnValue(mockResponse);

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

      // execFileSync is used for the actual claude command
      mockedExecFileSync.mockReturnValue(mockResponse);

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

      // execFileSync is used for the actual claude command
      mockedExecFileSync.mockReturnValue(mockResponse);

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

      // execFileSync is used for the actual claude command
      mockedExecFileSync.mockReturnValue(mockResponse);

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

      // execFileSync is used for the actual claude command - track calls and simulate failure
      mockedExecFileSync.mockImplementation(() => {
        callCount++;
        if (callCount === 1) {
          throw new Error("Temporary failure");
        }
        return mockResponse;
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

  describe("HTTP Transport", () => {
    // Store original fetch
    const originalFetch = global.fetch;

    beforeEach(() => {
      // Reset fetch mock before each test
      global.fetch = jest.fn();
    });

    afterEach(() => {
      // Restore original fetch
      global.fetch = originalFetch;
    });

    describe("Configuration", () => {
      it("should export HTTP_CLAUDE_CODE_CONFIG with http transport", () => {
        expect(HTTP_CLAUDE_CODE_CONFIG.enabled).toBe(true);
        expect(HTTP_CLAUDE_CODE_CONFIG.transport).toBe("http");
        expect(HTTP_CLAUDE_CODE_CONFIG.httpConfig?.baseUrl).toBe(
          "http://localhost:8085",
        );
        expect(HTTP_CLAUDE_CODE_CONFIG.features.behaviorInference).toBe(true);
      });
    });

    describe("Initialization", () => {
      it("should skip CLI availability check for HTTP transport", () => {
        // Clear previous calls
        mockedExecSync.mockClear();

        const bridge = new ClaudeCodeBridge(HTTP_CLAUDE_CODE_CONFIG);

        // Should NOT call which claude for HTTP transport
        expect(mockedExecSync).not.toHaveBeenCalledWith(
          "which claude",
          expect.anything(),
        );
        expect(bridge.getTransport()).toBe("http");
      });

      it("should be unavailable if httpConfig.baseUrl is missing", () => {
        const config: ClaudeCodeBridgeConfig = {
          enabled: true,
          transport: "http",
          httpConfig: undefined,
          features: { behaviorInference: true },
        };

        const bridge = new ClaudeCodeBridge(config);
        expect(bridge.isFeatureEnabled("behaviorInference")).toBe(false);
      });

      it("should be available when httpConfig is properly configured", () => {
        const config: ClaudeCodeBridgeConfig = {
          enabled: true,
          transport: "http",
          httpConfig: { baseUrl: "http://localhost:8085" },
          features: { behaviorInference: true },
        };

        const bridge = new ClaudeCodeBridge(config);
        expect(bridge.isFeatureEnabled("behaviorInference")).toBe(true);
      });
    });

    describe("getTransport", () => {
      it("should return cli for default config", () => {
        const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
        expect(bridge.getTransport()).toBe("cli");
      });

      it("should return http for HTTP config", () => {
        const bridge = new ClaudeCodeBridge(HTTP_CLAUDE_CODE_CONFIG);
        expect(bridge.getTransport()).toBe("http");
      });
    });

    describe("HTTP Execution", () => {
      it("should make HTTP request to Claude API proxy", async () => {
        const mockResponse = {
          content: JSON.stringify({
            expectedReadOnly: true,
            expectedDestructive: false,
            confidence: 85,
            reasoning: "Tool appears to be read-only",
            suggestedAnnotations: { readOnlyHint: true },
            misalignmentDetected: false,
          }),
        };

        (global.fetch as jest.Mock).mockResolvedValue({
          ok: true,
          json: () => Promise.resolve(mockResponse),
        });

        const bridge = new ClaudeCodeBridge(HTTP_CLAUDE_CODE_CONFIG);
        const mockTool: Tool = {
          name: "get_data",
          description: "Gets data from the system",
          inputSchema: { type: "object", properties: {} },
        };

        const result = await bridge.inferToolBehavior(mockTool);

        expect(global.fetch).toHaveBeenCalledWith(
          "http://localhost:8085/api/claude/messages",
          expect.objectContaining({
            method: "POST",
            headers: expect.objectContaining({
              "Content-Type": "application/json",
            }),
          }),
        );

        expect(result).not.toBeNull();
        expect(result!.expectedReadOnly).toBe(true);
        expect(result!.confidence).toBe(85);
      });

      it("should handle HTTP errors gracefully", async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
          ok: false,
          status: 500,
          text: () => Promise.resolve("Internal Server Error"),
        });

        const bridge = new ClaudeCodeBridge({
          ...HTTP_CLAUDE_CODE_CONFIG,
          maxRetries: 0,
        });
        const mockTool: Tool = {
          name: "test_tool",
          description: "Test",
          inputSchema: { type: "object", properties: {} },
        };

        const result = await bridge.inferToolBehavior(mockTool);
        expect(result).toBeNull();
      });

      it("should handle network errors gracefully", async () => {
        (global.fetch as jest.Mock).mockRejectedValue(
          new Error("Network error"),
        );

        const bridge = new ClaudeCodeBridge({
          ...HTTP_CLAUDE_CODE_CONFIG,
          maxRetries: 0,
        });
        const mockTool: Tool = {
          name: "test_tool",
          description: "Test",
          inputSchema: { type: "object", properties: {} },
        };

        const result = await bridge.inferToolBehavior(mockTool);
        expect(result).toBeNull();
      });

      it("should include API key in Authorization header when provided", async () => {
        (global.fetch as jest.Mock).mockResolvedValue({
          ok: true,
          json: () =>
            Promise.resolve({
              content: JSON.stringify({
                expectedReadOnly: true,
                expectedDestructive: false,
                confidence: 80,
                reasoning: "Test",
                suggestedAnnotations: {},
                misalignmentDetected: false,
              }),
            }),
        });

        const config: ClaudeCodeBridgeConfig = {
          ...HTTP_CLAUDE_CODE_CONFIG,
          httpConfig: {
            baseUrl: "http://localhost:8085",
            apiKey: "test-api-key",
          },
        };

        const bridge = new ClaudeCodeBridge(config);
        const mockTool: Tool = {
          name: "test_tool",
          description: "Test",
          inputSchema: { type: "object", properties: {} },
        };

        await bridge.inferToolBehavior(mockTool);

        expect(global.fetch).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            headers: expect.objectContaining({
              Authorization: "Bearer test-api-key",
            }),
          }),
        );
      });

      it("should retry HTTP requests on failure", async () => {
        let callCount = 0;
        (global.fetch as jest.Mock).mockImplementation(() => {
          callCount++;
          if (callCount === 1) {
            return Promise.resolve({
              ok: false,
              status: 503,
              text: () => Promise.resolve("Service Unavailable"),
            });
          }
          return Promise.resolve({
            ok: true,
            json: () =>
              Promise.resolve({
                content: JSON.stringify({
                  isViolation: false,
                  confidence: 80,
                  reasoning: "Test",
                  category: "A",
                  suggestedAction: "allow",
                  contextFactors: [],
                }),
              }),
          });
        });

        const bridge = new ClaudeCodeBridge({
          ...HTTP_CLAUDE_CODE_CONFIG,
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

    describe("checkHttpHealth", () => {
      it("should return true when health endpoint responds OK", async () => {
        (global.fetch as jest.Mock).mockResolvedValue({ ok: true });

        const bridge = new ClaudeCodeBridge(HTTP_CLAUDE_CODE_CONFIG);
        const healthy = await bridge.checkHttpHealth();

        expect(healthy).toBe(true);
        expect(global.fetch).toHaveBeenCalledWith(
          "http://localhost:8085/api/health",
          expect.objectContaining({ method: "GET" }),
        );
      });

      it("should return false when health endpoint fails", async () => {
        (global.fetch as jest.Mock).mockResolvedValue({ ok: false });

        const bridge = new ClaudeCodeBridge(HTTP_CLAUDE_CODE_CONFIG);
        const healthy = await bridge.checkHttpHealth();

        expect(healthy).toBe(false);
      });

      it("should return false for CLI transport", async () => {
        const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
        const healthy = await bridge.checkHttpHealth();

        expect(healthy).toBe(false);
      });
    });
  });
});
