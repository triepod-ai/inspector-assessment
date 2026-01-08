/**
 * Claude Code Bridge Integration Tests
 *
 * Tests HTTP transport integration with mcp-auditor's Claude API proxy endpoints.
 * These tests require mcp-auditor to be running at http://localhost:8085
 *
 * Run mcp-auditor: cd ~/mcp-auditor/server && node server.js
 */

import {
  ClaudeCodeBridge,
  ClaudeCodeBridgeConfig,
  HTTP_CLAUDE_CODE_CONFIG,
  FULL_CLAUDE_CODE_CONFIG,
} from "./claudeCodeBridge";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Integration test configuration
const MCP_AUDITOR_BASE_URL = "http://localhost:8085";
const HEALTH_CHECK_TIMEOUT = 5000;
const API_CALL_TIMEOUT = 30000;

// Server availability flag
let serverAvailable = false;
let claudeConfigured = false;

// Test helper functions
function createMockTool(overrides: Partial<Tool> = {}): Tool {
  return {
    name: "test_tool",
    description: "A test tool for integration testing",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string", description: "Test input" },
      },
    },
    ...overrides,
  };
}

function createReadOnlyTool(): Tool {
  return createMockTool({
    name: "list_files",
    description: "Lists files in a directory without modifying anything",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Directory path to list" },
      },
      required: ["path"],
    },
  });
}

function createDestructiveTool(): Tool {
  return createMockTool({
    name: "delete_file",
    description: "Permanently deletes a file from the filesystem",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "File path to delete" },
        force: { type: "boolean", description: "Skip confirmation" },
      },
      required: ["path"],
    },
  });
}

function createHttpConfig(
  overrides: Partial<ClaudeCodeBridgeConfig> = {},
): ClaudeCodeBridgeConfig {
  return {
    ...HTTP_CLAUDE_CODE_CONFIG,
    httpConfig: {
      baseUrl: MCP_AUDITOR_BASE_URL,
    },
    ...overrides,
  };
}

// Skip helper for conditional test execution
function skipIfServerUnavailable(): boolean {
  if (!serverAvailable) {
    // Jest doesn't have native conditional skip, so we return early
    return true;
  }
  return false;
}

function skipIfClaudeUnconfigured(): boolean {
  if (!claudeConfigured) {
    return true;
  }
  return false;
}

describe("ClaudeCodeBridge Integration Tests", () => {
  // Check server availability before all tests
  beforeAll(async () => {
    try {
      const healthResponse = await fetch(`${MCP_AUDITOR_BASE_URL}/api/health`, {
        signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
      });
      serverAvailable = healthResponse.ok;

      if (serverAvailable) {
        // Check if Claude API is configured
        const claudeResponse = await fetch(
          `${MCP_AUDITOR_BASE_URL}/api/claude/health`,
          {
            signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
          },
        );
        if (claudeResponse.ok) {
          const data = await claudeResponse.json();
          claudeConfigured = data.configured === true;
        }
      }
    } catch {
      serverAvailable = false;
      claudeConfigured = false;
    }

    if (!serverAvailable) {
      console.warn(
        "\n⚠️  mcp-auditor not running - integration tests will be skipped",
      );
      console.warn(
        "   Start server: cd ~/mcp-auditor/server && node server.js",
      );
    } else if (!claudeConfigured) {
      console.warn(
        "\n⚠️  Claude API not configured - some tests will be skipped",
      );
      console.warn("   Set ANTHROPIC_API_KEY environment variable");
    } else {
      console.log("\n✅ mcp-auditor running and Claude API configured");
    }
  }, HEALTH_CHECK_TIMEOUT + 1000);

  describe("Server Availability & Health Checks", () => {
    it("should detect server availability", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const bridge = new ClaudeCodeBridge(createHttpConfig());
      const available = await bridge.checkHttpHealth();
      expect(available).toBe(true);
    });

    it("should return health endpoint data", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const response = await fetch(`${MCP_AUDITOR_BASE_URL}/api/health`, {
        signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
      });
      const data = await response.json();

      expect(data).toHaveProperty("status", "healthy");
      expect(data).toHaveProperty("timestamp");
      expect(data).toHaveProperty("uptime");
      expect(data).toHaveProperty("memory");
    });

    it("should return Claude health endpoint data", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const response = await fetch(
        `${MCP_AUDITOR_BASE_URL}/api/claude/health`,
        {
          signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
        },
      );
      const data = await response.json();

      expect(data).toHaveProperty("success", true);
      expect(data).toHaveProperty("configured");
      expect(data).toHaveProperty("allowedModels");
      expect(Array.isArray(data.allowedModels)).toBe(true);
    });

    it("should handle unavailable server gracefully", async () => {
      const bridge = new ClaudeCodeBridge({
        ...HTTP_CLAUDE_CODE_CONFIG,
        httpConfig: {
          baseUrl: "http://localhost:9999", // Non-existent server
        },
      });

      const available = await bridge.checkHttpHealth();
      expect(available).toBe(false);
    });

    it("should report correct transport type", () => {
      const httpBridge = new ClaudeCodeBridge(createHttpConfig());
      expect(httpBridge.getTransport()).toBe("http");

      const cliBridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      expect(cliBridge.getTransport()).toBe("cli");
    });
  });

  describe("Tool Inference End-to-End", () => {
    it(
      "should infer read-only tool behavior via HTTP",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const tool = createReadOnlyTool();

        const result = await bridge.inferToolBehavior(tool);

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("expectedReadOnly");
          expect(result).toHaveProperty("expectedDestructive");
          expect(result).toHaveProperty("confidence");
          expect(result).toHaveProperty("suggestedAnnotations");

          // Read-only tool should be inferred as read-only
          expect(result.expectedReadOnly).toBe(true);
          expect(result.expectedDestructive).toBe(false);
        }
      },
      API_CALL_TIMEOUT,
    );

    it(
      "should infer destructive tool behavior via HTTP",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const tool = createDestructiveTool();

        const result = await bridge.inferToolBehavior(tool);

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("expectedReadOnly");
          expect(result).toHaveProperty("expectedDestructive");
          expect(result).toHaveProperty("confidence");

          // Destructive tool should be inferred as destructive
          expect(result.expectedReadOnly).toBe(false);
          expect(result.expectedDestructive).toBe(true);
        }
      },
      API_CALL_TIMEOUT,
    );

    it(
      "should include reasoning and suggested annotations",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const tool = createDestructiveTool();

        const result = await bridge.inferToolBehavior(tool);

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("reasoning");
          expect(result).toHaveProperty("suggestedAnnotations");
          expect(typeof result.reasoning).toBe("string");
        }
      },
      API_CALL_TIMEOUT,
    );

    it(
      "should handle tool inference with existing annotations",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const tool = createMockTool({
          name: "execute_query",
          description: "Executes a database query",
        });

        // Pass existing annotations to compare against
        const result = await bridge.inferToolBehavior(tool, {
          readOnlyHint: false,
          destructiveHint: false,
        });

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("confidence");
          expect(typeof result.confidence).toBe("number");
        }
      },
      API_CALL_TIMEOUT,
    );
  });

  describe("General Messages Proxy", () => {
    it(
      "should send basic message via HTTP proxy",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const response = await fetch(
          `${MCP_AUDITOR_BASE_URL}/api/claude/messages`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              messages: [
                { role: "user", content: "Say 'test' and nothing else" },
              ],
              maxTokens: 50,
            }),
            signal: AbortSignal.timeout(API_CALL_TIMEOUT),
          },
        );

        const data = await response.json();
        expect(data).toHaveProperty("success", true);
        expect(data).toHaveProperty("content");
        expect(data).toHaveProperty("usage");
        expect(data.usage).toHaveProperty("inputTokens");
        expect(data.usage).toHaveProperty("outputTokens");
      },
      API_CALL_TIMEOUT,
    );

    it(
      "should support custom model selection",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const response = await fetch(
          `${MCP_AUDITOR_BASE_URL}/api/claude/messages`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              messages: [{ role: "user", content: "Reply with OK" }],
              model: "claude-3-5-haiku-20241022",
              maxTokens: 20,
            }),
            signal: AbortSignal.timeout(API_CALL_TIMEOUT),
          },
        );

        const data = await response.json();
        expect(data).toHaveProperty("success", true);
      },
      API_CALL_TIMEOUT,
    );

    it("should reject invalid model selection", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const response = await fetch(
        `${MCP_AUDITOR_BASE_URL}/api/claude/messages`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: [{ role: "user", content: "Hello" }],
            model: "invalid-model-name",
          }),
          signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
        },
      );

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty("error");
    });

    it("should reject empty messages array", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const response = await fetch(
        `${MCP_AUDITOR_BASE_URL}/api/claude/messages`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: [],
          }),
          signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
        },
      );

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty("error");
    });
  });

  describe("Error Handling & Edge Cases", () => {
    it("should handle connection timeout gracefully", async () => {
      const bridge = new ClaudeCodeBridge({
        ...HTTP_CLAUDE_CODE_CONFIG,
        timeout: 100, // Very short timeout
        httpConfig: {
          baseUrl: "http://10.255.255.1", // Non-routable IP (will timeout)
        },
      });

      // This should not throw, but return false
      const available = await bridge.checkHttpHealth();
      expect(available).toBe(false);
    }, 5000);

    it("should return null when HTTP request fails", async () => {
      const bridge = new ClaudeCodeBridge({
        ...HTTP_CLAUDE_CODE_CONFIG,
        httpConfig: {
          baseUrl: "http://localhost:9999", // Non-existent server
        },
      });

      const tool = createReadOnlyTool();
      const result = await bridge.inferToolBehavior(tool);

      // inferToolBehavior returns null when the request fails
      expect(result).toBeNull();
    });

    it("should handle malformed tool definition", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const response = await fetch(
        `${MCP_AUDITOR_BASE_URL}/api/claude/tool-inference`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tool: "not an object", // Invalid: should be object
          }),
          signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
        },
      );

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty("error");
    });

    it("should handle missing tool name", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const response = await fetch(
        `${MCP_AUDITOR_BASE_URL}/api/claude/tool-inference`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tool: {
              description: "A tool without a name",
            },
          }),
          signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
        },
      );

      expect(response.status).toBe(400);
      const data = await response.json();
      expect(data).toHaveProperty("error");
    });
  });

  describe("Transport Switching", () => {
    it("should correctly identify HTTP transport", () => {
      const bridge = new ClaudeCodeBridge(createHttpConfig());
      expect(bridge.getTransport()).toBe("http");
    });

    it("should correctly identify CLI transport", () => {
      const bridge = new ClaudeCodeBridge(FULL_CLAUDE_CODE_CONFIG);
      expect(bridge.getTransport()).toBe("cli");
    });

    it("should default to CLI when transport not specified", () => {
      const bridge = new ClaudeCodeBridge({
        enabled: true,
        features: {
          intelligentTestGeneration: false,
          aupSemanticAnalysis: false,
          behaviorInference: false,
          annotationInference: false,
          documentationAssessment: false,
          documentationQuality: false,
        },
      });
      expect(bridge.getTransport()).toBe("cli");
    });

    it("should use HTTP transport when configured", async () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const bridge = new ClaudeCodeBridge(createHttpConfig());

      // HTTP health check should work
      const healthy = await bridge.checkHttpHealth();
      expect(healthy).toBe(true);
    });
  });

  describe("Feature Integration via HTTP", () => {
    it("should enable features when HTTP transport is configured", () => {
      if (skipIfServerUnavailable()) {
        console.log("   [SKIPPED] Server not available");
        return;
      }

      const bridge = new ClaudeCodeBridge(createHttpConfig());

      // Features should be enabled based on config
      expect(bridge.isFeatureEnabled("behaviorInference")).toBe(true);
      expect(bridge.isFeatureEnabled("aupSemanticAnalysis")).toBe(true);
      expect(bridge.isFeatureEnabled("documentationAssessment")).toBe(true);
    });

    it(
      "should analyze AUP violation via HTTP",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());

        const result = await bridge.analyzeAUPViolation(
          "rm -rf /", // Matched text that triggered the check
          {
            toolName: "execute_command",
            toolDescription: "Executes system commands",
            category: "C", // C = Malware & Cyberweapons
            categoryName: "Malware & Cyberweapons",
            location: "tool_output",
          },
        );

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("isViolation");
          expect(result).toHaveProperty("confidence");
          expect(typeof result.isViolation).toBe("boolean");
        }
      },
      API_CALL_TIMEOUT,
    );

    it(
      "should assess documentation via HTTP",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());

        // assessDocumentation takes readme content and tool count
        const readmeContent = `
# Test MCP Server

This server provides data validation tools.

## Tools

### validate_data
Validates input data against predefined rules.

## Installation
Run \`npm install\` to install dependencies.
`;

        const result = await bridge.assessDocumentation(readmeContent, 5);

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("score");
          expect(result).toHaveProperty("issues");
          expect(result).toHaveProperty("suggestions");
          expect(typeof result.score).toBe("number");
        }
      },
      API_CALL_TIMEOUT,
    );

    it(
      "should generate test scenarios via HTTP",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const tool = createMockTool({
          name: "search_database",
          description: "Searches the database with the given query",
          inputSchema: {
            type: "object",
            properties: {
              query: { type: "string", description: "Search query" },
              limit: { type: "number", description: "Max results" },
            },
            required: ["query"],
          },
        });

        // generateTestScenarios returns TestGenerationResult with scenarios array
        const result = await bridge.generateTestScenarios(tool, 0);

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("scenarios");
          expect(Array.isArray(result.scenarios)).toBe(true);
          if (result.scenarios.length > 0) {
            expect(result.scenarios[0]).toHaveProperty("name");
            expect(result.scenarios[0]).toHaveProperty("description");
          }
        }
      },
      API_CALL_TIMEOUT,
    );
  });

  describe("Retry Logic & Resilience", () => {
    it("should respect maxRetries configuration", async () => {
      const bridge = new ClaudeCodeBridge({
        ...HTTP_CLAUDE_CODE_CONFIG,
        maxRetries: 0, // No retries
        httpConfig: {
          baseUrl: "http://localhost:9999", // Non-existent server
        },
      });

      const startTime = Date.now();
      const tool = createReadOnlyTool();
      await bridge.inferToolBehavior(tool, {});
      const elapsed = Date.now() - startTime;

      // With no retries, should complete quickly (no retry delays)
      expect(elapsed).toBeLessThan(5000);
    });

    it("should include retry count in configuration", () => {
      const config = createHttpConfig({ maxRetries: 3 });
      expect(config.maxRetries).toBe(3);
    });
  });

  describe("Direct Tool Inference Endpoint", () => {
    it(
      "should call tool-inference endpoint directly",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const response = await fetch(
          `${MCP_AUDITOR_BASE_URL}/api/claude/tool-inference`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              tool: {
                name: "read_config",
                description: "Reads application configuration from a file",
                inputSchema: {
                  type: "object",
                  properties: {
                    configPath: { type: "string" },
                  },
                },
              },
              context: {
                serverName: "config-server",
              },
            }),
            signal: AbortSignal.timeout(API_CALL_TIMEOUT),
          },
        );

        expect(response.ok).toBe(true);
        const data = await response.json();

        expect(data).toHaveProperty("success", true);
        expect(data).toHaveProperty("inference");
        expect(data.inference).toHaveProperty("expectedReadOnly");
        expect(data.inference).toHaveProperty("expectedDestructive");
        expect(data.inference).toHaveProperty("confidence");
        expect(data.inference).toHaveProperty("suggestedAnnotations");
        expect(data).toHaveProperty("usage");
      },
      API_CALL_TIMEOUT,
    );

    it(
      "should return usage statistics",
      async () => {
        if (skipIfServerUnavailable() || skipIfClaudeUnconfigured()) {
          console.log("   [SKIPPED] Server or Claude not available");
          return;
        }

        const response = await fetch(
          `${MCP_AUDITOR_BASE_URL}/api/claude/tool-inference`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              tool: {
                name: "simple_tool",
                description: "A simple tool",
              },
            }),
            signal: AbortSignal.timeout(API_CALL_TIMEOUT),
          },
        );

        const data = await response.json();
        expect(data.usage).toHaveProperty("inputTokens");
        expect(data.usage).toHaveProperty("outputTokens");
        expect(data.usage).toHaveProperty("totalTokens");
        expect(typeof data.usage.totalTokens).toBe("number");
      },
      API_CALL_TIMEOUT,
    );
  });
});
