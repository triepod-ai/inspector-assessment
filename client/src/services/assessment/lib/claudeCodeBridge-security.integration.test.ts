/**
 * Claude Code Bridge - Security Semantic Analysis Integration Tests
 *
 * Tests the analyzeSecurityResponse method via HTTP transport to mcp-auditor.
 * These tests require mcp-auditor running at http://localhost:8085 with Claude API configured.
 *
 * Run mcp-auditor: cd ~/mcp-auditor/server && node server.js
 *
 * Test scenarios cover:
 * - False positive reduction (API wrapper coincidental numbers)
 * - Safe reflection detection (storage tools echoing input)
 * - True vulnerability confirmation (command execution evidence)
 * - Graceful degradation when Claude unavailable
 */

import {
  ClaudeCodeBridge,
  ClaudeCodeBridgeConfig,
  HTTP_CLAUDE_CODE_CONFIG,
  SecurityAnalysisContext,
} from "./claudeCodeBridge";

// Integration test configuration
const MCP_AUDITOR_BASE_URL = "http://localhost:8085";
const HEALTH_CHECK_TIMEOUT = 5000;
const API_CALL_TIMEOUT = 30000;

// Server availability flags
let serverAvailable = false;
let claudeConfigured = false;

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

// Pre-test setup - check server availability
beforeAll(async () => {
  try {
    // Check if mcp-auditor is running
    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      HEALTH_CHECK_TIMEOUT,
    );

    const healthResponse = await fetch(`${MCP_AUDITOR_BASE_URL}/api/health`, {
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    serverAvailable = healthResponse.ok;

    if (serverAvailable) {
      // Check if Claude API is configured
      const claudeHealthResponse = await fetch(
        `${MCP_AUDITOR_BASE_URL}/api/claude/health`,
        { signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT) },
      );
      claudeConfigured = claudeHealthResponse.ok;
    }
  } catch {
    serverAvailable = false;
    claudeConfigured = false;
  }

  if (!serverAvailable) {
    console.log(
      "⚠️ mcp-auditor not running - skipping security integration tests",
    );
  } else if (!claudeConfigured) {
    console.log(
      "⚠️ Claude API not configured in mcp-auditor - skipping Claude-dependent tests",
    );
  }
}, HEALTH_CHECK_TIMEOUT + 5000);

describe("ClaudeCodeBridge - Security Semantic Analysis Integration", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Server Availability", () => {
    it("should detect mcp-auditor availability", async () => {
      if (!serverAvailable) {
        console.log("Test skipped: mcp-auditor not available");
        return;
      }

      const config = createHttpConfig();
      const bridge = new ClaudeCodeBridge(config);

      const isHealthy = await bridge.checkHttpHealth();
      expect(isHealthy).toBe(true);
    });

    it("should handle unavailable server gracefully", async () => {
      const config = createHttpConfig({
        httpConfig: {
          baseUrl: "http://localhost:9999", // Non-existent server
        },
        timeout: 1000,
        maxRetries: 0,
      });

      const bridge = new ClaudeCodeBridge(config);
      const isHealthy = await bridge.checkHttpHealth();
      expect(isHealthy).toBe(false);
    });
  });

  describe("analyzeSecurityResponse - False Positive Scenarios", () => {
    it(
      "should identify API wrapper false positive (Issue #58)",
      async () => {
        if (!serverAvailable || !claudeConfigured) {
          console.log("Test skipped: mcp-auditor/Claude not available");
          return;
        }

        const config = createHttpConfig({ timeout: API_CALL_TIMEOUT });
        const bridge = new ClaudeCodeBridge(config);

        // Issue #58 scenario: API wrapper returns JSON with coincidental number
        const context: SecurityAnalysisContext = {
          toolName: "get_company_data",
          toolDescription: "Fetch company information from external CRM API",
          attackPattern: "Calculator Injection",
          payload: "2+2",
          response: '{"company": "Acme Corp", "records": 4, "status": "ok"}',
          originalConfidence: "medium",
        };

        const result = await bridge.analyzeSecurityResponse(context);

        // Should identify as false positive
        expect(result).not.toBeNull();
        if (result) {
          expect(result.isVulnerable).toBe(false);
          expect(result.suggestedAction).toBe("mark_safe");
          expect(result.reasoning).toBeDefined();
          expect(result.reasoning.length).toBeGreaterThan(10);
        }
      },
      API_CALL_TIMEOUT + 5000,
    );

    it(
      "should identify safe reflection (storage tool)",
      async () => {
        if (!serverAvailable || !claudeConfigured) {
          console.log("Test skipped: mcp-auditor/Claude not available");
          return;
        }

        const config = createHttpConfig({ timeout: API_CALL_TIMEOUT });
        const bridge = new ClaudeCodeBridge(config);

        // Safe reflection: storage tool stores and returns the input
        const context: SecurityAnalysisContext = {
          toolName: "qdrant_store",
          toolDescription: "Store information in Qdrant vector database",
          attackPattern: "Command Injection",
          payload: "; rm -rf /",
          response:
            '{"status": "stored", "document": "; rm -rf /", "id": "abc123"}',
          originalConfidence: "medium",
        };

        const result = await bridge.analyzeSecurityResponse(context);

        expect(result).not.toBeNull();
        if (result) {
          expect(result.isVulnerable).toBe(false);
          expect(["mark_safe", "flag_for_review"]).toContain(
            result.suggestedAction,
          );
        }
      },
      API_CALL_TIMEOUT + 5000,
    );
  });

  describe("analyzeSecurityResponse - True Vulnerability Scenarios", () => {
    it(
      "should confirm command injection vulnerability",
      async () => {
        if (!serverAvailable || !claudeConfigured) {
          console.log("Test skipped: mcp-auditor/Claude not available");
          return;
        }

        const config = createHttpConfig({ timeout: API_CALL_TIMEOUT });
        const bridge = new ClaudeCodeBridge(config);

        // True vulnerability: command output in response
        const context: SecurityAnalysisContext = {
          toolName: "run_script",
          toolDescription: "Execute shell scripts",
          attackPattern: "Command Injection",
          payload: "whoami",
          response: "root\nuid=0(root) gid=0(root) groups=0(root)",
          originalConfidence: "medium",
        };

        const result = await bridge.analyzeSecurityResponse(context);

        expect(result).not.toBeNull();
        if (result) {
          expect(result.isVulnerable).toBe(true);
          expect(result.refinedConfidence).toBe("high");
          expect(result.suggestedAction).toBe("flag_vulnerable");
        }
      },
      API_CALL_TIMEOUT + 5000,
    );

    it(
      "should confirm path traversal vulnerability",
      async () => {
        if (!serverAvailable || !claudeConfigured) {
          console.log("Test skipped: mcp-auditor/Claude not available");
          return;
        }

        const config = createHttpConfig({ timeout: API_CALL_TIMEOUT });
        const bridge = new ClaudeCodeBridge(config);

        // True vulnerability: sensitive file contents in response
        const context: SecurityAnalysisContext = {
          toolName: "read_file",
          toolDescription: "Read file contents",
          attackPattern: "Path Traversal",
          payload: "../../../etc/passwd",
          response:
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
          originalConfidence: "medium",
        };

        const result = await bridge.analyzeSecurityResponse(context);

        expect(result).not.toBeNull();
        if (result) {
          expect(result.isVulnerable).toBe(true);
          expect(result.refinedConfidence).toBe("high");
        }
      },
      API_CALL_TIMEOUT + 5000,
    );
  });

  describe("analyzeSecurityResponse - Edge Cases", () => {
    it(
      "should handle validation rejection as safe",
      async () => {
        if (!serverAvailable || !claudeConfigured) {
          console.log("Test skipped: mcp-auditor/Claude not available");
          return;
        }

        const config = createHttpConfig({ timeout: API_CALL_TIMEOUT });
        const bridge = new ClaudeCodeBridge(config);

        // Safe: input validation rejected the payload
        const context: SecurityAnalysisContext = {
          toolName: "scrape_url",
          toolDescription: "Scrape content from a URL",
          attackPattern: "Command Injection",
          payload: "; cat /etc/passwd",
          response:
            "MCP error -32602: Tool parameter validation failed: url: Invalid url format",
          originalConfidence: "low",
        };

        const result = await bridge.analyzeSecurityResponse(context);

        expect(result).not.toBeNull();
        if (result) {
          expect(result.isVulnerable).toBe(false);
          expect(result.suggestedAction).toBe("mark_safe");
        }
      },
      API_CALL_TIMEOUT + 5000,
    );

    it(
      "should handle empty response gracefully",
      async () => {
        if (!serverAvailable || !claudeConfigured) {
          console.log("Test skipped: mcp-auditor/Claude not available");
          return;
        }

        const config = createHttpConfig({ timeout: API_CALL_TIMEOUT });
        const bridge = new ClaudeCodeBridge(config);

        const context: SecurityAnalysisContext = {
          toolName: "test_tool",
          toolDescription: "Test tool",
          attackPattern: "Command Injection",
          payload: "whoami",
          response: "",
          originalConfidence: "low",
        };

        const result = await bridge.analyzeSecurityResponse(context);

        // Should handle empty response without crashing
        expect(result).not.toBeNull();
      },
      API_CALL_TIMEOUT + 5000,
    );
  });

  describe("Feature Flag Behavior", () => {
    it("should return null when securitySemanticAnalysis is disabled", async () => {
      const config = createHttpConfig({
        features: {
          securitySemanticAnalysis: false,
        },
      });

      const bridge = new ClaudeCodeBridge(config);

      const context: SecurityAnalysisContext = {
        toolName: "test_tool",
        toolDescription: "Test",
        attackPattern: "Command Injection",
        payload: "test",
        response: "test",
        originalConfidence: "medium",
      };

      const result = await bridge.analyzeSecurityResponse(context);
      expect(result).toBeNull();
    });
  });

  describe("HTTP Transport", () => {
    it("should use HTTP transport when configured", () => {
      const config = createHttpConfig();
      const bridge = new ClaudeCodeBridge(config);

      expect(bridge.getTransport()).toBe("http");
    });

    it("should handle HTTP timeout gracefully", async () => {
      if (!serverAvailable) {
        console.log("Test skipped: mcp-auditor not available");
        return;
      }

      // Very short timeout to force timeout error
      const config = createHttpConfig({
        timeout: 1, // 1ms timeout
        maxRetries: 0,
      });

      const bridge = new ClaudeCodeBridge(config);

      const context: SecurityAnalysisContext = {
        toolName: "test_tool",
        toolDescription: "Test",
        attackPattern: "Test",
        payload: "test",
        response: "test",
        originalConfidence: "medium",
      };

      const result = await bridge.analyzeSecurityResponse(context);
      // Should return null on timeout, not throw
      expect(result).toBeNull();
    });
  });
});
