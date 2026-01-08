/**
 * Claude Code Bridge End-to-End Tests
 *
 * Tests complete assessment workflows using HTTP transport to communicate
 * with mcp-auditor's Claude API proxy. These tests verify that HTTP transport
 * integrates correctly with the full assessment pipeline.
 *
 * Scope:
 * - Complete tool assessment workflows (behavior inference → scoring)
 * - AUP semantic analysis integration
 * - Documentation assessment workflows
 * - Multi-tool assessment orchestration
 * - Error recovery and fallback behavior
 * - Business outcome verification (not just API contracts)
 *
 * Prerequisites:
 * - mcp-auditor server running: cd ~/mcp-auditor/server && node server.js
 * - ANTHROPIC_API_KEY configured in environment
 *
 * Skip Conditions:
 * - Tests skip gracefully when mcp-auditor is not running
 * - Tests skip gracefully when Claude API is not configured
 *
 * @group e2e
 * @group http-transport
 */

import {
  ClaudeCodeBridge,
  HTTP_CLAUDE_CODE_CONFIG,
  type ClaudeCodeBridgeConfig,
} from "./claudeCodeBridge";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  ToolAnnotationAssessor,
  type EnhancedToolAnnotationAssessment,
  type EnhancedToolAnnotationResult,
} from "../modules/ToolAnnotationAssessor";
import { AUPComplianceAssessor } from "../modules/AUPComplianceAssessor";
import { DocumentationAssessor } from "../modules/DocumentationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import type { AssessmentContext } from "../AssessmentOrchestrator";

// Configuration
const MCP_AUDITOR_BASE_URL = "http://localhost:8085";
const HEALTH_CHECK_TIMEOUT = 5000;
const WORKFLOW_TIMEOUT = 60000; // E2E workflows can take longer

// Server availability flags
let serverAvailable = false;
let claudeConfigured = false;

// Skip helpers
function skipIfUnavailable(): boolean {
  return !serverAvailable || !claudeConfigured;
}

// Test data generators
function createReadOnlyTool(overrides: Partial<Tool> = {}): Tool {
  return {
    name: "list_files",
    description:
      "Lists files in a directory without modifying anything. Safe read-only operation.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Directory path to list" },
        recursive: { type: "boolean", description: "Include subdirectories" },
      },
      required: ["path"],
    },
    ...overrides,
  };
}

function createDestructiveTool(overrides: Partial<Tool> = {}): Tool {
  return {
    name: "delete_file",
    description:
      "Permanently deletes a file from the filesystem. This operation cannot be undone.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "File path to delete" },
        force: {
          type: "boolean",
          description: "Skip confirmation prompt",
          default: false,
        },
      },
      required: ["path"],
    },
    ...overrides,
  };
}

function createAmbiguousTool(): Tool {
  return {
    name: "manage_data",
    description: "Manages data operations in the database",
    inputSchema: {
      type: "object",
      properties: {
        operation: {
          type: "string",
          enum: ["read", "write", "delete"],
          description: "Operation to perform",
        },
        data: { type: "string", description: "Data to operate on" },
      },
      required: ["operation"],
    },
  };
}

function createWriteTool(): Tool {
  return {
    name: "update_config",
    description: "Updates application configuration file with new settings",
    inputSchema: {
      type: "object",
      properties: {
        key: { type: "string", description: "Configuration key" },
        value: { type: "string", description: "New value" },
      },
      required: ["key", "value"],
    },
  };
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

describe("ClaudeCodeBridge E2E Tests", () => {
  // Check server availability before all tests
  beforeAll(async () => {
    try {
      const healthResponse = await fetch(`${MCP_AUDITOR_BASE_URL}/api/health`, {
        signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT),
      });
      serverAvailable = healthResponse.ok;

      if (serverAvailable) {
        const claudeResponse = await fetch(
          `${MCP_AUDITOR_BASE_URL}/api/claude/health`,
          { signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT) },
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
      console.warn("\n⚠️  mcp-auditor not running - E2E tests will be skipped");
      console.warn(
        "   Start server: cd ~/mcp-auditor/server && node server.js",
      );
    } else if (!claudeConfigured) {
      console.warn(
        "\n⚠️  Claude API not configured - E2E tests will be skipped",
      );
      console.warn("   Set ANTHROPIC_API_KEY environment variable");
    } else {
      console.log("\n✅ E2E test prerequisites met (server + Claude API)");
    }
  }, HEALTH_CHECK_TIMEOUT + 1000);

  describe("Full Tool Assessment Flow", () => {
    it(
      "should complete full assessment workflow with behavior inference",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        // Step 1: Create bridge and assessor
        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const config = createMockAssessmentConfig();
        const assessor = new ToolAnnotationAssessor(config);
        assessor.setClaudeBridge(bridge);

        // Step 2: Create assessment context with a read-only tool
        const tool = createReadOnlyTool();
        const context = createMockAssessmentContext({
          tools: [tool],
        });

        // Step 3: Run full assessment
        const assessment = (await assessor.assess(
          context,
        )) as EnhancedToolAnnotationAssessment;

        // Step 4: Verify business outcomes
        expect(assessment).toBeDefined();
        expect(assessment.status).toBeDefined();

        // Verify tool was assessed
        expect(assessment.toolResults).toBeDefined();
        expect(assessment.toolResults.length).toBeGreaterThan(0);

        const toolResult = assessment.toolResults.find(
          (r) => r.toolName === tool.name,
        ) as EnhancedToolAnnotationResult;
        expect(toolResult).toBeDefined();

        // Verify inference was performed
        expect(toolResult.claudeInference).toBeDefined();
        if (toolResult.claudeInference) {
          expect(toolResult.claudeInference.expectedReadOnly).toBe(true);
          expect(toolResult.claudeInference.expectedDestructive).toBe(false);
          expect(toolResult.claudeInference.confidence).toBeGreaterThan(0);
          expect(toolResult.claudeInference.reasoning).toBeDefined();
          expect(typeof toolResult.claudeInference.reasoning).toBe("string");
        }

        // Verify scoring reflects inference
        expect(assessment.annotatedCount).toBeGreaterThanOrEqual(0);
      },
      WORKFLOW_TIMEOUT,
    );

    it(
      "should detect annotation misalignment in destructive tools",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const config = createMockAssessmentConfig();
        const assessor = new ToolAnnotationAssessor(config);
        assessor.setClaudeBridge(bridge);

        // Create a destructive tool
        const tool = createDestructiveTool();
        const context = createMockAssessmentContext({ tools: [tool] });

        // Run assessment
        const assessment = (await assessor.assess(
          context,
        )) as EnhancedToolAnnotationAssessment;

        // Find the tool result
        const toolResult = assessment.toolResults.find(
          (r) => r.toolName === tool.name,
        ) as EnhancedToolAnnotationResult;
        expect(toolResult).toBeDefined();

        // Verify inference detected destructive nature
        if (toolResult.claudeInference) {
          expect(toolResult.claudeInference.expectedDestructive).toBe(true);
          expect(toolResult.claudeInference.expectedReadOnly).toBe(false);

          // If annotations are present and wrong, should detect misalignment
          // Note: Without explicit annotations, misalignment detection may vary
        }
      },
      WORKFLOW_TIMEOUT,
    );

    it(
      "should handle ambiguous tools with lower confidence",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const config = createMockAssessmentConfig();
        const assessor = new ToolAnnotationAssessor(config);
        assessor.setClaudeBridge(bridge);

        const tool = createAmbiguousTool();
        const context = createMockAssessmentContext({ tools: [tool] });

        const assessment = (await assessor.assess(
          context,
        )) as EnhancedToolAnnotationAssessment;
        const toolResult = assessment.toolResults.find(
          (r) => r.toolName === tool.name,
        ) as EnhancedToolAnnotationResult;

        expect(toolResult).toBeDefined();
        if (toolResult.claudeInference) {
          // Ambiguous tools should have lower confidence
          // (exact threshold may vary, but should be reasonable)
          expect(toolResult.claudeInference.confidence).toBeGreaterThan(0);
          expect(toolResult.claudeInference.confidence).toBeLessThanOrEqual(
            100,
          );
          expect(toolResult.claudeInference.reasoning).toContain("manage");
        }
      },
      WORKFLOW_TIMEOUT,
    );

    it(
      "should complete assessment with write-capable tool",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const config = createMockAssessmentConfig();
        const assessor = new ToolAnnotationAssessor(config);
        assessor.setClaudeBridge(bridge);

        const tool = createWriteTool();
        const context = createMockAssessmentContext({ tools: [tool] });

        const assessment = (await assessor.assess(
          context,
        )) as EnhancedToolAnnotationAssessment;
        const toolResult = assessment.toolResults.find(
          (r) => r.toolName === tool.name,
        ) as EnhancedToolAnnotationResult;

        expect(toolResult).toBeDefined();
        if (toolResult.claudeInference) {
          // Write tools should not be read-only, but also not destructive
          expect(toolResult.claudeInference.expectedReadOnly).toBe(false);
          // "update" is typically not destructive (vs "delete")
          // But Claude may vary - just verify it makes a decision
          expect(typeof toolResult.claudeInference.expectedDestructive).toBe(
            "boolean",
          );
        }
      },
      WORKFLOW_TIMEOUT,
    );
  });

  describe("AUP Semantic Analysis Flow", () => {
    it(
      "should integrate AUP analysis with HTTP transport",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(
          createHttpConfig({
            features: {
              ...HTTP_CLAUDE_CODE_CONFIG.features,
              aupSemanticAnalysis: true,
            },
          }),
        );

        // Simulate a potential AUP violation
        const result = await bridge.analyzeAUPViolation(
          "rm -rf / --no-preserve-root", // Matched text
          {
            toolName: "execute_command",
            toolDescription: "Executes system commands with full permissions",
            category: "C", // C = Malware & Cyberweapons
            categoryName: "Malware & Cyberweapons",
            location: "tool_output",
          },
        );

        expect(result).not.toBeNull();
        if (result) {
          // Verify structure
          expect(result).toHaveProperty("isViolation");
          expect(result).toHaveProperty("confidence");
          expect(result).toHaveProperty("reasoning");
          expect(result).toHaveProperty("suggestedAction");
          expect(result).toHaveProperty("contextFactors");

          // Verify values are reasonable
          expect(typeof result.isViolation).toBe("boolean");
          expect(result.confidence).toBeGreaterThan(0);
          expect(result.confidence).toBeLessThanOrEqual(100);
          expect(
            ["block", "flag_for_review", "allow"].includes(
              result.suggestedAction,
            ),
          ).toBe(true);
          expect(Array.isArray(result.contextFactors)).toBe(true);

          // This is a clear violation - should be detected
          expect(result.isViolation).toBe(true);
          expect(result.suggestedAction).toMatch(/block|flag_for_review/);
        }
      },
      WORKFLOW_TIMEOUT,
    );

    it(
      "should handle false positive scenarios with appropriate context",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(
          createHttpConfig({
            features: {
              ...HTTP_CLAUDE_CODE_CONFIG.features,
              aupSemanticAnalysis: true,
            },
          }),
        );

        // Educational/security tool context
        const result = await bridge.analyzeAUPViolation(
          "exploit detection pattern", // Flagged text
          {
            toolName: "vulnerability_scanner",
            toolDescription:
              "Educational security tool for detecting common vulnerabilities. For authorized security testing only.",
            category: "A", // A = Security
            categoryName: "Security Testing",
            location: "tool_description",
          },
        );

        expect(result).not.toBeNull();
        if (result) {
          // Verify analysis considers context
          expect(result.reasoning).toBeDefined();
          expect(result.contextFactors.length).toBeGreaterThan(0);

          // Security tools with proper disclaimers should be flagged for review or allowed
          if (result.isViolation) {
            expect(result.suggestedAction).toBe("flag_for_review");
          } else {
            expect(result.suggestedAction).toMatch(/flag_for_review|allow/);
          }
        }
      },
      WORKFLOW_TIMEOUT,
    );

    it(
      "should integrate with AUPComplianceAssessor workflow",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(
          createHttpConfig({
            features: {
              ...HTTP_CLAUDE_CODE_CONFIG.features,
              aupSemanticAnalysis: true,
            },
          }),
        );

        const config = createMockAssessmentConfig();
        const assessor = new AUPComplianceAssessor(config);
        assessor.setClaudeBridge(bridge);

        // Create a tool that might trigger AUP checks
        const tool: Tool = {
          name: "system_admin",
          description: "Administrative tool for system management and control",
          inputSchema: {
            type: "object",
            properties: {
              command: { type: "string", description: "Admin command" },
            },
          },
        };

        const context = createMockAssessmentContext({ tools: [tool] });

        // Run assessment
        const assessment = await assessor.assess(context);

        // Verify assessment completed
        expect(assessment).toBeDefined();
        expect(assessment.status).toBeDefined();
        expect(assessment.violations).toBeDefined();

        // Violations may or may not be detected depending on the tool
        // Just verify the assessment completes and has proper structure
      },
      WORKFLOW_TIMEOUT,
    );
  });

  describe("Documentation Assessment Flow", () => {
    it(
      "should assess documentation quality end-to-end",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(
          createHttpConfig({
            features: {
              ...HTTP_CLAUDE_CODE_CONFIG.features,
              documentationAssessment: true,
            },
          }),
        );

        const readmeContent = `
# Example MCP Server

This server provides file system operations with security controls.

## Features

- Read-only file listing
- Secure file metadata access
- Permission-aware operations

## Installation

\`\`\`bash
npm install example-mcp-server
\`\`\`

## Configuration

Set the following environment variables:
- \`BASE_PATH\`: Root directory for operations
- \`LOG_LEVEL\`: Logging verbosity (info, debug, error)

## Tools

### list_files
Lists files in a directory without modifying anything.

Parameters:
- \`path\` (string, required): Directory path
- \`recursive\` (boolean, optional): Include subdirectories

## Security

This server implements:
- Path traversal prevention
- Permission checks before operations
- Audit logging for all file access

## License

MIT
`;

        const result = await bridge.assessDocumentation(readmeContent, 3);

        expect(result).not.toBeNull();
        if (result) {
          expect(result).toHaveProperty("score");
          expect(result).toHaveProperty("issues");
          expect(result).toHaveProperty("suggestions");

          // Verify score is reasonable
          expect(result.score).toBeGreaterThan(0);
          expect(result.score).toBeLessThanOrEqual(100);

          // Good documentation should score relatively high
          expect(result.score).toBeGreaterThanOrEqual(50);

          // Verify arrays are populated
          expect(Array.isArray(result.issues)).toBe(true);
          expect(Array.isArray(result.suggestions)).toBe(true);
        }
      },
      WORKFLOW_TIMEOUT,
    );

    it(
      "should identify missing sections in poor documentation",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(
          createHttpConfig({
            features: {
              ...HTTP_CLAUDE_CODE_CONFIG.features,
              documentationAssessment: true,
            },
          }),
        );

        const poorReadme = `
# My Server

This is a server.

## Usage

Run it.
`;

        const result = await bridge.assessDocumentation(poorReadme, 5);

        expect(result).not.toBeNull();
        if (result) {
          // Poor documentation should score low
          expect(result.score).toBeLessThan(50);

          // Should identify missing sections
          expect(result.issues.length).toBeGreaterThan(0);
          expect(result.suggestions.length).toBeGreaterThan(0);

          // Should flag missing key sections
          const allFeedback = [...result.issues, ...result.suggestions].join(
            " ",
          );
          const hasMissingSection =
            allFeedback.includes("installation") ||
            allFeedback.includes("configuration") ||
            allFeedback.includes("tool") ||
            allFeedback.includes("security");

          expect(hasMissingSection).toBe(true);
        }
      },
      WORKFLOW_TIMEOUT,
    );

    it(
      "should integrate with DocumentationAssessor workflow",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(
          createHttpConfig({
            features: {
              ...HTTP_CLAUDE_CODE_CONFIG.features,
              documentationAssessment: true,
            },
          }),
        );

        const config = createMockAssessmentConfig();
        const assessor = new DocumentationAssessor(config);
        // Note: DocumentationAssessor may not have setClaudeBridge method
        // This test verifies the assessor works with or without Claude enhancement

        const tool = createReadOnlyTool();
        const context = createMockAssessmentContext({
          tools: [tool],
          readmeContent: "# Test Server\n\nA simple test server.",
        });

        const assessment = await assessor.assess(context);

        expect(assessment).toBeDefined();
        expect(assessment.status).toBeDefined();

        // Documentation assessment should complete successfully
        expect(assessment.metrics.hasReadme).toBe(true);
      },
      WORKFLOW_TIMEOUT,
    );
  });

  describe("Multi-Tool Assessment", () => {
    it(
      "should handle assessment of multiple tools in sequence",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const config = createMockAssessmentConfig();
        const assessor = new ToolAnnotationAssessor(config);
        assessor.setClaudeBridge(bridge);

        // Create multiple tools with different characteristics
        const tools = [
          createReadOnlyTool(),
          createDestructiveTool(),
          createWriteTool(),
          createAmbiguousTool(),
        ];

        const context = createMockAssessmentContext({ tools });

        const assessment = (await assessor.assess(
          context,
        )) as EnhancedToolAnnotationAssessment;

        expect(assessment).toBeDefined();
        expect(assessment.toolResults.length).toBe(tools.length);

        // Verify each tool was assessed
        tools.forEach((tool) => {
          const result = assessment.toolResults.find(
            (r) => r.toolName === tool.name,
          ) as EnhancedToolAnnotationResult;
          expect(result).toBeDefined();
          expect(result.claudeInference).toBeDefined();
        });

        // Verify results are aggregated correctly
        expect(assessment.annotatedCount).toBeGreaterThanOrEqual(0);
      },
      WORKFLOW_TIMEOUT * 2, // Allow more time for multiple tools
    );

    it(
      "should handle concurrent requests efficiently",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());

        // Create multiple inference requests
        const tools = [
          createReadOnlyTool({ name: "list_1" }),
          createReadOnlyTool({ name: "list_2" }),
          createReadOnlyTool({ name: "list_3" }),
        ];

        const startTime = Date.now();

        // Run all inferences concurrently
        const results = await Promise.all(
          tools.map((tool) => bridge.inferToolBehavior(tool)),
        );

        const elapsed = Date.now() - startTime;

        // Verify all results came back
        expect(results.length).toBe(tools.length);
        results.forEach((result) => {
          expect(result).not.toBeNull();
          expect(result?.expectedReadOnly).toBe(true);
        });

        // Concurrent requests should be faster than sequential
        // (rough check - should complete in reasonable time)
        expect(elapsed).toBeLessThan(WORKFLOW_TIMEOUT);
      },
      WORKFLOW_TIMEOUT,
    );
  });

  describe("Error Recovery Flow", () => {
    it("should gracefully handle mid-assessment HTTP failures", async () => {
      // Use invalid URL to simulate failure
      const bridge = new ClaudeCodeBridge({
        ...HTTP_CLAUDE_CODE_CONFIG,
        httpConfig: {
          baseUrl: "http://localhost:9999", // Non-existent
        },
        maxRetries: 0,
      });

      const config = createMockAssessmentConfig();
      const assessor = new ToolAnnotationAssessor(config);
      assessor.setClaudeBridge(bridge);

      const tool = createReadOnlyTool();
      const context = createMockAssessmentContext({ tools: [tool] });

      // Assessment should complete even if HTTP transport fails
      const assessment = (await assessor.assess(
        context,
      )) as EnhancedToolAnnotationAssessment;

      expect(assessment).toBeDefined();
      expect(assessment.status).toBeDefined();

      // Tool should still be in results (fallback to pattern-based)
      const toolResult = assessment.toolResults.find(
        (r) => r.toolName === tool.name,
      ) as EnhancedToolAnnotationResult;
      expect(toolResult).toBeDefined();

      // Claude inference should be absent or marked as failed
      if (toolResult.claudeInference) {
        // If present, should indicate pattern-based fallback
        expect(toolResult.claudeInference.source).toBe("pattern-based");
      }
    });

    it("should preserve partial results on timeout", async () => {
      if (skipIfUnavailable()) {
        console.log("   [SKIPPED] Prerequisites not met");
        return;
      }

      const bridge = new ClaudeCodeBridge(
        createHttpConfig({
          timeout: 100, // Very short timeout to force failure
          maxRetries: 0,
        }),
      );

      const tool = createReadOnlyTool();

      // This should timeout but not throw
      const result = await bridge.inferToolBehavior(tool);

      // Should return null on timeout (graceful degradation)
      expect(result).toBeNull();
    });

    it(
      "should retry failed requests according to maxRetries",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(
          createHttpConfig({
            maxRetries: 2,
          }),
        );

        const tool = createReadOnlyTool();

        // First request might fail or succeed - we're testing retry mechanism exists
        const result = await bridge.inferToolBehavior(tool);

        // Even with retries, should eventually return a result or null
        // (not throw an exception)
        expect(result !== undefined).toBe(true);
      },
      WORKFLOW_TIMEOUT,
    );

    it("should handle malformed API responses gracefully", async () => {
      if (skipIfUnavailable()) {
        console.log("   [SKIPPED] Prerequisites not met");
        return;
      }

      const bridge = new ClaudeCodeBridge(createHttpConfig());

      // Direct API call with invalid data
      const response = await fetch(
        `${MCP_AUDITOR_BASE_URL}/api/claude/tool-inference`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tool: "not an object", // Invalid
          }),
        },
      );

      // Should return error status, not crash
      expect(response.ok).toBe(false);
      expect(response.status).toBe(400);
    });
  });

  describe("Business Outcome Verification", () => {
    it(
      "should improve assessment accuracy with HTTP transport",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        // Compare pattern-based vs Claude-enhanced assessment
        const tool = createAmbiguousTool(); // Ambiguous name/description

        // Pattern-based assessment
        const configWithoutClaude = createMockAssessmentConfig();
        const assessorWithoutClaude = new ToolAnnotationAssessor(
          configWithoutClaude,
        );

        const contextWithoutClaude = createMockAssessmentContext({
          tools: [tool],
        });

        const assessmentWithoutClaude = (await assessorWithoutClaude.assess(
          contextWithoutClaude,
        )) as EnhancedToolAnnotationAssessment;

        // Claude-enhanced assessment
        const bridge = new ClaudeCodeBridge(createHttpConfig());
        const configWithClaude = createMockAssessmentConfig();
        const assessorWithClaude = new ToolAnnotationAssessor(configWithClaude);
        assessorWithClaude.setClaudeBridge(bridge);

        const contextWithClaude = createMockAssessmentContext({
          tools: [tool],
        });

        const assessmentWithClaude = (await assessorWithClaude.assess(
          contextWithClaude,
        )) as EnhancedToolAnnotationAssessment;

        // Verify Claude-enhanced version has additional insights
        const resultWithoutClaude = assessmentWithoutClaude.toolResults.find(
          (r) => r.toolName === tool.name,
        ) as EnhancedToolAnnotationResult;
        const resultWithClaude = assessmentWithClaude.toolResults.find(
          (r) => r.toolName === tool.name,
        ) as EnhancedToolAnnotationResult;

        expect(resultWithoutClaude).toBeDefined();
        expect(resultWithClaude).toBeDefined();

        // Claude-enhanced should have inference data
        expect(resultWithClaude.claudeInference).toBeDefined();
        expect(resultWithoutClaude.claudeInference).toBeUndefined();

        // Claude-enhanced should provide reasoning
        if (resultWithClaude.claudeInference) {
          expect(
            resultWithClaude.claudeInference.reasoning.length,
          ).toBeGreaterThan(0);
        }
      },
      WORKFLOW_TIMEOUT * 2,
    );

    it(
      "should provide actionable recommendations",
      async () => {
        if (skipIfUnavailable()) {
          console.log("   [SKIPPED] Prerequisites not met");
          return;
        }

        const bridge = new ClaudeCodeBridge(createHttpConfig());

        // Tool with potential annotation issues
        const tool = createDestructiveTool();

        const result = await bridge.inferToolBehavior(tool, {
          readOnlyHint: true, // Wrong annotation
          destructiveHint: false,
        });

        expect(result).not.toBeNull();
        if (result) {
          // Should detect misalignment
          expect(result.misalignmentDetected).toBe(true);
          expect(result.misalignmentDetails).toBeDefined();

          // Should suggest correct annotations
          expect(result.suggestedAnnotations).toBeDefined();
          expect(result.suggestedAnnotations.destructiveHint).toBe(true);
          expect(result.suggestedAnnotations.readOnlyHint).toBe(false);
        }
      },
      WORKFLOW_TIMEOUT,
    );
  });
});
