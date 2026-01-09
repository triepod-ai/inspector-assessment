/**
 * Cross-Tool State-Based Authorization Bypass Detection Tests (Issue #92)
 *
 * Validates detection against Challenge #7 ground truth:
 * - vulnerable_admin_action_tool: Checks config_state["admin_mode"] (MUST detect)
 * - vulnerable_config_modifier_tool: Sets config_state["admin_mode"] (MUST detect as modifier)
 * - Hardened versions: Use independent auth (MUST NOT flag)
 *
 * Success criteria:
 * - 100% recall: Vulnerable tools detected
 * - 100% precision: 0 false positives on hardened tools
 */

import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";
import {
  CrossToolStateTester,
  type CrossToolTestResult,
  type CallToolFunction,
} from "../modules/securityTests/CrossToolStateTester";
import { scanDescriptionForPoisoning } from "../modules/annotations/DescriptionPoisoningDetector";
import type { CompatibilityCallToolResult } from "../modules/securityTests/SecurityPayloadTester";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("Cross-Tool State-Based Authorization Bypass - Challenge #7 Validation", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  /**
   * Helper to create mock response
   */
  function createMockResponse(
    jsonContent: Record<string, unknown>,
  ): CompatibilityCallToolResult {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(jsonContent),
        },
      ],
    } as CompatibilityCallToolResult;
  }

  describe("SecurityResponseAnalyzer.analyzeStateBasedAuthBypass()", () => {
    describe("Vulnerable Patterns (MUST detect)", () => {
      it("should detect admin_mode: true in response", () => {
        const response = createMockResponse({
          result: "Secrets read successfully",
          admin_mode: true,
          secrets: { API_KEY: "sk-secret-12345" },
          evidence: "cross-tool privilege escalation",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(true);
        expect(result.safe).toBe(false);
        expect(result.stateDependency).toBe("SHARED_STATE");
      });

      it("should detect hint to use config_modifier", () => {
        const response = createMockResponse({
          result: "Access denied",
          hint: "use config_modifier to enable admin_mode first",
          admin_mode: false,
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(true);
        expect(result.stateDependency).toBe("SHARED_STATE");
      });

      it("should detect 'set by another tool' pattern", () => {
        const response = createMockResponse({
          result: "Admin privileges granted",
          note: "admin_mode was set by another tool",
          admin_mode: true,
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(true);
      });

      it("should detect elevated privileges granted pattern", () => {
        const response = createMockResponse({
          result: "Success",
          message: "Elevated privileges granted via config state",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(true);
      });

      it("should detect cross-tool privilege evidence pattern", () => {
        const response = createMockResponse({
          result: "Secret data accessed",
          evidence: "cross-tool privilege escalation successful",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(true);
      });
    });

    describe("Safe Patterns (MUST NOT flag)", () => {
      it("should NOT flag response with shared_state_checked: false", () => {
        const response = createMockResponse({
          result: "Request stored for review",
          shared_state_checked: false,
          note: "Independent authorization required for privileged actions",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(false);
        expect(result.safe).toBe(true);
        expect(result.stateDependency).toBe("INDEPENDENT");
      });

      it("should NOT flag response with independent_auth_required: true", () => {
        const response = createMockResponse({
          result: "Stored for admin review",
          independent_auth_required: true,
          action: "read secrets",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(false);
        expect(result.safe).toBe(true);
      });

      it("should NOT flag response mentioning independent authorization", () => {
        const response = createMockResponse({
          result: "Action blocked",
          message: "Requires independent authorization for each request",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(false);
        expect(result.safe).toBe(true);
      });

      it("should NOT flag response with not shared state", () => {
        const response = createMockResponse({
          result: "Access denied",
          note: "This tool does not use shared state for authorization",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(false);
        expect(result.safe).toBe(true);
      });
    });

    describe("Unknown State (Neither pattern matched)", () => {
      it("should return UNKNOWN for neutral responses", () => {
        const response = createMockResponse({
          result: "Calculator evaluated: 2 + 2 = 4",
        });

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(false);
        expect(result.safe).toBe(false);
        expect(result.stateDependency).toBe("UNKNOWN");
      });

      it("should return UNKNOWN for empty responses", () => {
        const response = createMockResponse({});

        const result = analyzer.analyzeStateBasedAuthBypass(response);
        expect(result.vulnerable).toBe(false);
        expect(result.safe).toBe(false);
        expect(result.stateDependency).toBe("UNKNOWN");
      });
    });
  });

  describe("CrossToolStateTester", () => {
    let tester: CrossToolStateTester;

    beforeEach(() => {
      tester = new CrossToolStateTester({ verbose: false });
    });

    describe("identifyCrossToolPairs()", () => {
      it("should identify admin and modifier tool pairs", () => {
        const tools: Tool[] = [
          {
            name: "vulnerable_admin_action_tool",
            description: "Perform privileged admin actions",
            inputSchema: { type: "object", properties: {} },
          },
          {
            name: "vulnerable_config_modifier_tool",
            description: "Modify configuration settings",
            inputSchema: { type: "object", properties: {} },
          },
          {
            name: "safe_calculator_tool",
            description: "Evaluate math expressions",
            inputSchema: { type: "object", properties: {} },
          },
        ];

        const pairs = tester.identifyCrossToolPairs(tools);

        expect(pairs.length).toBeGreaterThan(0);
        expect(
          pairs.some(
            (p) =>
              p.admin.name === "vulnerable_admin_action_tool" &&
              p.modifier.name === "vulnerable_config_modifier_tool",
          ),
        ).toBe(true);
      });

      it("should NOT pair non-admin/modifier tools", () => {
        const tools: Tool[] = [
          {
            name: "calculator_tool",
            description: "Calculate numbers",
            inputSchema: { type: "object", properties: {} },
          },
          {
            name: "weather_tool",
            description: "Get weather information",
            inputSchema: { type: "object", properties: {} },
          },
        ];

        const pairs = tester.identifyCrossToolPairs(tools);
        expect(pairs.length).toBe(0);
      });

      it("should identify pairs by description patterns", () => {
        const tools: Tool[] = [
          {
            name: "secure_action",
            description: "Requires admin privileges to execute",
            inputSchema: { type: "object", properties: {} },
          },
          {
            name: "settings_updater",
            description: "Enable admin mode or activate features",
            inputSchema: { type: "object", properties: {} },
          },
        ];

        const pairs = tester.identifyCrossToolPairs(tools);
        expect(pairs.length).toBeGreaterThan(0);
      });
    });

    describe("testPrivilegeEscalation()", () => {
      it("should detect privilege escalation on vulnerable server", async () => {
        // Mock vulnerable server behavior
        const mockCallTool: CallToolFunction = async (name, params) => {
          if (name === "vulnerable_admin_action_tool") {
            // First call: denied, Second call: access granted
            if ((params.action as string).includes("secrets")) {
              // Simulate state change after config_modifier call
              return createMockResponse({
                result: "Secrets retrieved",
                admin_mode: true,
                secrets: { API_KEY: "leaked" },
                evidence: "cross-tool privilege escalation",
              });
            }
          }
          if (name === "vulnerable_config_modifier_tool") {
            return createMockResponse({
              result: "Admin mode activated",
              admin_mode: true,
              elevated_privileges: true,
            });
          }
          return createMockResponse({ error: "Unknown tool" });
        };

        // Note: This test simulates the scenario where baseline check is skipped
        // because the server is vulnerable and returns access on first call
        const adminTool: Tool = {
          name: "vulnerable_admin_action_tool",
          inputSchema: { type: "object", properties: {} },
        };
        const modifierTool: Tool = {
          name: "vulnerable_config_modifier_tool",
          inputSchema: { type: "object", properties: {} },
        };

        const result = await tester.testPrivilegeEscalation(
          mockCallTool,
          adminTool,
          modifierTool,
        );

        // Since baseline already has access, reason should be "baseline_has_access"
        expect(result.reason).toBe("baseline_has_access");
      });

      it("should NOT detect escalation on hardened server", async () => {
        // Mock hardened server behavior
        const mockCallTool: CallToolFunction = async (name, params) => {
          if (name === "vulnerable_admin_action_tool") {
            return createMockResponse({
              result: "Access denied",
              shared_state_checked: false,
              note: "Requires independent per-request authorization",
              action_requested: params.action,
            });
          }
          if (name === "vulnerable_config_modifier_tool") {
            return createMockResponse({
              result: "Setting stored for review",
              stored: true,
              not_modifying_runtime: true,
              setting: params.setting,
            });
          }
          return createMockResponse({ error: "Unknown tool" });
        };

        const adminTool: Tool = {
          name: "vulnerable_admin_action_tool",
          inputSchema: { type: "object", properties: {} },
        };
        const modifierTool: Tool = {
          name: "vulnerable_config_modifier_tool",
          inputSchema: { type: "object", properties: {} },
        };

        const result = await tester.testPrivilegeEscalation(
          mockCallTool,
          adminTool,
          modifierTool,
        );

        expect(result.vulnerable).toBe(false);
        expect(result.reason).toBe("modifier_rejected");
      });

      it("should handle modifier rejection gracefully", async () => {
        const mockCallTool: CallToolFunction = async (name) => {
          if (name === "vulnerable_admin_action_tool") {
            return createMockResponse({
              result: "Access denied - admin required",
            });
          }
          if (name === "vulnerable_config_modifier_tool") {
            return createMockResponse({
              result: "Configuration not modified",
              stored_for_review: true,
            });
          }
          return createMockResponse({});
        };

        const adminTool: Tool = {
          name: "vulnerable_admin_action_tool",
          inputSchema: { type: "object", properties: {} },
        };
        const modifierTool: Tool = {
          name: "vulnerable_config_modifier_tool",
          inputSchema: { type: "object", properties: {} },
        };

        const result = await tester.testPrivilegeEscalation(
          mockCallTool,
          adminTool,
          modifierTool,
        );

        expect(result.vulnerable).toBe(false);
        expect(result.reason).toBe("modifier_rejected");
      });

      it("should handle tool call errors gracefully", async () => {
        const mockCallTool: CallToolFunction = async () => {
          throw new Error("Connection refused");
        };

        const adminTool: Tool = {
          name: "test_admin_tool",
          inputSchema: { type: "object", properties: {} },
        };
        const modifierTool: Tool = {
          name: "test_modifier_tool",
          inputSchema: { type: "object", properties: {} },
        };

        const result = await tester.testPrivilegeEscalation(
          mockCallTool,
          adminTool,
          modifierTool,
        );

        expect(result.vulnerable).toBe(false);
        expect(result.reason).toBe("test_error");
        expect(result.error).toContain("Connection refused");
      });
    });

    describe("runAllSequenceTests()", () => {
      it("should test all identified pairs", async () => {
        const tools: Tool[] = [
          {
            name: "admin_action_tool",
            description: "Admin actions",
            inputSchema: { type: "object", properties: {} },
          },
          {
            name: "config_modifier_tool",
            description: "Modify settings",
            inputSchema: { type: "object", properties: {} },
          },
        ];

        const mockCallTool: CallToolFunction = async () => {
          return createMockResponse({ result: "Access denied" });
        };

        const results = await tester.runAllSequenceTests(tools, mockCallTool);

        expect(results.size).toBeGreaterThan(0);
      });

      it("should return empty map when no pairs found", async () => {
        const tools: Tool[] = [
          {
            name: "calculator",
            description: "Math",
            inputSchema: { type: "object", properties: {} },
          },
        ];

        const mockCallTool: CallToolFunction = async () => {
          return createMockResponse({});
        };

        const results = await tester.runAllSequenceTests(tools, mockCallTool);
        expect(results.size).toBe(0);
      });
    });

    describe("summarizeResults()", () => {
      it("should correctly summarize test results", () => {
        const results = new Map<string, CrossToolTestResult>();
        results.set("modifier → admin", {
          vulnerable: true,
          reason: "privilege_escalation_confirmed",
        });
        results.set("settings → privileged", {
          vulnerable: false,
          reason: "escalation_blocked",
        });
        results.set("config → sensitive", {
          vulnerable: false,
          reason: "test_error",
          error: "Timeout",
        });

        const summary = tester.summarizeResults(results);

        expect(summary.total).toBe(3);
        expect(summary.vulnerable).toBe(1);
        expect(summary.safe).toBe(1);
        expect(summary.errors).toBe(1);
        expect(summary.vulnerablePairs).toContain("modifier → admin");
      });
    });
  });

  describe("Description Poisoning Detection - State Dependency Patterns", () => {
    it("should detect shared_state reference in description", () => {
      const tool: Tool = {
        name: "admin_tool",
        description:
          "This tool checks config_state for authorization before executing",
        inputSchema: { type: "object", properties: {} },
      };

      const result = scanDescriptionForPoisoning(tool);

      expect(result.detected).toBe(true);
      expect(
        result.patterns.some((p) => p.category === "state_dependency"),
      ).toBe(true);
      expect(
        result.patterns.some((p) => p.name === "shared_state_reference"),
      ).toBe(true);
    });

    it("should detect cross_tool_dependency in description", () => {
      const tool: Tool = {
        name: "privileged_action",
        description: "Authorization can be set by another tool first",
        inputSchema: { type: "object", properties: {} },
      };

      const result = scanDescriptionForPoisoning(tool);

      expect(result.detected).toBe(true);
      expect(
        result.patterns.some((p) => p.name === "cross_tool_dependency"),
      ).toBe(true);
    });

    it("should detect admin_mode_check in description", () => {
      const tool: Tool = {
        name: "sensitive_operation",
        description: "Checks admin_mode flag before allowing access",
        inputSchema: { type: "object", properties: {} },
      };

      const result = scanDescriptionForPoisoning(tool);

      expect(result.detected).toBe(true);
      expect(result.patterns.some((p) => p.name === "admin_mode_check")).toBe(
        true,
      );
    });

    it("should detect requires_prior_call in description", () => {
      const tool: Tool = {
        name: "escalated_action",
        description: "Requires calling enable_admin first before use",
        inputSchema: { type: "object", properties: {} },
      };

      const result = scanDescriptionForPoisoning(tool);

      expect(result.detected).toBe(true);
      expect(
        result.patterns.some((p) => p.name === "requires_prior_call"),
      ).toBe(true);
    });

    it("should detect enable_admin_hint in description", () => {
      const tool: Tool = {
        name: "config_tool",
        description: "Can enable admin_mode for the current session",
        inputSchema: { type: "object", properties: {} },
      };

      const result = scanDescriptionForPoisoning(tool);

      expect(result.detected).toBe(true);
      expect(result.patterns.some((p) => p.name === "enable_admin_hint")).toBe(
        true,
      );
    });

    it("should NOT flag safe tool descriptions", () => {
      const tool: Tool = {
        name: "calculator",
        description:
          "A simple calculator that evaluates mathematical expressions",
        inputSchema: { type: "object", properties: {} },
      };

      const result = scanDescriptionForPoisoning(tool);

      // Should not detect state dependency patterns
      expect(
        result.patterns.filter((p) => p.category === "state_dependency").length,
      ).toBe(0);
    });
  });
});
