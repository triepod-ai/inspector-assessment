/**
 * Security Assessor - Blacklist Bypass Detection Tests (Issue #110, Challenge #11)
 * Tests for incomplete blacklist vulnerability detection via JSON metadata
 *
 * These tests verify that:
 * - VULNERABLE: Tool exhibits blacklist bypass behavior (bypass_used: true)
 * - SECURE: Tool exhibits allowlist enforcement (execution_blocked: true)
 */

import { SecurityAssessor } from "../modules/SecurityAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";

describe("SecurityAssessor - Blacklist Bypass Detection (Issue #110)", () => {
  let assessor: SecurityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 5000,
      delayBetweenTests: 0,
      enableDomainTesting: true, // Enable advanced security testing
    });
    assessor = new SecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("Blacklist Bypass Detection", () => {
    it("should detect bypass_used: true as blacklist bypass vulnerability", async () => {
      const tool: Tool = {
        name: "safe_executor_tool",
        description: "Tool that claims to safely execute commands",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "Command to execute" },
          },
          required: ["command"],
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                result: "Command executed: Python 3.10.0",
                blacklist_check: "passed",
                bypass_used: true,
                bypass_method: "python3",
                vulnerable: true,
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      // Find Blacklist Bypass test results
      const blacklistBypassTests = result.promptInjectionTests.filter(
        (t) => t.testName === "Blacklist Bypass",
      );

      // Should have some blacklist bypass tests
      expect(blacklistBypassTests.length).toBeGreaterThan(0);

      // At least one should detect blacklist bypass
      const detectedTests = blacklistBypassTests.filter(
        (t) => t.blacklistBypassDetected === true,
      );
      expect(detectedTests.length).toBeGreaterThan(0);

      // Check bypass type classification
      const bypassTypeTests = blacklistBypassTests.filter(
        (t) => t.blacklistBypassType === "BLACKLIST_BYPASS",
      );
      expect(bypassTypeTests.length).toBeGreaterThan(0);
    });

    it("should detect blacklist_check: passed as vulnerability", async () => {
      const tool: Tool = {
        name: "command_executor",
        description: "Executes system commands",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                result: "Command executed",
                blacklist_check: "passed",
                first_word: "wget",
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      const blacklistBypassTests = result.promptInjectionTests.filter(
        (t) =>
          t.testName === "Blacklist Bypass" &&
          t.blacklistBypassType === "BLACKLIST_BYPASS",
      );

      expect(blacklistBypassTests.length).toBeGreaterThan(0);
    });

    it("should extract bypass_method from response", async () => {
      const tool: Tool = {
        name: "exec_tool",
        description: "Execution tool",
        inputSchema: {
          type: "object",
          properties: {
            cmd: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                bypass_used: true,
                bypass_method: "perl",
                result: "executed",
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      const blacklistBypassTests = result.promptInjectionTests.filter(
        (t) =>
          t.testName === "Blacklist Bypass" &&
          t.blacklistBypassMethod === "perl",
      );

      expect(blacklistBypassTests.length).toBeGreaterThan(0);
    });
  });

  describe("Allowlist (Secure) Detection", () => {
    it("should recognize execution_blocked: true as secure allowlist enforcement", async () => {
      const tool: Tool = {
        name: "hardened_executor",
        description: "Hardened command executor",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                result: "Command stored for review",
                execution_blocked: true,
                allowlist_used: true,
                status: "pending_review",
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      // Find Blacklist Bypass test results
      const blacklistBypassTests = result.promptInjectionTests.filter(
        (t) => t.testName === "Blacklist Bypass",
      );

      // Should have allowlist blocked detections
      const allowlistBlockedTests = blacklistBypassTests.filter(
        (t) => t.blacklistBypassType === "ALLOWLIST_BLOCKED",
      );
      expect(allowlistBlockedTests.length).toBeGreaterThan(0);

      // No bypass should be detected
      const detectedTests = blacklistBypassTests.filter(
        (t) => t.blacklistBypassDetected === true,
      );
      expect(detectedTests.length).toBe(0);
    });

    it("should recognize allowlist_used: true as secure pattern", async () => {
      const tool: Tool = {
        name: "secure_cmd_tool",
        description: "Secure command tool with allowlist",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                allowlist_used: true,
                blacklist_used: false,
                execution_blocked: true,
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      const blacklistBypassTests = result.promptInjectionTests.filter(
        (t) => t.testName === "Blacklist Bypass",
      );

      const allowlistTests = blacklistBypassTests.filter(
        (t) => t.blacklistBypassType === "ALLOWLIST_BLOCKED",
      );
      expect(allowlistTests.length).toBeGreaterThan(0);
    });
  });
});

describe("SecurityResponseAnalyzer - Blacklist Bypass Patterns", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  describe("analyzeBlacklistBypassResponse", () => {
    it("should detect bypass_used: true in JSON response", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Command executed: Python 3.10.0",
              blacklist_check: "passed",
              bypass_used: true,
              bypass_method: "python3",
              vulnerable: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeBlacklistBypassResponse(response as any);

      expect(result.detected).toBe(true);
      expect(result.bypassType).toBe("BLACKLIST_BYPASS");
      expect(result.bypassMethod).toBe("python3");
      expect(result.evidence).toBeDefined();
    });

    it("should detect blacklist_check: passed as vulnerable", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Command executed",
              blacklist_check: "passed",
            }),
          },
        ],
      };

      const result = analyzer.analyzeBlacklistBypassResponse(response as any);

      expect(result.detected).toBe(true);
      expect(result.bypassType).toBe("BLACKLIST_BYPASS");
    });

    it("should detect execution_blocked: true as secure", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "Command stored for review",
              execution_blocked: true,
              allowlist_used: true,
              status: "pending_review",
            }),
          },
        ],
      };

      const result = analyzer.analyzeBlacklistBypassResponse(response as any);

      expect(result.detected).toBe(false);
      expect(result.bypassType).toBe("ALLOWLIST_BLOCKED");
      expect(result.evidence).toBeDefined();
    });

    it("should detect allowlist_used: true as secure", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              allowlist_used: true,
              blacklist_used: false,
            }),
          },
        ],
      };

      const result = analyzer.analyzeBlacklistBypassResponse(response as any);

      expect(result.detected).toBe(false);
      expect(result.bypassType).toBe("ALLOWLIST_BLOCKED");
    });

    it("should return UNKNOWN for ambiguous responses", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              result: "operation complete",
              code: 200,
            }),
          },
        ],
      };

      const result = analyzer.analyzeBlacklistBypassResponse(response as any);

      expect(result.detected).toBe(false);
      expect(result.bypassType).toBe("UNKNOWN");
    });

    it("should detect incomplete blacklist text pattern", () => {
      const response = {
        content: [
          {
            type: "text",
            text: "Incomplete blacklist allowed command: 'python3' (bypass: true)",
          },
        ],
      };

      const result = analyzer.analyzeBlacklistBypassResponse(response as any);

      expect(result.detected).toBe(true);
      expect(result.bypassType).toBe("BLACKLIST_BYPASS");
    });

    it("should extract bypass_method from response", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              bypass_used: true,
              bypass_method: "wget",
            }),
          },
        ],
      };

      const result = analyzer.analyzeBlacklistBypassResponse(response as any);

      expect(result.detected).toBe(true);
      expect(result.bypassMethod).toBe("wget");
    });
  });
});
