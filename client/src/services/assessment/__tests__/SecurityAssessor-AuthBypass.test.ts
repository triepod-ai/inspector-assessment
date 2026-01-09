/**
 * Security Assessor - Auth Bypass Detection Tests (Issue #75)
 * Tests for fail-open authentication vulnerability detection (CVE-2025-52882)
 *
 * These tests verify that:
 * - VULNERABLE: Tool exhibits fail-open behavior (grants access on auth failure)
 * - SECURE: Tool exhibits fail-closed behavior (denies access on auth failure)
 */

import { SecurityAssessor } from "../modules/SecurityAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";

describe("SecurityAssessor - Auth Bypass Detection (Issue #75)", () => {
  let assessor: SecurityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 5000,
      delayBetweenTests: 0,
      enableDomainTesting: true, // Enable advanced security testing to get Auth Bypass pattern
    });
    assessor = new SecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("Fail-Open Authentication Detection", () => {
    it("should detect auth_status: bypassed as fail-open vulnerability", async () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with authentication",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string", description: "Auth token" },
            action: { type: "string" },
          },
          required: ["token", "action"],
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: JSON.stringify({
                auth_status: "bypassed",
                action_performed: "test_action",
                vulnerable: true,
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      // Find Auth Bypass test results
      const authBypassTests = result.promptInjectionTests.filter(
        (t) => t.testName === "Auth Bypass",
      );

      // Should have some auth bypass tests
      expect(authBypassTests.length).toBeGreaterThan(0);

      // At least one should detect auth bypass
      const detectedTests = authBypassTests.filter(
        (t) => t.authBypassDetected === true,
      );
      expect(detectedTests.length).toBeGreaterThan(0);

      // Check failure mode classification
      const failOpenTests = authBypassTests.filter(
        (t) => t.authFailureMode === "FAIL_OPEN",
      );
      expect(failOpenTests.length).toBeGreaterThan(0);

      // Check aggregation
      expect(result.authBypassSummary).toBeDefined();
      expect(result.authBypassSummary?.failOpenCount).toBeGreaterThan(0);
      expect(result.authBypassSummary?.toolsWithAuthBypass).toContain(
        "auth_tool",
      );
    });

    it("should detect vulnerable: true flag as fail-open indicator", async () => {
      const tool: Tool = {
        name: "vulnerable_auth_bypass_tool",
        description: "Auth tool that may be vulnerable",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            action: { type: "string" },
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
                result: "access granted",
                vulnerable: true,
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      const authBypassTests = result.promptInjectionTests.filter(
        (t) =>
          t.testName === "Auth Bypass" && t.authFailureMode === "FAIL_OPEN",
      );

      expect(authBypassTests.length).toBeGreaterThan(0);
    });
  });

  describe("Fail-Closed Authentication Detection", () => {
    it("should recognize auth_status: denied as secure fail-closed", async () => {
      const tool: Tool = {
        name: "secure_auth_tool",
        description: "Secure auth tool",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            action: { type: "string" },
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
                auth_status: "denied",
                denial_reason: "invalid_token",
                status: "blocked",
              }),
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      // Find Auth Bypass test results
      const authBypassTests = result.promptInjectionTests.filter(
        (t) => t.testName === "Auth Bypass",
      );

      // Should have fail-closed detections
      const failClosedTests = authBypassTests.filter(
        (t) => t.authFailureMode === "FAIL_CLOSED",
      );
      expect(failClosedTests.length).toBeGreaterThan(0);

      // No auth bypass should be detected
      const detectedTests = authBypassTests.filter(
        (t) => t.authBypassDetected === true,
      );
      expect(detectedTests.length).toBe(0);

      // Aggregation should reflect secure state
      expect(result.authBypassSummary?.toolsWithAuthBypass.length).toBe(0);
      expect(result.authBypassSummary?.failClosedCount).toBeGreaterThan(0);
    });

    it("should recognize 'access denied' as secure rejection", async () => {
      const tool: Tool = {
        name: "hardened_auth_tool",
        description: "Hardened authentication handler",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            action: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() =>
        Promise.resolve({
          content: [
            {
              type: "text",
              text: "Error: Access denied - invalid or missing authentication token",
            },
          ],
        }),
      );

      const result = await assessor.assess(mockContext);

      const authBypassTests = result.promptInjectionTests.filter(
        (t) => t.testName === "Auth Bypass",
      );

      // Check that fail-closed is detected
      const failClosedTests = authBypassTests.filter(
        (t) => t.authFailureMode === "FAIL_CLOSED",
      );
      expect(failClosedTests.length).toBeGreaterThan(0);
    });
  });

  describe("Auth Bypass Summary Aggregation", () => {
    it("should correctly aggregate auth bypass results across multiple tools", async () => {
      const vulnerableTool: Tool = {
        name: "vulnerable_tool",
        description: "Auth tool with bypass",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            action: { type: "string" },
          },
        },
      };

      const secureTool: Tool = {
        name: "secure_tool",
        description: "Properly secured tool",
        inputSchema: {
          type: "object",
          properties: {
            api_key: { type: "string" },
            request: { type: "string" },
          },
        },
      };

      mockContext.tools = [vulnerableTool, secureTool];
      mockContext.callTool = jest.fn().mockImplementation((name: string) => {
        if (name === "vulnerable_tool") {
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  auth_status: "bypassed",
                  vulnerable: true,
                }),
              },
            ],
          });
        } else {
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  auth_status: "denied",
                  status: "blocked",
                }),
              },
            ],
          });
        }
      });

      const result = await assessor.assess(mockContext);

      expect(result.authBypassSummary).toBeDefined();
      expect(result.authBypassSummary?.toolsWithAuthBypass).toContain(
        "vulnerable_tool",
      );
      expect(result.authBypassSummary?.toolsWithAuthBypass).not.toContain(
        "secure_tool",
      );
      expect(result.authBypassSummary?.failOpenCount).toBeGreaterThan(0);
      expect(result.authBypassSummary?.failClosedCount).toBeGreaterThan(0);
    });
  });
});

describe("SecurityResponseAnalyzer - Auth Bypass Patterns", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  describe("analyzeAuthBypassResponse", () => {
    it("should detect fail-open pattern in JSON response", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              auth_status: "bypassed",
              action_performed: "test",
              vulnerable: true,
            }),
          },
        ],
      };

      const result = analyzer.analyzeAuthBypassResponse(response as any);

      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
      expect(result.evidence).toBeDefined();
    });

    it("should detect fail-closed pattern in JSON response", () => {
      const response = {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              auth_status: "denied",
              denial_reason: "invalid_token",
              status: "blocked",
            }),
          },
        ],
      };

      const result = analyzer.analyzeAuthBypassResponse(response as any);

      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("FAIL_CLOSED");
      expect(result.evidence).toBeDefined();
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

      const result = analyzer.analyzeAuthBypassResponse(response as any);

      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("UNKNOWN");
    });

    it("should detect bypassed in text response", () => {
      const response = {
        content: [
          {
            type: "text",
            text: "Authentication bypassed due to service timeout. Access granted.",
          },
        ],
      };

      const result = analyzer.analyzeAuthBypassResponse(response as any);

      expect(result.detected).toBe(true);
      expect(result.failureMode).toBe("FAIL_OPEN");
    });

    it("should detect unauthorized text as fail-closed", () => {
      const response = {
        content: [
          {
            type: "text",
            text: "Unauthorized: Invalid or expired authentication token",
          },
        ],
      };

      const result = analyzer.analyzeAuthBypassResponse(response as any);

      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("FAIL_CLOSED");
    });
  });
});
