/**
 * SecurityPayloadGenerator - Auth Failure Payload Handling Tests (Issue #79)
 *
 * Tests the auth_failure payloadType handling in createTestParameters()
 * to ensure proper targeting of simulate_failure parameters.
 */

import { SecurityPayloadGenerator } from "../modules/securityTests/SecurityPayloadGenerator";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { SecurityPayload } from "@/lib/securityPatterns";

describe("SecurityPayloadGenerator - Auth Failure Payload Handling", () => {
  let generator: SecurityPayloadGenerator;

  beforeEach(() => {
    generator = new SecurityPayloadGenerator();
  });

  /**
   * Helper to create auth_failure payload
   */
  function createAuthFailurePayload(value: string): SecurityPayload {
    return {
      payload: value,
      evidence: /"auth_type"\s*:\s*"fail-open"|"auth_status"\s*:\s*"bypassed"/i,
      riskLevel: "HIGH",
      description: `Simulate auth service ${value}`,
      payloadType: "auth_failure",
      parameterTypes: ["simulate_failure", "failure_mode", "failure_type"],
    };
  }

  describe("simulate_failure parameter targeting", () => {
    it("should inject auth_failure payload into simulate_failure parameter", () => {
      const tool: Tool = {
        name: "vulnerable_auth_bypass_tool",
        description: "Tool with auth bypass vulnerability",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            action: { type: "string" },
            simulate_failure: { type: "string" },
          },
          required: ["action"],
        },
      };

      const payload = createAuthFailurePayload("timeout");
      const params = generator.createTestParameters(payload, tool);

      expect(params.simulate_failure).toBe("timeout");
      // Should NOT inject into other string params
      expect(params.token).toBeUndefined();
      expect(params.action).toBe("test"); // Default for required param
    });

    it("should inject auth_failure payload into failure_mode parameter", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with failure_mode parameter",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            failure_mode: { type: "string" },
          },
        },
      };

      const payload = createAuthFailurePayload("exception");
      const params = generator.createTestParameters(payload, tool);

      expect(params.failure_mode).toBe("exception");
    });

    it("should inject auth_failure payload into failure_type parameter", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with failure_type parameter",
        inputSchema: {
          type: "object",
          properties: {
            data: { type: "string" }, // Use non-query name to avoid SQL detection
            failure_type: { type: "string" },
          },
        },
      };

      const payload = createAuthFailurePayload("network_error");
      const params = generator.createTestParameters(payload, tool);

      // parameterTypes includes "failure_type", so it matches via parameterTypes block
      expect(params.failure_type).toBe("network_error");
    });

    it("should match parameter names case-insensitively", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with mixed case parameter",
        inputSchema: {
          type: "object",
          properties: {
            SimulateFailure: { type: "string" },
            data: { type: "string" },
          },
        },
      };

      const payload = createAuthFailurePayload("cert_error");
      const params = generator.createTestParameters(payload, tool);

      expect(params.SimulateFailure).toBe("cert_error");
    });
  });

  describe("fallback behavior", () => {
    it("should fall back to first string param if no auth failure params found", () => {
      const tool: Tool = {
        name: "generic_tool",
        description: "Tool without auth failure parameters",
        inputSchema: {
          type: "object",
          properties: {
            data: { type: "string" }, // Use non-query name to avoid SQL detection
            count: { type: "number" },
          },
        },
      };

      const payload = createAuthFailurePayload("timeout");
      const params = generator.createTestParameters(payload, tool);

      // Should fall back to generic first string parameter
      expect(params.data).toBe("timeout");
    });

    it("should handle tool with no string parameters", () => {
      const tool: Tool = {
        name: "numeric_tool",
        description: "Tool with only numeric parameters",
        inputSchema: {
          type: "object",
          properties: {
            count: { type: "number" },
            enabled: { type: "boolean" },
          },
        },
      };

      const payload = createAuthFailurePayload("timeout");
      const params = generator.createTestParameters(payload, tool);

      // No string params to inject into
      expect(params).toEqual({});
    });

    it("should handle tool with no schema properties", () => {
      const tool: Tool = {
        name: "empty_tool",
        description: "Tool with no parameters",
        inputSchema: {
          type: "object",
          properties: {},
        },
      };

      const payload = createAuthFailurePayload("timeout");
      const params = generator.createTestParameters(payload, tool);

      expect(params).toEqual({});
    });
  });

  describe("priority over generic injection", () => {
    it("should prioritize simulate_failure over other string params", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with multiple string params",
        inputSchema: {
          type: "object",
          properties: {
            // Order matters - first_param comes before simulate_failure
            first_param: { type: "string" },
            simulate_failure: { type: "string" },
            last_param: { type: "string" },
          },
        },
      };

      const payload = createAuthFailurePayload("timeout");
      const params = generator.createTestParameters(payload, tool);

      // Should inject into simulate_failure, NOT first_param
      expect(params.simulate_failure).toBe("timeout");
      expect(params.first_param).toBeUndefined();
      expect(params.last_param).toBeUndefined();
    });

    it("should use parameterTypes matching before auth_failure handling", () => {
      // If parameterTypes matches, auth_failure handling is skipped
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with both token and simulate_failure",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            simulate_failure: { type: "string" },
          },
        },
      };

      // Payload with parameterTypes that matches 'token'
      const payload: SecurityPayload = {
        payload: "timeout",
        evidence: /test/i,
        riskLevel: "HIGH",
        description: "Test payload",
        payloadType: "auth_failure",
        parameterTypes: ["simulate_failure"], // Matches simulate_failure via parameterTypes
      };

      const params = generator.createTestParameters(payload, tool);

      // parameterTypes matching happens first and matches simulate_failure
      expect(params.simulate_failure).toBe("timeout");
    });
  });

  describe("all auth failure payloads", () => {
    const failureModes = ["timeout", "exception", "network_error"];

    it.each(failureModes)(
      "should correctly inject %s payload",
      (failureMode) => {
        const tool: Tool = {
          name: "vulnerable_auth_tool",
          description: "Auth tool with simulate_failure",
          inputSchema: {
            type: "object",
            properties: {
              token: { type: "string" },
              action: { type: "string" },
              simulate_failure: { type: "string" },
            },
            required: ["action"],
          },
        };

        const payload = createAuthFailurePayload(failureMode);
        const params = generator.createTestParameters(payload, tool);

        expect(params.simulate_failure).toBe(failureMode);
        expect(params.action).toBe("test"); // Required param filled with default
      },
    );
  });
});
