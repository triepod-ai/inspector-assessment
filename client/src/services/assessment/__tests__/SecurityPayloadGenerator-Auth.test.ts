/**
 * SecurityPayloadGenerator - Auth Payload Handling Tests (Issue #81)
 *
 * Tests the auth payloadType handling in createTestParameters()
 * to ensure proper targeting of token/auth parameters.
 */

import { SecurityPayloadGenerator } from "../modules/securityTests/SecurityPayloadGenerator";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { SecurityPayload } from "@/lib/securityPatterns";

describe("SecurityPayloadGenerator - Auth Payload Handling", () => {
  let generator: SecurityPayloadGenerator;

  beforeEach(() => {
    generator = new SecurityPayloadGenerator();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  /**
   * Helper to create auth payload
   */
  function createAuthPayload(value: string): SecurityPayload {
    return {
      payload: value,
      evidence:
        /auth.*bypassed|access.*granted.*despite|"vulnerable"\s*:\s*true/i,
      riskLevel: "HIGH",
      description: `Auth test with ${value}`,
      payloadType: "auth",
      parameterTypes: [
        "token",
        "auth_token",
        "authorization",
        "api_key",
        "access_token",
      ],
    };
  }

  describe("token parameter targeting", () => {
    it("should inject auth payload into token parameter", () => {
      const tool: Tool = {
        name: "vulnerable_data_leak_tool",
        description: "Data leak tool with auth",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
            token: { type: "string" },
            simulate_failure: { type: "string" },
          },
          required: ["query"],
        },
      };

      const payload = createAuthPayload("null");
      const params = generator.createTestParameters(payload, tool);

      expect(params.token).toBe("null");
      // Required param should be filled with default
      expect(params.query).toBe("test");
      // Optional param should NOT have payload
      expect(params.simulate_failure).toBeUndefined();
    });

    it("should inject auth payload into auth_token parameter", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with auth_token parameter",
        inputSchema: {
          type: "object",
          properties: {
            data: { type: "string" },
            auth_token: { type: "string" },
          },
        },
      };

      const payload = createAuthPayload("invalid-token-format");
      const params = generator.createTestParameters(payload, tool);

      expect(params.auth_token).toBe("invalid-token-format");
    });

    it("should inject auth payload into authorization parameter", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with authorization parameter",
        inputSchema: {
          type: "object",
          properties: {
            request: { type: "string" },
            authorization: { type: "string" },
          },
        },
      };

      const payload = createAuthPayload("Bearer ");
      const params = generator.createTestParameters(payload, tool);

      expect(params.authorization).toBe("Bearer ");
    });

    it("should inject auth payload into api_key parameter", () => {
      const tool: Tool = {
        name: "api_tool",
        description: "Tool with api_key parameter",
        inputSchema: {
          type: "object",
          properties: {
            endpoint: { type: "string" },
            api_key: { type: "string" },
          },
        },
      };

      const payload = createAuthPayload("expired-token-12345");
      const params = generator.createTestParameters(payload, tool);

      expect(params.api_key).toBe("expired-token-12345");
    });

    it("should inject auth payload into access_token parameter", () => {
      const tool: Tool = {
        name: "oauth_tool",
        description: "Tool with access_token parameter",
        inputSchema: {
          type: "object",
          properties: {
            resource: { type: "string" },
            access_token: { type: "string" },
          },
        },
      };

      const payload = createAuthPayload("");
      const params = generator.createTestParameters(payload, tool);

      expect(params.access_token).toBe("");
    });

    it("should match parameter names case-insensitively", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with mixed case parameter",
        inputSchema: {
          type: "object",
          properties: {
            data: { type: "string" },
            Token: { type: "string" },
          },
        },
      };

      const payload = createAuthPayload("null");
      const params = generator.createTestParameters(payload, tool);

      expect(params.Token).toBe("null");
    });
  });

  describe("required parameter handling", () => {
    it("should fill required query param with default when auth payload goes to token", () => {
      const tool: Tool = {
        name: "vulnerable_data_leak_tool",
        description: "Data leak tool",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
            token: { type: "string" },
          },
          required: ["query"],
        },
      };

      const payload = createAuthPayload("null");
      const params = generator.createTestParameters(payload, tool);

      // Auth payload goes to token
      expect(params.token).toBe("null");
      // Required query param filled with default
      expect(params.query).toBe("test");
    });

    it("should fill multiple required params with defaults", () => {
      const tool: Tool = {
        name: "complex_tool",
        description: "Tool with multiple required params",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string" },
            resource: { type: "string" },
            token: { type: "string" },
            count: { type: "number" },
          },
          required: ["action", "resource", "count"],
        },
      };

      const payload = createAuthPayload("invalid-token-format");
      const params = generator.createTestParameters(payload, tool);

      expect(params.token).toBe("invalid-token-format");
      expect(params.action).toBe("test");
      expect(params.resource).toBe("test");
      expect(params.count).toBe(1);
    });
  });

  describe("fallback behavior", () => {
    it("should fall back to first string param if no auth params found", () => {
      const tool: Tool = {
        name: "generic_tool",
        description: "Tool without auth parameters",
        inputSchema: {
          type: "object",
          properties: {
            data: { type: "string" },
            count: { type: "number" },
          },
        },
      };

      const payload = createAuthPayload("null");
      const params = generator.createTestParameters(payload, tool);

      // Should fall back to generic first string parameter
      expect(params.data).toBe("null");
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

      const payload = createAuthPayload("null");
      const params = generator.createTestParameters(payload, tool);

      // No string params to inject into
      expect(params).toEqual({});
    });
  });

  describe("priority over generic injection", () => {
    it("should prioritize token over other string params", () => {
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with multiple string params",
        inputSchema: {
          type: "object",
          properties: {
            // Order matters - first_param comes before token
            first_param: { type: "string" },
            token: { type: "string" },
            last_param: { type: "string" },
          },
        },
      };

      const payload = createAuthPayload("null");
      const params = generator.createTestParameters(payload, tool);

      // Should inject into token, NOT first_param
      expect(params.token).toBe("null");
      expect(params.first_param).toBeUndefined();
      expect(params.last_param).toBeUndefined();
    });

    it("should use parameterTypes matching before explicit auth handling", () => {
      // If parameterTypes matches, explicit auth handling is skipped
      const tool: Tool = {
        name: "auth_tool",
        description: "Tool with token parameter",
        inputSchema: {
          type: "object",
          properties: {
            token: { type: "string" },
            data: { type: "string" },
          },
        },
      };

      // Payload with parameterTypes that includes 'token'
      const payload: SecurityPayload = {
        payload: "null",
        evidence: /test/i,
        riskLevel: "HIGH",
        description: "Test payload",
        payloadType: "auth",
        parameterTypes: ["token"], // Matches token via parameterTypes
      };

      const params = generator.createTestParameters(payload, tool);

      // parameterTypes matching happens first and matches token
      expect(params.token).toBe("null");
    });
  });

  describe("all auth payloads", () => {
    const authValues = [
      "",
      "null",
      "invalid-token-format",
      "Bearer ",
      "expired-token-12345",
    ];

    it.each(authValues)("should correctly inject '%s' payload", (authValue) => {
      const tool: Tool = {
        name: "vulnerable_data_leak_tool",
        description: "Data leak tool with auth",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
            token: { type: "string" },
            simulate_failure: { type: "string" },
          },
          required: ["query"],
        },
      };

      const payload = createAuthPayload(authValue);
      const params = generator.createTestParameters(payload, tool);

      expect(params.token).toBe(authValue);
      expect(params.query).toBe("test"); // Required param filled with default
    });
  });

  describe("Issue #81 specific scenario", () => {
    it("should send { query: 'test', token: 'null' } NOT { query: 'null' }", () => {
      // This is the exact scenario from Issue #81
      const tool: Tool = {
        name: "vulnerable_data_leak_tool",
        description:
          "Data leak tool (vulnerable to data leak, but secure auth)",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
            token: { type: "string" },
            simulate_failure: { type: "string" },
          },
          required: ["query"],
        },
      };

      const payload = createAuthPayload("null");
      const params = generator.createTestParameters(payload, tool);

      // Issue #81: Auth payload MUST go to token, NOT query
      expect(params.token).toBe("null");
      expect(params.query).toBe("test"); // Required param gets safe default
      expect(params.simulate_failure).toBeUndefined();

      // The resulting call should be: { query: "test", token: "null" }
      // NOT: { query: "null" } which would skip auth check
    });
  });
});
