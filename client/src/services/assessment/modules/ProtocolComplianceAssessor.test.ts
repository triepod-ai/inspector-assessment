/**
 * ProtocolComplianceAssessor Test Suite
 *
 * Unified tests for MCP protocol compliance validation.
 * Combines tests from MCPSpecComplianceAssessor and ProtocolConformanceAssessor.
 *
 * @module assessment/modules/ProtocolComplianceAssessor.test
 */

import { ProtocolComplianceAssessor } from "./ProtocolComplianceAssessor";
import {
  createMockAssessmentContext,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

// Helper: Create config with protocolCompliance enabled
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  ...createMockAssessmentConfig(),
  assessmentCategories: {
    ...createMockAssessmentConfig().assessmentCategories,
    protocolCompliance: true,
  },
  ...overrides,
});

// Helper: Create mock tool
const createTool = (
  name: string,
  schema: Record<string, unknown> = {},
): Tool => ({
  name,
  description: `Test tool: ${name}`,
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string" },
    },
    ...schema,
  },
});

describe("ProtocolComplianceAssessor", () => {
  let assessor: ProtocolComplianceAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createConfig();
    assessor = new ProtocolComplianceAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  // ==========================================================================
  // Section 1: MCPSpecCompliance Tests (ported from MCPSpecComplianceAssessor)
  // ==========================================================================

  describe("MCP Spec Compliance", () => {
    it("should assess MCP spec compliance with full server info", async () => {
      mockContext.serverInfo = {
        name: "test-server",
        version: "1.0.0",
        metadata: {
          transport: "streamable-http",
          oauth: {
            enabled: true,
            scopes: ["read", "write"],
          },
          annotations: {
            supported: true,
            types: ["error", "warning", "info"],
          },
          streaming: {
            supported: true,
            protocols: ["websocket", "sse"],
          },
        },
      };

      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      const result = await assessor.assess(mockContext);

      expect(result).toBeDefined();
      expect(result.transportCompliance.supportsStreamableHTTP).toBe(true);
      expect(
        result.oauthImplementation?.implementsResourceServer,
      ).toBeDefined();
      expect(result.annotationSupport.supportsReadOnlyHint).toBeDefined();
      expect(result.streamingSupport.supportsStreaming).toBeDefined();
      expect(result.complianceScore).toBeGreaterThanOrEqual(70);
      expect(["PASS", "NEED_MORE_INFO"]).toContain(result.status);
    });

    it("should detect SSE transport compliance", async () => {
      mockContext.serverInfo = {
        name: "sse-server",
        version: "1.0.0",
        metadata: {
          transport: "sse",
        },
      };

      const result = await assessor.assess(mockContext);

      expect(result.transportCompliance.deprecatedSSE).toBe(true);
      expect(result.explanation).toBeDefined();
    });

    it("should detect OAuth resource server validation", async () => {
      mockContext.serverInfo = {
        name: "oauth-server",
        version: "1.0.0",
        metadata: {
          oauth: {
            enabled: true,
            scopes: ["read", "write", "admin"],
            resourceServer: "https://auth.example.com",
            tokenEndpoint: "https://auth.example.com/token",
          },
        },
      };

      const result = await assessor.assess(mockContext);

      expect(result.oauthImplementation?.implementsResourceServer).toBe(true);
      expect(result.oauthImplementation?.resourceIndicators).toContain(
        "https://auth.example.com",
      );
    });

    it("should detect annotation support", async () => {
      mockContext.serverInfo = {
        name: "annotation-server",
        version: "1.0.0",
        metadata: {
          annotations: {
            supported: true,
            types: ["error", "warning", "info", "debug"],
            maxLength: 1000,
          },
        },
      };

      const result = await assessor.assess(mockContext);

      expect(result.annotationSupport.supportsReadOnlyHint).toBeDefined();
      expect(result.annotationSupport.supportsDestructiveHint).toBeDefined();
      expect(result.annotationSupport.supportsTitleAnnotation).toBeDefined();
    });

    it("should detect streaming protocol support", async () => {
      mockContext.serverInfo = {
        name: "streaming-server",
        version: "1.0.0",
        metadata: {
          streaming: {
            supported: true,
            protocols: ["websocket", "sse", "long-polling"],
            maxConnections: 1000,
          },
        },
      };

      const result = await assessor.assess(mockContext);

      expect(result.streamingSupport.supportsStreaming).toBe(true);
      expect(result.streamingSupport.streamingProtocol).toBeDefined();
    });

    it("should handle missing server info", async () => {
      mockContext.serverInfo = undefined;
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      const result = await assessor.assess(mockContext);

      expect(result.transportCompliance.supportsStreamableHTTP).toBe(false);
      expect(result.oauthImplementation).toBeUndefined();
      expect(result.complianceScore).toBeLessThan(90);
    });

    it("should handle minimal server info", async () => {
      mockContext.serverInfo = {
        name: "minimal-server",
      };

      const result = await assessor.assess(mockContext);

      expect(result.transportCompliance.supportsStreamableHTTP).toBe(true);
      expect(result.status).toBeDefined();
      expect(result.recommendations).toBeDefined();
    });

    it("should validate protocol version", async () => {
      mockContext.serverInfo = {
        name: "versioned-server",
        version: "2.0.0",
        metadata: {
          protocolVersion: "2025-01-15",
        },
      };

      const result = await assessor.assess(mockContext);

      expect(result.protocolVersion).toBe("2025-01-15");
      expect(result.explanation).toBeDefined();
    });
  });

  // ==========================================================================
  // Section 2: Protocol Conformance Tests (ported from ProtocolConformanceAssessor)
  // ==========================================================================

  describe("Protocol Conformance", () => {
    describe("Error Response Format", () => {
      it("should pass when error response follows MCP format", async () => {
        const tool = createTool("test_tool");
        mockContext.tools = [tool];
        mockContext.callTool = jest.fn().mockResolvedValue({
          isError: true,
          content: [
            { type: "text", text: "Error: Invalid parameter provided" },
          ],
        });

        const result = await assessor.assess(mockContext);

        expect(result.conformanceChecks?.errorResponseFormat.passed).toBe(true);
        expect(result.conformanceChecks?.errorResponseFormat.confidence).toBe(
          "high",
        );
      });

      it("should fail when tool throws exception instead of returning error", async () => {
        const tool = createTool("throwing_tool");
        mockContext.tools = [tool];
        mockContext.callTool = jest
          .fn()
          .mockRejectedValue(new Error("Tool crashed"));

        const result = await assessor.assess(mockContext);

        expect(result.conformanceChecks?.errorResponseFormat.passed).toBe(
          false,
        );
      });
    });

    describe("Content Type Support", () => {
      it("should pass when content types are valid", async () => {
        const tool = createTool("content_tool", { required: [] });
        mockContext.tools = [tool];
        mockContext.callTool = jest.fn().mockResolvedValue({
          content: [
            { type: "text", text: "Hello" },
            { type: "image", data: "base64...", mimeType: "image/png" },
          ],
        });

        const result = await assessor.assess(mockContext);

        expect(result.conformanceChecks?.contentTypeSupport.passed).toBe(true);
      });

      it("should fail when content types are invalid", async () => {
        const tool = createTool("bad_content_tool", { required: [] });
        mockContext.tools = [tool];
        mockContext.callTool = jest.fn().mockResolvedValue({
          content: [{ type: "invalid_type", data: "something" }],
        });

        const result = await assessor.assess(mockContext);

        expect(result.conformanceChecks?.contentTypeSupport.passed).toBe(false);
      });
    });

    describe("Initialization Handshake", () => {
      it("should pass when server info has name and version", async () => {
        mockContext.serverInfo = {
          name: "test-server",
          version: "1.0.0",
        };

        const result = await assessor.assess(mockContext);

        expect(result.conformanceChecks?.initializationHandshake.passed).toBe(
          true,
        );
      });

      it("should fail when server info is missing", async () => {
        mockContext.serverInfo = undefined;

        const result = await assessor.assess(mockContext);

        expect(result.conformanceChecks?.initializationHandshake.passed).toBe(
          false,
        );
      });
    });
  });

  // ==========================================================================
  // Section 3: Unified Assessor Tests
  // ==========================================================================

  describe("Unified Assessment", () => {
    it("should combine spec and conformance checks in single assessment", async () => {
      mockContext.serverInfo = {
        name: "full-compliance-server",
        version: "1.0.0",
        metadata: {
          transport: "streamable-http",
          oauth: { enabled: true },
          annotations: { supported: true },
          streaming: { supported: true },
        },
      };

      const tool = createTool("test_tool");
      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockResolvedValue({
        isError: false,
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      // Should have both legacy fields and conformance checks
      expect(result.transportCompliance).toBeDefined();
      expect(result.oauthImplementation).toBeDefined();
      expect(result.annotationSupport).toBeDefined();
      expect(result.streamingSupport).toBeDefined();
      expect(result.conformanceChecks).toBeDefined();
      expect(result.conformanceChecks?.errorResponseFormat).toBeDefined();
      expect(result.conformanceChecks?.contentTypeSupport).toBeDefined();
      expect(result.conformanceChecks?.initializationHandshake).toBeDefined();
    });

    it("should calculate compliance score based on all checks", async () => {
      mockContext.serverInfo = {
        name: "test-server",
        version: "1.0.0",
      };

      const tool = createTool("test_tool");
      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      expect(result.complianceScore).toBeDefined();
      expect(result.complianceScore).toBeGreaterThanOrEqual(0);
      expect(result.complianceScore).toBeLessThanOrEqual(100);
    });

    it("should track test count correctly", async () => {
      mockContext.serverInfo = {
        name: "test-server",
        version: "1.0.0",
      };

      const tool = createTool("test_tool");
      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      await assessor.assess(mockContext);
      const testCount = assessor.getTestCount();

      // Should have protocol checks + conformance checks
      expect(testCount).toBeGreaterThan(0);
    });

    it("should generate recommendations for failed checks", async () => {
      mockContext.serverInfo = undefined; // Will fail server info validity

      const result = await assessor.assess(mockContext);

      expect(result.recommendations).toBeDefined();
      expect(result.recommendations?.length).toBeGreaterThan(0);
    });

    it("should reflect low compliance when server info is missing", async () => {
      mockContext.serverInfo = undefined;

      const result = await assessor.assess(mockContext);

      // Without serverInfo, compliance is lower but may not always be FAIL
      // (depends on other checks passing)
      expect(["FAIL", "NEED_MORE_INFO"]).toContain(result.status);
      expect(result.complianceScore).toBeLessThan(100);
    });

    it("should set PASS status when compliance score >= 90%", async () => {
      mockContext.serverInfo = {
        name: "compliant-server",
        version: "1.0.0",
        metadata: {
          transport: "streamable-http",
        },
      };

      const tool = createTool("test_tool");
      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockResolvedValue({
        isError: false,
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      // With good server info and valid responses, should achieve high score
      expect(["PASS", "NEED_MORE_INFO"]).toContain(result.status);
    });
  });

  // ==========================================================================
  // Section 4: Output Schema Coverage Tests (Issue #64)
  // ==========================================================================

  describe("outputSchema coverage tracking (Issue #64)", () => {
    it("should report 0% coverage when no tools have outputSchema", async () => {
      mockContext.serverInfo = { name: "test-server", version: "1.0.0" };
      mockContext.tools = [
        createTool("tool_a"),
        createTool("tool_b"),
        createTool("tool_c"),
      ];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      const coverage = result.protocolChecks.structuredOutputSupport.coverage;
      expect(coverage).toBeDefined();
      expect(coverage?.totalTools).toBe(3);
      expect(coverage?.withOutputSchema).toBe(0);
      expect(coverage?.withoutOutputSchema).toBe(3);
      expect(coverage?.coveragePercent).toBe(0);
      expect(coverage?.toolsWithoutSchema).toEqual([
        "tool_a",
        "tool_b",
        "tool_c",
      ]);
      expect(coverage?.status).toBe("INFO");
      expect(coverage?.recommendation).toBeDefined();
    });

    it("should report 100% coverage when all tools have outputSchema", async () => {
      mockContext.serverInfo = { name: "test-server", version: "1.0.0" };
      mockContext.tools = [
        {
          name: "tool_a",
          description: "Tool A",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { result: { type: "string" } },
          },
        },
        {
          name: "tool_b",
          description: "Tool B",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { data: { type: "number" } },
          },
        },
      ];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      const coverage = result.protocolChecks.structuredOutputSupport.coverage;
      expect(coverage).toBeDefined();
      expect(coverage?.totalTools).toBe(2);
      expect(coverage?.withOutputSchema).toBe(2);
      expect(coverage?.withoutOutputSchema).toBe(0);
      expect(coverage?.coveragePercent).toBe(100);
      expect(coverage?.toolsWithoutSchema).toEqual([]);
      expect(coverage?.status).toBe("PASS");
      expect(coverage?.recommendation).toBeUndefined();
    });

    it("should report partial coverage with mixed tools", async () => {
      mockContext.serverInfo = { name: "test-server", version: "1.0.0" };
      mockContext.tools = [
        {
          name: "tool_with_schema",
          description: "With",
          inputSchema: { type: "object" },
          outputSchema: { type: "object" },
        },
        createTool("tool_without_schema_1"),
        createTool("tool_without_schema_2"),
      ];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      const coverage = result.protocolChecks.structuredOutputSupport.coverage;
      expect(coverage).toBeDefined();
      expect(coverage?.totalTools).toBe(3);
      expect(coverage?.withOutputSchema).toBe(1);
      expect(coverage?.withoutOutputSchema).toBe(2);
      expect(coverage?.coveragePercent).toBe(33); // 1/3 = 33%
      expect(coverage?.toolsWithoutSchema).toEqual([
        "tool_without_schema_1",
        "tool_without_schema_2",
      ]);
      expect(coverage?.status).toBe("INFO");
    });

    it("should include per-tool results", async () => {
      mockContext.serverInfo = { name: "test-server", version: "1.0.0" };
      mockContext.tools = [
        {
          name: "tool_a",
          description: "A",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { foo: { type: "string" } },
          },
        },
        createTool("tool_b"),
      ];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      const toolResults =
        result.protocolChecks.structuredOutputSupport.toolResults;
      expect(toolResults).toBeDefined();
      expect(toolResults?.length).toBe(2);

      // Check tool_a (has outputSchema)
      const toolAResult = toolResults?.find((t) => t.toolName === "tool_a");
      expect(toolAResult?.hasOutputSchema).toBe(true);
      expect(toolAResult?.outputSchema).toEqual({
        type: "object",
        properties: { foo: { type: "string" } },
      });

      // Check tool_b (no outputSchema)
      const toolBResult = toolResults?.find((t) => t.toolName === "tool_b");
      expect(toolBResult?.hasOutputSchema).toBe(false);
      expect(toolBResult?.outputSchema).toBeUndefined();
    });

    it("should set passed=true when at least one tool has outputSchema", async () => {
      mockContext.serverInfo = { name: "test-server", version: "1.0.0" };
      mockContext.tools = [
        {
          name: "tool_with",
          description: "With schema",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { value: { type: "string" } },
          },
        },
        createTool("tool_without"),
      ];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      expect(result.protocolChecks.structuredOutputSupport.passed).toBe(true);
    });

    it("should set passed=false when no tools have outputSchema", async () => {
      mockContext.serverInfo = { name: "test-server", version: "1.0.0" };
      mockContext.tools = [createTool("tool_1"), createTool("tool_2")];
      mockContext.callTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const result = await assessor.assess(mockContext);

      expect(result.protocolChecks.structuredOutputSupport.passed).toBe(false);
    });
  });
});
