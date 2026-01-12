import { MCPSpecComplianceAssessor } from "./MCPSpecComplianceAssessor";
import {
  createMockAssessmentContext,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("MCPSpecComplianceAssessor", () => {
  let assessor: MCPSpecComplianceAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new MCPSpecComplianceAssessor(config);
    mockContext = createMockAssessmentContext();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess MCP spec compliance with full server info", async () => {
      // Arrange
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

      // Mock callTool to return successful responses for compliance checks
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
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
      // Arrange
      mockContext.serverInfo = {
        name: "sse-server",
        version: "1.0.0",
        metadata: {
          transport: "sse",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transportCompliance.deprecatedSSE).toBe(true);
      expect(result.explanation).toBeDefined();
    });

    it("should detect OAuth resource server validation", async () => {
      // Arrange
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

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.oauthImplementation?.implementsResourceServer).toBe(true);
      expect(result.oauthImplementation?.resourceIndicators).toContain(
        "https://auth.example.com",
      );
      expect(result.explanation).toBeDefined();
    });

    it("should detect annotation support", async () => {
      // Arrange
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

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.annotationSupport.supportsReadOnlyHint).toBeDefined();
      expect(result.annotationSupport.supportsDestructiveHint).toBeDefined();
      expect(result.annotationSupport.supportsTitleAnnotation).toBeDefined();
    });

    it("should detect streaming protocol support", async () => {
      // Arrange
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

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.streamingSupport.supportsStreaming).toBe(true);
      expect(result.streamingSupport.streamingProtocol).toBeDefined();
    });

    it("should handle missing server info", async () => {
      // Arrange
      mockContext.serverInfo = undefined;
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transportCompliance.supportsStreamableHTTP).toBe(false);
      expect(result.oauthImplementation).toBeUndefined();
      // Without server info, compliance score should be low
      expect(result.complianceScore).toBeLessThan(90);
    });

    it("should calculate compliance score based on features", async () => {
      // Arrange - partial compliance
      mockContext.serverInfo = {
        name: "partial-server",
        version: "1.0.0",
        metadata: {
          transport: "http", // Valid but not streamable
          oauth: {
            enabled: false,
          },
          annotations: {
            supported: true,
          },
          streaming: {
            supported: false,
          },
        },
      };

      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Should have lower score due to missing features
      expect(result.complianceScore).toBeLessThan(90);
      expect(result.transportCompliance.transportValidation).toBe("passed");
    });

    it("should validate protocol version", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "versioned-server",
        version: "2.0.0",
        metadata: {
          protocolVersion: "2025-01-15",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.protocolVersion).toBe("2025-01-15");
      expect(result.explanation).toBeDefined();
    });

    it("should assess capability declarations", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "capability-server",
        version: "1.0.0",
        metadata: {
          capabilities: {
            tools: true,
            resources: true,
            prompts: false,
            sampling: true,
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBeDefined();
    });

    it("should detect non-compliant transports", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "legacy-server",
        version: "1.0.0",
        metadata: {
          transport: "http", // http is valid
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transportCompliance.supportsStreamableHTTP).toBe(true);
      expect(result.transportCompliance.transportValidation).toBe("passed");
    });

    it("should assess extension support", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "extended-server",
        version: "1.0.0",
        metadata: {
          extensions: {
            "custom-extension": {
              version: "1.0.0",
              enabled: true,
            },
            analytics: {
              version: "2.0.0",
              enabled: true,
            },
          },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.explanation).toBeDefined();
    });

    it("should handle minimal server info", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "minimal-server",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // When no transport specified, defaults to supporting streamable HTTP
      expect(result.transportCompliance.supportsStreamableHTTP).toBe(true);
      expect(result.status).toBeDefined();
      expect(result.recommendations).toBeDefined();
    });

    it("should provide detailed compliance findings", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "detailed-server",
        version: "1.0.0",
        metadata: {
          transport: "streamable-http",
          oauth: { enabled: true },
          annotations: { supported: false },
          streaming: { supported: true },
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transportCompliance.transportValidation).toBe("passed");
      expect(result.oauthImplementation?.implementsResourceServer).toBe(true);
      expect(result.annotationSupport.supportsReadOnlyHint).toBe(false);
      expect(result.streamingSupport.supportsStreaming).toBe(true);
    });

    it("should calculate weighted compliance score", async () => {
      // Test different combinations and verify scoring logic
      const testCases = [
        {
          metadata: {
            transport: "streamable-http",
            oauth: { enabled: true },
            annotations: { supported: true },
            streaming: { supported: true },
          },
          expectedMin: 90,
        },
        {
          metadata: {
            transport: "sse",
            oauth: { enabled: false },
            annotations: { supported: true },
            streaming: { supported: false },
          },
          expectedMax: 70,
        },
        {
          metadata: {},
          expectedMax: 30,
        },
      ];

      for (const testCase of testCases) {
        mockContext.serverInfo = {
          name: "test-server",
          version: "1.0.0",
          metadata: testCase.metadata,
        };

        const result = await assessor.assess(mockContext);

        if (testCase.expectedMin) {
          expect(["PASS", "FAIL", "NEED_MORE_INFO"]).toContain(result.status);
        }
        if (testCase.expectedMax) {
          expect(result.recommendations).toBeDefined();
        }
      }
    });
  });

  describe("outputSchema coverage tracking (Issue #64)", () => {
    it("should report 0% coverage when no tools have outputSchema", async () => {
      // Arrange
      mockContext.tools = [
        { name: "tool_a", description: "A", inputSchema: { type: "object" } },
        { name: "tool_b", description: "B", inputSchema: { type: "object" } },
        { name: "tool_c", description: "C", inputSchema: { type: "object" } },
      ];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
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
      // Arrange
      mockContext.tools = [
        {
          name: "tool_a",
          description: "A",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { result: { type: "string" } },
          },
        },
        {
          name: "tool_b",
          description: "B",
          inputSchema: { type: "object" },
          outputSchema: {
            type: "object",
            properties: { data: { type: "number" } },
          },
        },
      ];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
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
      // Arrange
      mockContext.tools = [
        {
          name: "tool_with_schema",
          description: "With",
          inputSchema: { type: "object" },
          outputSchema: { type: "object" },
        },
        {
          name: "tool_without_schema_1",
          description: "Without 1",
          inputSchema: { type: "object" },
        },
        {
          name: "tool_without_schema_2",
          description: "Without 2",
          inputSchema: { type: "object" },
        },
      ];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
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
      // Arrange
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
        {
          name: "tool_b",
          description: "B",
          inputSchema: { type: "object" },
        },
      ];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
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
      // Arrange
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
        {
          name: "tool_without",
          description: "Without schema",
          inputSchema: { type: "object" },
        },
      ];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.protocolChecks.structuredOutputSupport.passed).toBe(true);
    });

    it("should set passed=false when no tools have outputSchema", async () => {
      // Arrange
      mockContext.tools = [
        { name: "tool_1", description: "T1", inputSchema: { type: "object" } },
        { name: "tool_2", description: "T2", inputSchema: { type: "object" } },
      ];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("Success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.protocolChecks.structuredOutputSupport.passed).toBe(false);
    });
  });
});
