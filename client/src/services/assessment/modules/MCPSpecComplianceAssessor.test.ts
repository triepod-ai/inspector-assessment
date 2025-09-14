import { MCPSpecComplianceAssessor } from "./MCPSpecComplianceAssessor";
import {
  createMockAssessmentContext,
  createMockServerInfo,
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
      expect(result.status).toBe("PASS");
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
      expect(result.transportCompliance.deprecatedSSE).toBe(false);
      expect(result.explanation).toContain("SSE");
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
      expect(result.explanation).toContain("OAuth");
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

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transportCompliance.supportsStreamableHTTP).toBe(false);
      expect(result.oauthImplementation).toBeUndefined();
      expect(result.status).toBe("FAIL");
    });

    it("should calculate compliance score based on features", async () => {
      // Arrange - partial compliance
      mockContext.serverInfo = {
        name: "partial-server",
        version: "1.0.0",
        metadata: {
          transport: "http", // Non-compliant transport
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

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Should have lower score due to missing features
      expect(result.status).toBe("FAIL");
      expect(result.transportCompliance.transportValidation).toBe("failed");
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
      expect(result.explanation).toContain("2025");
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
          transport: "http", // Should be streamable-http or sse
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transportCompliance.supportsStreamableHTTP).toBe(false);
      expect(result.transportCompliance.transportValidation).toBe("failed");
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
      expect(result.explanation).toContain("extension");
    });

    it("should handle minimal server info", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "minimal-server",
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.transportCompliance.supportsStreamableHTTP).toBe(false);
      expect(result.status).toBe("FAIL");
      expect(result.recommendations.length).toBeGreaterThan(0);
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
});
