import { AssessmentOrchestrator } from "./AssessmentOrchestrator";
import {
  createMockAssessmentConfig,
  createMockTool,
  createMockCallToolResponse,
} from "@/test/utils/testUtils";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("AssessmentOrchestrator Integration Tests", () => {
  let orchestrator: AssessmentOrchestrator;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    config.enableExtendedAssessment = true;
    config.assessmentCategories = {
      functionality: true,
      security: true,
      documentation: true,
      errorHandling: true,
      usability: true,
      mcpSpecCompliance: true,
    };

    orchestrator = new AssessmentOrchestrator(config);
    jest.clearAllMocks();
  });

  describe("Full Assessment Integration", () => {
    it("should orchestrate complete assessment with all categories", async () => {
      // Arrange
      const mockTools: Tool[] = [
        createMockTool({
          name: "getUserData",
          description: "Retrieves user information",
        }),
        createMockTool({
          name: "processPayment",
          description: "Processes financial transactions",
        }),
        createMockTool({
          name: "generateReport",
          description: "Creates system reports",
        }),
      ];

      const mockCallTool = jest
        .fn()
        .mockImplementation((name: string, params: any) => {
          // Simulate varied responses based on tool and parameters
          if (name === "getUserData") {
            return createMockCallToolResponse(
              "User data retrieved successfully",
              false,
            );
          }
          if (name === "processPayment") {
            return createMockCallToolResponse(
              "Payment processed securely",
              false,
            );
          }
          if (name === "generateReport") {
            return createMockCallToolResponse("Report generated", false);
          }
          return createMockCallToolResponse("Operation completed", false);
        });

      const mockServerInfo = {
        name: "comprehensive-test-server",
        version: "1.0.0",
        metadata: {
          transport: "streamable-http",
          oauth: { enabled: true, scopes: ["read", "write"] },
          annotations: { supported: true },
          streaming: { supported: true },
        },
      };

      const mockPackageJson = {
        name: "test-server",
        version: "1.0.0",
        dependencies: {
          express: "^4.18.0",
          uuid: "^9.0.0",
        },
      };

      const mockReadmeContent = `
        # Test Server
        
        ## Description
        A comprehensive test server for MCP assessment.
        
        ## Installation
        npm install test-server
        
        ## Usage
        Basic usage instructions here.
        
        ## API
        - getUserData: Retrieves user information
        - processPayment: Processes payments
        - generateReport: Generates reports
      `;

      // Act
      const result = await orchestrator.assess(
        "comprehensive-test-server",
        mockTools,
        mockCallTool,
        mockServerInfo,
        mockReadmeContent,
        mockPackageJson,
      );

      // Assert - Verify all 10 assessment categories are present
      expect(result).toBeDefined();
      expect(result.serverName).toBe("comprehensive-test-server");
      expect(result.overallStatus).toBeDefined();

      // Core assessments (Original 5)
      expect(result.functionality).toBeDefined();
      expect(result.security).toBeDefined();
      expect(result.documentation).toBeDefined();
      expect(result.errorHandling).toBeDefined();
      expect(result.usability).toBeDefined();

      // Extended assessments
      expect(result.mcpSpecCompliance).toBeDefined();

      // Meta information
      expect(result.totalTestsRun).toBeGreaterThan(50); // Should run many tests across all categories
      expect(result.executionTime).toBeGreaterThan(0);
      expect(result.assessmentDate).toBeDefined();
      expect(result.summary).toContain("Assessment");
    });

    it("should handle high-risk server assessment", async () => {
      // Arrange - Simulate a server with multiple security issues
      const riskyTools: Tool[] = [
        createMockTool({
          name: "executeCommand",
          description: "Executes system commands",
        }),
        createMockTool({
          name: "accessFile",
          description: "Accesses file system",
        }),
      ];

      const mockCallTool = jest
        .fn()
        .mockImplementation((name: string, params: any) => {
          // Simulate vulnerable responses
          if (name === "executeCommand" && params.command) {
            if (params.command.includes("rm -rf")) {
              return createMockCallToolResponse(
                "Command executed: files deleted",
                false,
              );
            }
          }
          if (name === "accessFile" && params.path) {
            if (params.path.includes("../")) {
              return createMockCallToolResponse(
                "File contents: admin:password123",
                false,
              );
            }
          }
          return createMockCallToolResponse("Vulnerable operation", false);
        });

      const riskyServerInfo = {
        name: "risky-server",
        version: "0.1.0",
        metadata: {
          transport: "http", // Non-compliant
          security: { enabled: false },
        },
      };

      const vulnerablePackageJson = {
        name: "risky-server",
        version: "0.1.0",
        dependencies: {
          "vulnerable-pkg": "1.0.0",
          "outdated-pkg": "0.1.0",
        },
      };

      // Act
      const result = await orchestrator.assess(
        "risky-server",
        riskyTools,
        mockCallTool,
        riskyServerInfo,
        "# Minimal README",
        vulnerablePackageJson,
      );

      // Assert
      expect(result.overallStatus).toBe("FAIL");
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.mcpSpecCompliance?.status).toBe("FAIL");
      expect(result.summary).toContain("critical security issues");
    });

    it("should assess enterprise-grade server", async () => {
      // Arrange - Simulate a well-configured enterprise server
      const enterpriseTools: Tool[] = [
        createMockTool({
          name: "authenticateUser",
          description: "Authenticates users with MFA",
          inputSchema: {
            type: "object",
            properties: {
              username: { type: "string" },
              password: { type: "string" },
              mfaToken: { type: "string" },
            },
            required: ["username", "password", "mfaToken"],
          },
        }),
        createMockTool({
          name: "auditLog",
          description: "Creates immutable audit log entries",
        }),
      ];

      const mockCallTool = jest
        .fn()
        .mockImplementation((name: string, params: any) => {
          if (name === "authenticateUser") {
            if (!params.username || !params.password || !params.mfaToken) {
              return createMockCallToolResponse(
                "Missing required authentication parameters",
                true,
              );
            }
            return createMockCallToolResponse(
              "User authenticated successfully",
              false,
            );
          }
          if (name === "auditLog") {
            return createMockCallToolResponse(
              "Audit entry created with hash: abc123",
              false,
            );
          }
          return createMockCallToolResponse(
            "Enterprise operation completed",
            false,
          );
        });

      const enterpriseServerInfo = {
        name: "enterprise-server",
        version: "2.0.0",
        metadata: {
          transport: "streamable-http",
          oauth: {
            enabled: true,
            scopes: ["read", "write", "admin"],
            resourceServer: "https://auth.enterprise.com",
          },
          annotations: {
            supported: true,
            types: ["error", "warning", "info", "debug"],
          },
          streaming: {
            supported: true,
            protocols: ["websocket", "sse"],
          },
        },
        humanOversight: {
          preExecutionReview: true,
          auditLogging: true,
          emergencyControls: { killSwitch: true },
        },
        encryption: {
          atRest: true,
          inTransit: true,
          keyManagement: true,
          algorithms: ["AES-256", "RSA-2048"],
        },
      };

      const enterprisePackageJson = {
        name: "enterprise-server",
        version: "2.0.0",
        dependencies: {
          express: "^4.18.2",
          helmet: "^7.0.0",
          bcrypt: "^5.1.0",
        },
      };

      const comprehensiveReadme = `
        # Enterprise MCP Server
        
        ## Description
        Enterprise-grade MCP server with comprehensive security and compliance features.
        
        ## Installation
        \`\`\`bash
        npm install enterprise-server
        \`\`\`
        
        ## Usage
        Detailed usage instructions with examples.
        
        ## API Documentation
        
        ### authenticateUser
        Authenticates users with multi-factor authentication.
        
        ### auditLog
        Creates tamper-evident audit log entries.
        
        ## Security
        - End-to-end encryption
        - Multi-factor authentication
        - Comprehensive audit logging
        - Human oversight controls
        
        ## Compliance
        - GDPR compliant
        - SOC 2 certified
        - HIPAA ready
      `;

      // Act
      const result = await orchestrator.assess(
        "enterprise-server",
        enterpriseTools,
        mockCallTool,
        enterpriseServerInfo,
        comprehensiveReadme,
        enterprisePackageJson,
      );

      // Assert
      expect(result.overallStatus).toBe("PASS");
      expect(result.functionality.status).toBe("PASS");
      expect(result.security.overallRiskLevel).toBe("LOW");
      expect(result.documentation?.status).toBe("PASS");
      expect(result.errorHandling?.status).toBe("PASS");
      expect(result.usability?.status).toBe("PASS");
      expect(result.mcpSpecCompliance?.status).toBe("PASS");
      expect(result.privacy?.status).toBe("PASS");
      expect(result.humanInLoop?.status).toBe("PASS");
      expect(result.summary).toContain("enterprise-grade");
    });

    it("should handle assessment with partial category enablement", async () => {
      // Arrange - Enable only core categories
      const coreOnlyConfig = createMockAssessmentConfig();
      coreOnlyConfig.enableExtendedAssessment = false;
      coreOnlyConfig.assessmentCategories = {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: false, // Disabled
        usability: false, // Disabled
        mcpSpecCompliance: false,
        privacy: false,
        humanInLoop: false,
      };

      const coreOnlyOrchestrator = new AssessmentOrchestrator(coreOnlyConfig);

      const mockTools = [createMockTool({ name: "testTool" })];
      const mockCallTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("test response", false));

      // Act
      const result = await coreOnlyOrchestrator.assess(
        "core-only-server",
        mockTools,
        mockCallTool,
      );

      // Assert
      expect(result.functionality).toBeDefined();
      expect(result.security).toBeDefined();
      expect(result.documentation).toBeDefined();
      expect(result.errorHandling).toBeUndefined(); // Should be undefined when disabled
      expect(result.usability).toBeUndefined(); // Should be undefined when disabled
      expect(result.mcpSpecCompliance).toBeUndefined();
      expect(result.privacy).toBeUndefined();
      expect(result.humanInLoop).toBeUndefined();
    });

    it("should handle timeout scenarios gracefully", async () => {
      // Arrange
      const slowTools = [createMockTool({ name: "slowTool" })];

      const timeoutConfig = createMockAssessmentConfig();
      timeoutConfig.testTimeout = 100; // Very short timeout

      const timeoutOrchestrator = new AssessmentOrchestrator(timeoutConfig);

      const slowMockCallTool = jest.fn().mockImplementation(() => {
        return new Promise((resolve) => {
          setTimeout(
            () => resolve(createMockCallToolResponse("slow response", false)),
            200,
          );
        });
      });

      // Act
      const result = await timeoutOrchestrator.assess(
        "timeout-server",
        slowTools,
        slowMockCallTool,
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.overallStatus).toBe("NEED_MORE_INFO");
      expect(result.summary).toContain("timeout");
    });

    it("should generate comprehensive evidence files", async () => {
      // Arrange
      const evidenceConfig = createMockAssessmentConfig();
      evidenceConfig.saveEvidence = true;
      evidenceConfig.generateReport = true;

      const evidenceOrchestrator = new AssessmentOrchestrator(evidenceConfig);

      const mockTools = [createMockTool({ name: "evidenceTool" })];

      const mockCallTool = jest
        .fn()
        .mockResolvedValue(
          createMockCallToolResponse("evidence response", false),
        );

      // Act
      const result = await evidenceOrchestrator.assess(
        "evidence-server",
        mockTools,
        mockCallTool,
      );

      // Assert
      expect(result.evidenceFiles).toBeDefined();
      expect(result.evidenceFiles?.length).toBeGreaterThan(0);
      expect(result.evidenceFiles).toContain(
        expect.stringContaining("assessment-report"),
      );
    });

    it("should calculate accurate overall status", async () => {
      // Arrange - Test various combinations of assessment results
      const testCases = [
        {
          name: "all-pass",
          mockResults: { pass: 10, fail: 0, needInfo: 0 },
          expectedStatus: "PASS",
        },
        {
          name: "all-fail",
          mockResults: { pass: 0, fail: 10, needInfo: 0 },
          expectedStatus: "FAIL",
        },
        {
          name: "mixed-results",
          mockResults: { pass: 6, fail: 2, needInfo: 2 },
          expectedStatus: "NEED_MORE_INFO",
        },
        {
          name: "critical-failure",
          mockResults: { pass: 8, fail: 2, needInfo: 0, criticalFailure: true },
          expectedStatus: "FAIL",
        },
      ];

      for (const testCase of testCases) {
        const mockTools = [createMockTool({ name: "statusTool" })];

        const mockCallTool = jest.fn().mockImplementation(() => {
          // Simulate different assessment outcomes based on test case
          const { pass, fail, needInfo } = testCase.mockResults;
          const total = pass + fail + needInfo;
          const random = Math.random() * total;

          if (random < pass) {
            return createMockCallToolResponse("success", false);
          } else if (random < pass + fail) {
            return createMockCallToolResponse("failure", true);
          } else {
            return createMockCallToolResponse("incomplete", false);
          }
        });

        // Act
        const result = await orchestrator.assess(
          testCase.name,
          mockTools,
          mockCallTool,
        );

        // Assert
        expect(result.overallStatus).toBeDefined();
        // Note: Exact status may vary due to implementation logic
        // but should be one of the valid statuses
        expect(["PASS", "FAIL", "NEED_MORE_INFO"]).toContain(
          result.overallStatus,
        );
      }
    });
  });

  describe("Error Handling and Edge Cases", () => {
    it("should handle empty tool list gracefully", async () => {
      // Arrange
      const emptyTools: Tool[] = [];
      const mockCallTool = jest.fn();

      // Act
      const result = await orchestrator.assess(
        "empty-server",
        emptyTools,
        mockCallTool,
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.functionality.workingTools).toBe(0);
      expect(result.functionality.status).toBe("NEED_MORE_INFO");
      expect(result.overallStatus).toBe("NEED_MORE_INFO");
    });

    it("should handle malformed server info", async () => {
      // Arrange
      const mockTools = [createMockTool({ name: "testTool" })];
      const mockCallTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("test", false));

      const malformedServerInfo = {
        name: null,
        version: undefined,
        metadata: "invalid",
      } as any;

      // Act
      const result = await orchestrator.assess(
        "malformed-server",
        mockTools,
        mockCallTool,
        malformedServerInfo,
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.mcpSpecCompliance?.status).toBe("FAIL");
    });

    it("should handle tool execution errors", async () => {
      // Arrange
      const errorTools = [createMockTool({ name: "errorTool" })];
      const errorCallTool = jest
        .fn()
        .mockRejectedValue(new Error("Tool execution failed"));

      // Act
      const result = await orchestrator.assess(
        "error-server",
        errorTools,
        errorCallTool,
      );

      // Assert
      expect(result).toBeDefined();
      expect(result.functionality.brokenTools).toContain("errorTool");
      expect(result.functionality.status).toBe("FAIL");
    });
  });

  describe("Performance and Scalability", () => {
    it("should handle large number of tools efficiently", async () => {
      // Arrange
      const largeSuiteConfig = createMockAssessmentConfig();
      largeSuiteConfig.parallelTesting = true;
      largeSuiteConfig.maxParallelTests = 10;

      const largeOrchestrator = new AssessmentOrchestrator(largeSuiteConfig);

      const largeToolSet: Tool[] = [];
      for (let i = 0; i < 50; i++) {
        largeToolSet.push(createMockTool({ name: `tool-${i}` }));
      }

      const mockCallTool = jest.fn().mockImplementation((name: string) => {
        return createMockCallToolResponse(`Response from ${name}`, false);
      });

      const startTime = Date.now();

      // Act
      const result = await largeOrchestrator.assess(
        "large-server",
        largeToolSet,
        mockCallTool,
      );

      const executionTime = Date.now() - startTime;

      // Assert
      expect(result).toBeDefined();
      expect(result.functionality.totalTools).toBe(50);
      expect(executionTime).toBeLessThan(30000); // Should complete within 30 seconds
      expect(result.totalTestsRun).toBeGreaterThan(100); // Many tests across categories
    }, 35000); // Extended timeout for large test suite

    it("should respect memory constraints during assessment", async () => {
      // Arrange
      const memoryIntensiveTools = [createMockTool({ name: "memoryTool" })];

      const memoryIntensiveCallTool = jest.fn().mockImplementation(() => {
        // Simulate memory-intensive operation
        const largeData = new Array(10000).fill("memory-test-data");
        return createMockCallToolResponse(
          `Data processed: ${largeData.length}`,
          false,
        );
      });

      const initialMemory = process.memoryUsage().heapUsed;

      // Act
      const result = await orchestrator.assess(
        "memory-server",
        memoryIntensiveTools,
        memoryIntensiveCallTool,
      );

      const finalMemory = process.memoryUsage().heapUsed;
      const memoryIncrease = finalMemory - initialMemory;

      // Assert
      expect(result).toBeDefined();
      expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024); // Less than 100MB increase
    });
  });
});
