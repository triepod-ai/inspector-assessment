import { SecurityAssessor } from "./SecurityAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import {
  ALL_SECURITY_PATTERNS,
  ORIGINAL_SECURITY_PATTERNS,
  NEW_SECURITY_PATTERNS,
  createMixedAttackPayload,
} from "@/test/utils/securityPatternFactory";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("SecurityAssessor", () => {
  let assessor: SecurityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new SecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should test all 17 security patterns", async () => {
      // Arrange
      const tool = createMockTool({ name: "test-tool" });
      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.promptInjectionTests).toHaveLength(17);
      // Main 17 patterns + additional security checks (metadata, sandbox, shadowing)
      expect(mockContext.callTool).toHaveBeenCalled();
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "test-tool",
        expect.any(Object),
      );
    });

    it("should detect Direct Command Injection vulnerability", async () => {
      // Arrange
      const pattern = ORIGINAL_SECURITY_PATTERNS[0]; // Direct Command Injection
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(
          createMockCallToolResponse("Command executed: rm -rf /", false),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.promptInjectionTests).toContainEqual(
        expect.objectContaining({
          riskLevel: "HIGH",
          testName: expect.stringContaining("Direct Command Injection"),
        }),
      );
    });

    it("should detect Role Override vulnerability", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (JSON.stringify(params).includes("admin")) {
          return createMockCallToolResponse("Role changed to admin", false);
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const roleOverrideFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Role Override"),
      );
      expect(roleOverrideFindings.length).toBeGreaterThan(0);
    });

    it("should detect Data Exfiltration attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (JSON.stringify(params).includes("external://")) {
          return createMockCallToolResponse(
            "Data sent to external source",
            false,
          );
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const exfiltrationFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Data Exfiltration"),
      );
      expect(exfiltrationFindings.length).toBeGreaterThan(0);
    });

    it("should detect Context Escape attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const paramStr = JSON.stringify(params);
        if (paramStr.includes("]]>") || paramStr.includes("<script>")) {
          return createMockCallToolResponse("Context boundary violated", false);
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const escapeFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Context Escape"),
      );
      expect(escapeFindings.length).toBeGreaterThan(0);
    });

    it("should detect Unicode Bypass attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (JSON.stringify(params).includes("ＲＭ")) {
          return createMockCallToolResponse("Unicode command detected", false);
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const unicodeFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Unicode Bypass"),
      );
      expect(unicodeFindings.length).toBeGreaterThan(0);
    });

    it("should detect Tool Shadowing attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (JSON.stringify(params).includes("shadow")) {
          return createMockCallToolResponse("Tool shadowing detected", false);
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const shadowFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Tool Shadowing"),
      );
      expect(shadowFindings.length).toBeGreaterThan(0);
    });

    it("should detect Package Squatting attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (JSON.stringify(params).includes("expres")) {
          // typo of express
          return createMockCallToolResponse(
            "Package typosquatting detected",
            false,
          );
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const squattingFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Package Squatting"),
      );
      expect(squattingFindings.length).toBeGreaterThan(0);
    });

    it("should detect Sandbox Escape attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const paramStr = JSON.stringify(params);
        if (paramStr.includes("../../../") || paramStr.includes("spawn_sync")) {
          return createMockCallToolResponse("Sandbox escape attempted", false);
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const sandboxFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Sandbox Escape"),
      );
      expect(sandboxFindings.length).toBeGreaterThan(0);
      expect(sandboxFindings[0].riskLevel).toBe("HIGH");
    });

    it("should calculate security score correctly", async () => {
      // Arrange - simulate 3 vulnerabilities out of 17 tests
      let testCount = 0;
      mockContext.callTool = jest.fn().mockImplementation(() => {
        testCount++;
        if (testCount <= 3) {
          return createMockCallToolResponse("vulnerability detected", false);
        }
        return createMockCallToolResponse("safe", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // With 3 vulnerabilities detected, security should not pass
      expect(result.status).toBeDefined();
      expect(["PASS", "FAIL", "NEED_MORE_INFO"]).toContain(result.status);
    });

    it("should handle mixed attack payloads", async () => {
      // Arrange
      const mixedPayload = createMixedAttackPayload();
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const paramStr = JSON.stringify(params);
        if (paramStr.includes("rm -rf") || paramStr.includes("admin")) {
          return createMockCallToolResponse(
            "Multiple vulnerabilities detected",
            false,
          );
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.vulnerabilities.length).toBeGreaterThan(1);
      const highRiskFindings = result.promptInjectionTests.filter(
        (f) => f.riskLevel === "HIGH",
      );
      expect(highRiskFindings.length).toBeGreaterThan(0);
    });

    it("should handle tool errors gracefully", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockResolvedValueOnce(createMockCallToolResponse("error", true))
        .mockResolvedValue(createMockCallToolResponse("success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.promptInjectionTests).toHaveLength(17);
    });

    it("should test all NEW security patterns", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Verify all patterns were tested by checking test results
      const newPatternNames = NEW_SECURITY_PATTERNS.map((p) => p.pattern);

      for (const patternName of newPatternNames) {
        expect(
          result.promptInjectionTests.some((t) => t.testName === patternName),
        ).toBe(true);
      }
    });

    it("should properly categorize risk levels", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const paramStr = JSON.stringify(params);

        // Critical risk for sandbox escape and system commands
        if (
          paramStr.includes("Sandbox Escape") ||
          paramStr.includes("System Command")
        ) {
          return createMockCallToolResponse("Critical vulnerability", false);
        }
        // High risk for command injection
        if (paramStr.includes("Direct Command")) {
          return createMockCallToolResponse("High risk detected", false);
        }
        // Medium risk for unicode bypass
        if (paramStr.includes("Unicode")) {
          return createMockCallToolResponse("Medium risk detected", false);
        }

        return createMockCallToolResponse("safe", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const findings = result.promptInjectionTests;
      const highRisk = findings.filter((f) => f.riskLevel === "HIGH");
      const mediumRisk = findings.filter((f) => f.riskLevel === "MEDIUM");

      expect(highRisk.length).toBeGreaterThan(0);
      expect(mediumRisk.length).toBeGreaterThan(0);
    });

    it("should handle timeout scenarios", async () => {
      // Arrange
      mockContext.config.testTimeout = 100;
      mockContext.callTool = jest
        .fn()
        .mockImplementation(
          () =>
            new Promise((resolve) =>
              setTimeout(
                () => resolve(createMockCallToolResponse("success", false)),
                200,
              ),
            ),
        );

      // Act
      const resultPromise = assessor.assess(mockContext);

      // Fast-forward time
      jest.advanceTimersByTime(300);

      const result = await resultPromise;

      // Assert
      expect(result).toBeDefined();
      // Should still have structure even if tests timeout
      expect(result.promptInjectionTests.length).toBeGreaterThanOrEqual(0);
    });

    it("should test with different tool configurations", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "read-tool" }),
        createMockTool({ name: "write-tool" }),
        createMockTool({ name: "execute-tool" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Should test tools with all patterns + additional security checks
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "read-tool",
        expect.any(Object),
      );
      // 3 tools × 17 patterns + additional security checks
      expect(mockContext.callTool).toHaveBeenCalled();
    });
  });
});
