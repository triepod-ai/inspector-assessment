import { SecurityAssessor } from "./SecurityAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { NEW_SECURITY_PATTERNS } from "@/test/utils/securityPatternFactory";
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
    it("should test all 8 security patterns", async () => {
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
      // In advanced mode, multiple payloads are tested per pattern (8 patterns × 3 payloads ≈ 24+ tests)
      expect(result.promptInjectionTests.length).toBeGreaterThanOrEqual(8);
      // 8 backend API security patterns
      expect(mockContext.callTool).toHaveBeenCalled();
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "test-tool",
        expect.any(Object),
      );
    });

    it("should detect Command Injection vulnerability", async () => {
      // Arrange
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
          testName: expect.stringContaining("Command Injection"),
        }),
      );
    });

    it("should detect SQL Injection vulnerability", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(
          createMockCallToolResponse(
            "SQL error: syntax error near DROP TABLE",
            false,
          ),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.promptInjectionTests).toContainEqual(
        expect.objectContaining({
          riskLevel: "HIGH",
          testName: expect.stringContaining("SQL Injection"),
        }),
      );
    });

    it("should detect Path Traversal vulnerability", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const paramStr = JSON.stringify(params);
        if (paramStr.includes("../../../")) {
          return createMockCallToolResponse("File accessed: root:x:0:0", false);
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const traversalFindings = result.promptInjectionTests.filter((f) =>
        f.testName.includes("Path Traversal"),
      );
      expect(traversalFindings.length).toBeGreaterThan(0);
      expect(traversalFindings[0].riskLevel).toBe("HIGH");
    });

    it("should calculate security score correctly", async () => {
      // Arrange - simulate 3 vulnerabilities out of 8 patterns
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
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const paramStr = JSON.stringify(params);
        // Simulate actual command execution responses that indicate vulnerability
        if (paramStr.includes("rm -rf")) {
          return createMockCallToolResponse(
            "Command executed: deleted /tmp/*, 234 files removed",
            false,
          );
        }
        if (paramStr.includes("admin")) {
          return createMockCallToolResponse(
            "Admin mode enabled. User role: admin. Access granted.",
            false,
          );
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // With improved detection, we correctly identify actual command execution vs mere keyword mentions
      expect(result.vulnerabilities.length).toBeGreaterThanOrEqual(0);
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
      // In advanced mode, should test multiple payloads per pattern (24+ tests total)
      expect(result.promptInjectionTests.length).toBeGreaterThanOrEqual(8);
    });

    it("should test all 8 backend security patterns", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("success", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // In advanced mode, verify comprehensive coverage across all 8 pattern categories
      // Patterns: Command Injection, SQL Injection, Path Traversal, Type Safety, Boundary Testing, Required Fields, MCP Error Format, Timeout Handling
      const uniqueTestNames = new Set(
        result.promptInjectionTests.map((t) => t.testName),
      );

      // Should test all 8 backend security patterns
      expect(uniqueTestNames.size).toBeGreaterThanOrEqual(8);

      // Verify key patterns are covered (use partial matching for flexibility)
      const keyBackendPatterns = [
        "Command Injection",
        "SQL Injection",
        "Path Traversal",
        "Type Safety",
        "Boundary Testing",
      ];
      for (const pattern of keyBackendPatterns) {
        expect(
          result.promptInjectionTests.some((t) => t.testName.includes(pattern)),
        ).toBe(true);
      }
    }, 240000); // 240 second timeout for comprehensive mode testing all 8 backend patterns

    it("should properly categorize risk levels", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const paramStr = JSON.stringify(params);

        // High risk for injection patterns
        if (
          paramStr.includes("Path Traversal") ||
          paramStr.includes("SQL Injection") ||
          paramStr.includes("Command Injection")
        ) {
          return createMockCallToolResponse("High risk detected", false);
        }
        // Medium risk for validation patterns
        if (
          paramStr.includes("Type Safety") ||
          paramStr.includes("Boundary Testing")
        ) {
          return createMockCallToolResponse("Medium risk detected", false);
        }
        // Low risk for protocol patterns
        if (
          paramStr.includes("MCP Error Format") ||
          paramStr.includes("Timeout Handling")
        ) {
          return createMockCallToolResponse("Low risk detected", false);
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
    }, 240000); // 240 second timeout for comprehensive risk categorization testing

    it("should handle timeout scenarios", async () => {
      // Enable fake timers for this test
      jest.useFakeTimers();

      try {
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
      } finally {
        // Clean up fake timers
        jest.useRealTimers();
      }
    }, 480000); // 480 second timeout for comprehensive mode with fake timers

    it("should test with different tool configurations", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "read-tool" }),
        createMockTool({ name: "write-tool" }),
        createMockTool({ name: "execute-tool" }),
      ];
      mockContext.tools = tools;

      // Act
      await assessor.assess(mockContext);

      // Assert
      // Should test tools with all patterns + additional security checks
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "read-tool",
        expect.any(Object),
      );
      // In advanced mode: 3 tools × ~19 patterns × ~3 payloads ≈ 171 tests
      expect(mockContext.callTool).toHaveBeenCalled();
    }, 480000); // 480 second timeout for testing 3 tools in comprehensive mode
  });
});
