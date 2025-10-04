import { DynamicSecurityAssessor } from "./DynamicSecurityAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("DynamicSecurityAssessor", () => {
  let assessor: DynamicSecurityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new DynamicSecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess dynamic security with clean runtime behavior", async () => {
      // Arrange
      const tool = createMockTool({ name: "safe-tool" });
      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(
          createMockCallToolResponse("Normal operation", false),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.category).toBe("dynamicSecurity");
      expect(result.status).toBe("PASS");
      expect(result.score).toBeGreaterThan(80);
      expect(result.runtimeBehavior.anomalies).toHaveLength(0);
      expect(result.runtimeBehavior.resourceUsage.cpu).toBe("normal");
      expect(result.runtimeBehavior.resourceUsage.memory).toBe("normal");
      expect(result.runtimeBehavior.resourceUsage.network).toBe("normal");
    });

    it("should detect runtime anomalies", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(async () => {
        // Simulate high resource usage
        await new Promise((resolve) => setTimeout(resolve, 100));
        return createMockCallToolResponse("Anomalous behavior detected", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.runtimeBehavior.anomalies.length).toBeGreaterThan(0);
      expect(result.runtimeBehavior.suspiciousPatterns).toContain(
        "High execution time",
      );
      expect(result.criticalFindings).toContain("Runtime anomalies detected");
      expect(result.status).toBe("FAIL");
    });

    it("should detect excessive resource usage", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        // Simulate excessive CPU usage
        const start = Date.now();
        while (Date.now() - start < 200) {
          // Busy wait to simulate high CPU
        }
        return createMockCallToolResponse("CPU intensive operation", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.runtimeBehavior.resourceUsage.cpu).toBe("excessive");
      expect(result.criticalFindings).toContain("Excessive resource usage");
      expect(result.score).toBeLessThan(60);
    });

    it("should conduct fuzzing tests", async () => {
      // Arrange
      let fuzzTestCount = 0;
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        fuzzTestCount++;

        // Simulate different responses to fuzz inputs
        if (params.fuzzInput && typeof params.fuzzInput === "string") {
          if (params.fuzzInput.includes("crash")) {
            throw new Error("Tool crashed");
          }
          if (params.fuzzInput.length > 10000) {
            return createMockCallToolResponse("Buffer overflow detected", true);
          }
          if (params.fuzzInput.includes("injection")) {
            return createMockCallToolResponse(
              "Injection attempt blocked",
              true,
            );
          }
        }

        return createMockCallToolResponse("Fuzz test passed", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.fuzzingResults.totalTests).toBeGreaterThan(0);
      expect(result.fuzzingResults.crashes).toBeGreaterThan(0);
      expect(result.fuzzingResults.unexpectedBehaviors).toContain(
        "Buffer overflow",
      );
      expect(result.fuzzingResults.unexpectedBehaviors).toContain(
        "Injection attempt",
      );
      expect(result.criticalFindings).toContain("Fuzzing vulnerabilities");
    });

    it("should detect sandbox escape attempts", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        // Simulate sandbox escape detection
        if (params.command && params.command.includes("break")) {
          return createMockCallToolResponse(
            "Sandbox escape attempt detected",
            true,
          );
        }
        if (params.input && params.input.includes("__proto__")) {
          return createMockCallToolResponse(
            "Prototype pollution attempt",
            true,
          );
        }
        return createMockCallToolResponse("Normal operation", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.sandboxEscape.attempted).toBe(true);
      expect(result.sandboxEscape.techniques).toContain("Prototype pollution");
      expect(result.sandboxEscape.techniques).toContain("Command injection");
      expect(result.criticalFindings).toContain("Sandbox escape attempts");
      expect(result.status).toBe("FAIL");
    });

    it("should detect memory leaks", async () => {
      // Arrange
      const largeObjectReferences: any[] = [];

      mockContext.callTool = jest.fn().mockImplementation(() => {
        // Simulate memory leak by creating large objects
        for (let i = 0; i < 1000; i++) {
          largeObjectReferences.push(new Array(1000).fill("memory-leak"));
        }
        return createMockCallToolResponse("Operation completed", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.memoryLeaks.detected).toBe(true);
      expect(result.memoryLeaks.severity).toBe("high");
      expect(result.memoryLeaks.locations).toContain("Tool execution context");
      expect(result.criticalFindings).toContain("Memory leaks detected");
    });

    it("should test boundary conditions", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        // Test various boundary conditions
        if (params.value === null) {
          return createMockCallToolResponse("Null handling error", true);
        }
        if (params.value === undefined) {
          return createMockCallToolResponse("Undefined handling error", true);
        }
        if (
          typeof params.value === "number" &&
          params.value === Number.MAX_SAFE_INTEGER
        ) {
          return createMockCallToolResponse("Integer overflow", true);
        }
        if (typeof params.value === "string" && params.value.length === 0) {
          return createMockCallToolResponse("Empty string error", true);
        }
        return createMockCallToolResponse("Boundary test passed", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.fuzzingResults.unexpectedBehaviors).toContain(
        "Null handling error",
      );
      expect(result.fuzzingResults.unexpectedBehaviors).toContain(
        "Integer overflow",
      );
      expect(result.fuzzingResults.unexpectedBehaviors).toContain(
        "Empty string error",
      );
      expect(result.criticalFindings).toContain("Boundary condition failures");
    });

    it("should detect infinite loops and hangs", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (params.input === "infinite-loop") {
          // Simulate hang by never resolving
          return new Promise(() => {});
        }
        return createMockCallToolResponse("Normal response", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.fuzzingResults.hangs).toBeGreaterThan(0);
      expect(result.runtimeBehavior.suspiciousPatterns).toContain(
        "Tool timeouts",
      );
      expect(result.criticalFindings).toContain("Tool hangs detected");
    });

    it("should analyze network behavior patterns", async () => {
      // Arrange
      let networkCalls = 0;
      mockContext.callTool = jest.fn().mockImplementation(() => {
        networkCalls++;
        // Simulate network-intensive operation
        if (networkCalls > 10) {
          return createMockCallToolResponse(
            "Excessive network activity",
            false,
          );
        }
        return createMockCallToolResponse("Network operation", false);
      });

      // Mock fetch to simulate network calls
      jest
        .spyOn(global, "fetch")
        .mockImplementation(() =>
          Promise.resolve(new Response("Network response")),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.runtimeBehavior.resourceUsage.network).toBe("high");
      expect(result.runtimeBehavior.suspiciousPatterns).toContain(
        "Excessive network calls",
      );
      expect(result.anomalyScore).toBeGreaterThan(0.5);
    });

    it("should test input validation bypasses", async () => {
      // Arrange
      const bypassAttempts = [
        'admin"; DROP TABLE users; --',
        "../../etc/passwd",
        '<script>alert("xss")</script>',
        "${7*7}", // Template injection
        'eval("malicious code")',
        "%00null-byte-injection",
      ];

      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        const input = JSON.stringify(params);
        for (const attempt of bypassAttempts) {
          if (input.includes(attempt)) {
            return createMockCallToolResponse(
              `Bypass attempt with: ${attempt}`,
              true,
            );
          }
        }
        return createMockCallToolResponse("Input validated", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.fuzzingResults.unexpectedBehaviors.length).toBeGreaterThan(
        3,
      );
      expect(result.criticalFindings).toContain("Input validation bypasses");
      expect(result.score).toBeLessThan(70);
    });

    it("should calculate comprehensive anomaly score", async () => {
      // Arrange - simulate mixed security profile
      let testCounter = 0;
      mockContext.callTool = jest.fn().mockImplementation(() => {
        testCounter++;

        // Mix of normal and anomalous behaviors
        if (testCounter % 3 === 0) {
          // Every third call has anomalous behavior
          return createMockCallToolResponse(
            "Anomalous response time",
            false,
            500,
          );
        }
        if (testCounter % 5 === 0) {
          // Every fifth call consumes excessive memory
          const largeData = new Array(100000).fill("memory-intensive");
          return createMockCallToolResponse(
            `Large data: ${largeData.length}`,
            false,
          );
        }

        return createMockCallToolResponse("Normal operation", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.anomalyScore).toBeGreaterThan(0.2);
      expect(result.anomalyScore).toBeLessThan(0.8);
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.score).toBeGreaterThan(40);
      expect(result.score).toBeLessThan(80);
    });

    it("should provide security recommendations", async () => {
      // Arrange - simulate various security issues
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (params.test === "memory-leak") {
          // Simulate memory leak
          return createMockCallToolResponse("Memory leak detected", false);
        }
        if (params.test === "injection") {
          return createMockCallToolResponse("Injection vulnerability", true);
        }
        return createMockCallToolResponse("Normal", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContain(
        "Implement memory leak detection",
      );
      expect(result.recommendations).toContain("Add input sanitization");
      expect(result.recommendations).toContain("Enable runtime monitoring");
      expect(result.recommendations).toContain("Implement resource limits");
      expect(result.recommendations.length).toBeGreaterThan(3);
    });

    it("should handle tools with no dynamic behavior", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.fuzzingResults.totalTests).toBe(0);
      expect(result.score).toBe(0);
      expect(result.explanation).toContain(
        "No tools available for dynamic testing",
      );
    });

    it("should detect race conditions", async () => {
      // Arrange
      let sharedResource = 0;
      const operations: Promise<any>[] = [];

      mockContext.callTool = jest.fn().mockImplementation(() => {
        // Simulate race condition by concurrent access to shared resource
        const operation = new Promise((resolve) => {
          setTimeout(() => {
            const current = sharedResource;
            setTimeout(() => {
              sharedResource = current + 1;
              resolve(
                createMockCallToolResponse(
                  `Resource: ${sharedResource}`,
                  false,
                ),
              );
            }, 1);
          }, Math.random() * 10);
        });

        operations.push(operation);
        return operation;
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.runtimeBehavior.suspiciousPatterns).toContain(
        "Race conditions",
      );
      expect(result.criticalFindings).toContain("Concurrency issues");
    });

    it("should test performance under load", async () => {
      // Arrange
      const performanceResults: number[] = [];

      mockContext.callTool = jest.fn().mockImplementation(() => {
        const start = Date.now();

        // Simulate varying performance under load
        const delay = Math.random() * 100 + performanceResults.length * 2;

        return new Promise((resolve) => {
          setTimeout(() => {
            const executionTime = Date.now() - start;
            performanceResults.push(executionTime);
            resolve(
              createMockCallToolResponse(
                `Execution time: ${executionTime}ms`,
                false,
              ),
            );
          }, delay);
        });
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.runtimeBehavior.suspiciousPatterns).toContain(
        "Performance degradation",
      );
      expect(result.anomalyScore).toBeGreaterThan(0.3);
    });
  });

  describe("edge cases", () => {
    it("should handle tool crashes gracefully", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        throw new Error("Tool crashed unexpectedly");
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.fuzzingResults.crashes).toBeGreaterThan(0);
      expect(result.status).toBe("FAIL");
      expect(result.criticalFindings).toContain("Tool crashes during testing");
    });

    it("should handle malformed responses", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockResolvedValue(null);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.runtimeBehavior.anomalies).toContain("Malformed responses");
      expect(result.criticalFindings).toContain("Response format anomalies");
    });

    it("should timeout long-running operations", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return new Promise((resolve) => {
          // Never resolve to simulate infinite execution
        });
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.fuzzingResults.hangs).toBeGreaterThan(0);
      expect(result.status).toBe("FAIL");
    });
  });
});
