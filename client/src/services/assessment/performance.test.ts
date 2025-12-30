import { AssessmentOrchestrator } from "./AssessmentOrchestrator";
import {
  createMockAssessmentConfig,
  createMockTool,
  createMockCallToolResponse,
} from "@/test/utils/testUtils";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessmentTypes";

describe("Assessment Performance Benchmarks", () => {
  describe("Performance Metrics", () => {
    it("should complete basic assessment within performance thresholds", async () => {
      // Arrange
      const config = createMockAssessmentConfig();
      config.parallelTesting = true;
      config.maxParallelTests = 5;

      const orchestrator = new AssessmentOrchestrator(config);

      const basicTools: Tool[] = [
        createMockTool({ name: "basic-tool-1" }),
        createMockTool({ name: "basic-tool-2" }),
        createMockTool({ name: "basic-tool-3" }),
      ];

      const mockCallTool = jest.fn().mockImplementation((name: string) => {
        // Simulate realistic response times
        const delay = Math.random() * 50 + 10; // 10-60ms
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve(createMockCallToolResponse(`Response from ${name}`, false));
          }, delay);
        });
      });

      const startTime = performance.now();
      const initialMemory = process.memoryUsage();

      // Act
      const mockContext = {
        serverName: "performance-test-server",
        tools: basicTools,
        callTool: mockCallTool,
        config,
      };

      const result = await orchestrator.runFullAssessment(mockContext);

      const endTime = performance.now();
      const finalMemory = process.memoryUsage();
      const executionTime = endTime - startTime;

      // Assert Performance Thresholds (relaxed for CI runners which are slower)
      expect(executionTime).toBeLessThan(15000); // < 15 seconds for basic assessment (CI runners are slower)
      expect(result.totalTestsRun).toBeGreaterThan(20); // Should run substantial tests
      expect((result.totalTestsRun / executionTime) * 1000).toBeGreaterThan(5); // > 5 tests/second

      // Memory usage should be reasonable
      const memoryIncreaseMB =
        (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024;
      expect(memoryIncreaseMB).toBeLessThan(50); // < 50MB memory increase

      console.log(`Basic Assessment Performance:
        - Execution Time: ${executionTime.toFixed(2)}ms
        - Total Tests: ${result.totalTestsRun}
        - Tests/Second: ${((result.totalTestsRun / executionTime) * 1000).toFixed(2)}
        - Memory Increase: ${memoryIncreaseMB.toFixed(2)}MB`);
    }, 60000); // 60 second timeout for comprehensive mode

    it("should scale linearly with tool count", async () => {
      // Arrange - Use minimal config to isolate scaling behavior from assessment complexity
      const config = createMockAssessmentConfig();
      config.parallelTesting = true;
      config.enableExtendedAssessment = false;
      config.assessmentCategories = {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        mcpSpecCompliance: false,
      };

      const orchestrator = new AssessmentOrchestrator(config);

      const toolCounts = [5, 10, 20, 30];
      const performanceResults: Array<{
        toolCount: number;
        executionTime: number;
        testsRun: number;
        throughput: number;
      }> = [];

      for (const toolCount of toolCounts) {
        const tools: Tool[] = [];
        for (let i = 0; i < toolCount; i++) {
          tools.push(createMockTool({ name: `tool-${i}` }));
        }

        const mockCallTool = jest.fn().mockImplementation(() => {
          const delay = Math.random() * 20 + 5; // 5-25ms
          return new Promise((resolve) => {
            setTimeout(() => {
              resolve(createMockCallToolResponse("test response", false));
            }, delay);
          });
        });

        const startTime = performance.now();

        // Act
        const mockContext = {
          serverName: `scale-test-${toolCount}`,
          tools: tools,
          callTool: mockCallTool,
          config,
        };

        const result = await orchestrator.runFullAssessment(mockContext);

        const endTime = performance.now();
        const executionTime = endTime - startTime;
        const throughput = (result.totalTestsRun / executionTime) * 1000; // tests/second

        performanceResults.push({
          toolCount,
          executionTime,
          testsRun: result.totalTestsRun,
          throughput,
        });

        // Performance should scale reasonably (4000ms per tool on CI runners)
        // Even with minimal config, 5 core modules run multiple scenarios per tool
        expect(executionTime).toBeLessThan(toolCount * 4000); // < 4s per tool on CI runners
        expect(throughput).toBeGreaterThan(1); // > 1 test/second minimum
      }

      // Assert scaling characteristics
      for (let i = 1; i < performanceResults.length; i++) {
        const current = performanceResults[i];
        const previous = performanceResults[i - 1];

        // Execution time should not grow exponentially
        const timeRatio = current.executionTime / previous.executionTime;
        const toolRatio = current.toolCount / previous.toolCount;

        expect(timeRatio).toBeLessThan(toolRatio * 1.5); // Should be roughly linear
      }

      console.log("Scaling Performance Results:");
      performanceResults.forEach((result) => {
        console.log(
          `  ${result.toolCount} tools: ${result.executionTime.toFixed(2)}ms, ${result.testsRun} tests, ${result.throughput.toFixed(2)} tests/sec`,
        );
      });
    }, 180000); // 180 second timeout for testing 5+10+20+30 tools on CI runners

    it("should maintain performance with extended assessments enabled", async () => {
      // Arrange
      const baseConfig = createMockAssessmentConfig();
      baseConfig.enableExtendedAssessment = false;
      baseConfig.assessmentCategories = {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        mcpSpecCompliance: false,
      };

      const extendedConfig = createMockAssessmentConfig();
      extendedConfig.enableExtendedAssessment = true;
      extendedConfig.assessmentCategories = {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        mcpSpecCompliance: true,
      };

      const baseOrchestrator = new AssessmentOrchestrator(baseConfig);
      const extendedOrchestrator = new AssessmentOrchestrator(extendedConfig);

      const testTools: Tool[] = [
        createMockTool({ name: "test-tool-1" }),
        createMockTool({ name: "test-tool-2" }),
        createMockTool({ name: "test-tool-3" }),
      ];

      const mockCallTool = jest.fn().mockImplementation(() => {
        return createMockCallToolResponse("test response", false);
      });

      const mockServerInfo = {
        name: "performance-server",
        version: "1.0.0",
      };

      const mockPackageJson = {
        name: "performance-server",
        version: "1.0.0",
        dependencies: { "test-dep": "1.0.0" },
      };

      // Act - Base assessment
      const baseStartTime = performance.now();
      const baseResult = await baseOrchestrator.assess(
        "base-server",
        testTools,
        mockCallTool,
        mockServerInfo,
        "# Basic README",
        mockPackageJson,
      );
      const baseEndTime = performance.now();
      const baseExecutionTime = baseEndTime - baseStartTime;

      // Act - Extended assessment
      const extendedStartTime = performance.now();
      const extendedResult = await extendedOrchestrator.assess(
        "extended-server",
        testTools,
        mockCallTool,
        mockServerInfo,
        "# Basic README",
        mockPackageJson,
      );
      const extendedEndTime = performance.now();
      const extendedExecutionTime = extendedEndTime - extendedStartTime;

      // Assert - Extended assessments should run at least as many tests as base
      // Note: Some extended categories (mcpSpec, privacy, humanInLoop) may not add
      // significantly to test count, so we check >= instead of >
      expect(extendedResult.totalTestsRun).toBeGreaterThanOrEqual(
        baseResult.totalTestsRun,
      );

      // Extended assessment should not be more than 3x slower than base
      const performanceRatio = extendedExecutionTime / baseExecutionTime;
      expect(performanceRatio).toBeLessThan(3);

      // Both should maintain reasonable throughput
      const baseThroughput =
        (baseResult.totalTestsRun / baseExecutionTime) * 1000;
      const extendedThroughput =
        (extendedResult.totalTestsRun / extendedExecutionTime) * 1000;

      expect(baseThroughput).toBeGreaterThan(5);
      expect(extendedThroughput).toBeGreaterThan(3);

      console.log(`Extended Assessment Performance Comparison:
        Base (5 categories): ${baseExecutionTime.toFixed(2)}ms, ${baseResult.totalTestsRun} tests, ${baseThroughput.toFixed(2)} tests/sec
        Extended (10 categories): ${extendedExecutionTime.toFixed(2)}ms, ${extendedResult.totalTestsRun} tests, ${extendedThroughput.toFixed(2)} tests/sec
        Performance Ratio: ${performanceRatio.toFixed(2)}x`);
    }, 60000); // 60 second timeout for comprehensive mode with extended assessments

    it("should handle concurrent assessments efficiently", async () => {
      // Arrange
      const config = createMockAssessmentConfig();
      config.parallelTesting = true;
      config.maxParallelTests = 10;

      const orchestrator = new AssessmentOrchestrator(config);

      const testTools: Tool[] = [
        createMockTool({ name: "concurrent-tool-1" }),
        createMockTool({ name: "concurrent-tool-2" }),
      ];

      const mockCallTool = jest.fn().mockImplementation((name: string) => {
        const delay = Math.random() * 30 + 10; // 10-40ms
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve(createMockCallToolResponse(`Response from ${name}`, false));
          }, delay);
        });
      });

      // Create multiple concurrent assessments
      const concurrentCount = 5;
      const assessmentPromises: Promise<any>[] = [];

      const startTime = performance.now();

      for (let i = 0; i < concurrentCount; i++) {
        const mockContext = {
          serverName: `concurrent-server-${i}`,
          tools: testTools,
          callTool: mockCallTool,
          config,
        };

        const assessmentPromise = orchestrator.runFullAssessment(mockContext);
        assessmentPromises.push(assessmentPromise);
      }

      // Act
      const results = await Promise.all(assessmentPromises);
      const endTime = performance.now();
      const totalExecutionTime = endTime - startTime;

      // Assert
      expect(results).toHaveLength(concurrentCount);
      results.forEach((result, index) => {
        expect(result).toBeDefined();
        expect(result.serverName).toBe(`concurrent-server-${index}`);
      });

      // Concurrent execution should be more efficient than sequential
      const avgTestsPerAssessment =
        results.reduce((sum, r) => sum + r.totalTestsRun, 0) / concurrentCount;
      const totalThroughput =
        ((avgTestsPerAssessment * concurrentCount) / totalExecutionTime) * 1000;

      expect(totalThroughput).toBeGreaterThan(10); // > 10 tests/second total throughput

      console.log(`Concurrent Assessment Performance:
        ${concurrentCount} concurrent assessments
        Total Time: ${totalExecutionTime.toFixed(2)}ms
        Avg Tests per Assessment: ${avgTestsPerAssessment.toFixed(0)}
        Total Throughput: ${totalThroughput.toFixed(2)} tests/sec`);
    }, 60000); // 60 second timeout for 5 concurrent assessments in comprehensive mode

    it("should optimize memory usage during large assessments", async () => {
      // Arrange
      const config = createMockAssessmentConfig();
      const orchestrator = new AssessmentOrchestrator(config);

      // Create a large set of tools
      const largeToolSet: Tool[] = [];
      for (let i = 0; i < 100; i++) {
        largeToolSet.push(
          createMockTool({
            name: `memory-tool-${i}`,
            description: `Tool ${i} for memory testing with longer description to increase memory usage`,
          }),
        );
      }

      const mockCallTool = jest.fn().mockImplementation((_name: string) => {
        // Return responses with varying sizes
        const responseSize = Math.floor(Math.random() * 1000) + 100;
        const response = "x".repeat(responseSize);
        return createMockCallToolResponse(response, false);
      });

      // Measure memory usage
      const measurements: Array<{
        testNumber: number;
        heapUsed: number;
        heapTotal: number;
      }> = [];

      let testCounter = 0;
      const originalCallTool = mockCallTool;
      const instrumentedCallTool = jest.fn().mockImplementation((...args) => {
        testCounter++;
        if (testCounter % 20 === 0) {
          // Sample every 20th call
          const memUsage = process.memoryUsage();
          measurements.push({
            testNumber: testCounter,
            heapUsed: memUsage.heapUsed,
            heapTotal: memUsage.heapTotal,
          });
        }
        return originalCallTool(...args);
      });

      const initialMemory = process.memoryUsage();

      // Act
      const mockContext = {
        serverName: "memory-test-server",
        tools: largeToolSet,
        callTool: instrumentedCallTool,
        config,
      };

      const result = await orchestrator.runFullAssessment(mockContext);

      const finalMemory = process.memoryUsage();

      // Assert
      expect(result).toBeDefined();
      expect(result.totalTestsRun).toBeGreaterThan(200);

      // Memory usage should not grow excessively
      const memoryIncreaseMB =
        (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024;
      expect(memoryIncreaseMB).toBeLessThan(200); // < 200MB total increase

      // Memory should not continuously grow (should have garbage collection)
      if (measurements.length >= 3) {
        const firstThird = measurements.slice(
          0,
          Math.floor(measurements.length / 3),
        );
        const lastThird = measurements.slice(
          -Math.floor(measurements.length / 3),
        );

        const avgEarly =
          firstThird.reduce((sum, m) => sum + m.heapUsed, 0) /
          firstThird.length;
        const avgLate =
          lastThird.reduce((sum, m) => sum + m.heapUsed, 0) / lastThird.length;

        const memoryGrowthRatio = avgLate / avgEarly;
        expect(memoryGrowthRatio).toBeLessThan(3); // Should not triple memory usage
      }

      console.log(`Memory Usage Analysis:
        Initial: ${(initialMemory.heapUsed / 1024 / 1024).toFixed(2)}MB
        Final: ${(finalMemory.heapUsed / 1024 / 1024).toFixed(2)}MB
        Increase: ${memoryIncreaseMB.toFixed(2)}MB
        Tests Run: ${result.totalTestsRun}
        Memory per Test: ${((memoryIncreaseMB * 1024) / result.totalTestsRun).toFixed(2)}KB`);
    }, 240000); // 240 second timeout for comprehensive mode memory testing

    it("should maintain consistent performance across multiple runs", async () => {
      // Arrange
      const config = createMockAssessmentConfig();
      const orchestrator = new AssessmentOrchestrator(config);

      const consistentTools: Tool[] = [
        createMockTool({ name: "consistent-tool-1" }),
        createMockTool({ name: "consistent-tool-2" }),
        createMockTool({ name: "consistent-tool-3" }),
      ];

      const mockCallTool = jest.fn().mockImplementation(() => {
        const delay = 15 + Math.random() * 10; // 15-25ms consistent range
        return new Promise((resolve) => {
          setTimeout(() => {
            resolve(createMockCallToolResponse("consistent response", false));
          }, delay);
        });
      });

      const runCount = 5;
      const executionTimes: number[] = [];
      const testCounts: number[] = [];

      // Act - Multiple runs
      for (let i = 0; i < runCount; i++) {
        const startTime = performance.now();

        const mockContext = {
          serverName: `consistency-test-${i}`,
          tools: consistentTools,
          callTool: mockCallTool,
          config,
        };

        const result = await orchestrator.runFullAssessment(mockContext);

        const endTime = performance.now();
        const executionTime = endTime - startTime;

        executionTimes.push(executionTime);
        testCounts.push(result.totalTestsRun);
      }

      // Assert consistency
      const avgExecutionTime =
        executionTimes.reduce((sum, time) => sum + time, 0) / runCount;
      const avgTestCount =
        testCounts.reduce((sum, count) => sum + count, 0) / runCount;

      // Calculate coefficient of variation (standard deviation / mean)
      const executionTimeVariance =
        executionTimes.reduce(
          (sum, time) => sum + Math.pow(time - avgExecutionTime, 2),
          0,
        ) / runCount;
      const executionTimeStdDev = Math.sqrt(executionTimeVariance);
      const executionTimeCv = executionTimeStdDev / avgExecutionTime;

      const testCountVariance =
        testCounts.reduce(
          (sum, count) => sum + Math.pow(count - avgTestCount, 2),
          0,
        ) / runCount;
      const testCountStdDev = Math.sqrt(testCountVariance);
      const testCountCv = testCountStdDev / avgTestCount;

      // Performance should be consistent (CV < 20%)
      expect(executionTimeCv).toBeLessThan(0.2);
      expect(testCountCv).toBeLessThan(0.1); // Test count should be very consistent

      // All runs should complete within reasonable time
      executionTimes.forEach((time) => {
        expect(time).toBeLessThan(avgExecutionTime * 1.5);
        expect(time).toBeGreaterThan(avgExecutionTime * 0.5);
      });

      console.log(`Consistency Analysis (${runCount} runs):
        Avg Execution Time: ${avgExecutionTime.toFixed(2)}ms (CV: ${(executionTimeCv * 100).toFixed(2)}%)
        Avg Test Count: ${avgTestCount.toFixed(0)} (CV: ${(testCountCv * 100).toFixed(2)}%)
        Time Range: ${Math.min(...executionTimes).toFixed(2)}ms - ${Math.max(...executionTimes).toFixed(2)}ms`);
    }, 240000); // 240 second timeout for multiple comprehensive mode runs
  });

  describe("Stress Testing", () => {
    it("should handle stress conditions gracefully", async () => {
      // Arrange
      const stressConfig = createMockAssessmentConfig();
      stressConfig.testTimeout = 1000; // Shorter timeout for stress test
      stressConfig.parallelTesting = true;
      stressConfig.maxParallelTests = 20; // High parallelism

      const orchestrator = new AssessmentOrchestrator(stressConfig);

      // Create many tools with complex schemas
      const stressTools: Tool[] = [];
      for (let i = 0; i < 50; i++) {
        stressTools.push(
          createMockTool({
            name: `stress-tool-${i}`,
            description: `Stress testing tool ${i} with complex functionality`,
            inputSchema: {
              type: "object",
              properties: {
                param1: { type: "string", enum: ["a", "b", "c"] },
                param2: { type: "number", minimum: 0, maximum: 100 },
                param3: { type: "array", items: { type: "string" } },
                param4: { type: "object", additionalProperties: true },
              },
            },
          }),
        );
      }

      const stressCallTool = jest
        .fn()
        .mockImplementation((_name: string, _params: any) => {
          // Simulate varying load conditions
          const complexity = Math.random();
          let delay: number;

          if (complexity < 0.1) {
            // 10% very slow responses (simulating external API calls)
            delay = 200 + Math.random() * 300;
          } else if (complexity < 0.3) {
            // 20% medium responses
            delay = 50 + Math.random() * 100;
          } else {
            // 70% fast responses
            delay = 5 + Math.random() * 20;
          }

          return new Promise((resolve, reject) => {
            setTimeout(() => {
              // Occasionally fail to simulate real-world conditions
              if (Math.random() < 0.05) {
                // 5% failure rate
                reject(new Error(`Stress-induced failure in ${name}`));
              } else {
                resolve(
                  createMockCallToolResponse(
                    `Stress response from ${name}`,
                    false,
                  ),
                );
              }
            }, delay);
          });
        });

      const startTime = performance.now();
      const initialMemory = process.memoryUsage();

      // Act
      const mockContext = {
        serverName: "stress-test-server",
        tools: stressTools,
        callTool: stressCallTool,
        config: DEFAULT_ASSESSMENT_CONFIG,
      };

      const result = await orchestrator.runFullAssessment(mockContext);

      const endTime = performance.now();
      const finalMemory = process.memoryUsage();
      const executionTime = endTime - startTime;

      // Assert resilience under stress
      expect(result).toBeDefined();
      expect(result.overallStatus).toBeDefined();
      expect(executionTime).toBeLessThan(60000); // Should complete within 60 seconds on CI runners

      // Should handle failures gracefully (5% random failure rate means 0-5 failures typically)
      // Verify all tools are accounted for (working + broken = total)
      expect(
        result.functionality.brokenTools.length +
          result.functionality.workingTools,
      ).toBe(result.functionality.totalTools);
      expect(result.functionality.workingTools).toBeGreaterThan(30); // Most should work

      const memoryIncreaseMB =
        (finalMemory.heapUsed - initialMemory.heapUsed) / 1024 / 1024;
      expect(memoryIncreaseMB).toBeLessThan(300); // Should not consume excessive memory

      const throughput = (result.totalTestsRun / executionTime) * 1000;
      expect(throughput).toBeGreaterThan(2); // Should maintain some throughput under stress

      console.log(`Stress Test Results:
        Execution Time: ${executionTime.toFixed(2)}ms
        Total Tests: ${result.totalTestsRun}
        Working Tools: ${result.functionality.workingTools}/${result.functionality.totalTools}
        Broken Tools: ${result.functionality.brokenTools.length}
        Throughput: ${throughput.toFixed(2)} tests/sec
        Memory Increase: ${memoryIncreaseMB.toFixed(2)}MB`);
    }, 240000); // 240 second timeout for stress testing in comprehensive mode

    it("should handle explicit tool failures correctly (deterministic failure injection)", async () => {
      // This test uses deterministic failures instead of random chance
      // to explicitly verify failure handling works correctly
      const config = createMockAssessmentConfig();
      const orchestrator = new AssessmentOrchestrator(config);

      const failingTools: Tool[] = [
        createMockTool({ name: "always_fail_1" }),
        createMockTool({ name: "always_fail_2" }),
        createMockTool({ name: "working_tool_1" }),
        createMockTool({ name: "working_tool_2" }),
      ];

      const mockCallTool = jest.fn().mockImplementation((name: string) => {
        // First two tools always fail deterministically
        if (name.startsWith("always_fail")) {
          throw new Error(`Intentional failure for ${name}`);
        }
        return Promise.resolve(
          createMockCallToolResponse(`Success from ${name}`, false),
        );
      });

      const mockContext = {
        serverName: "explicit-failure-test",
        tools: failingTools,
        callTool: mockCallTool,
        config,
      };

      const result = await orchestrator.runFullAssessment(mockContext);

      // Explicit assertions - these MUST detect the failures
      expect(result.functionality.brokenTools.length).toBe(2);
      expect(result.functionality.brokenTools).toContain("always_fail_1");
      expect(result.functionality.brokenTools).toContain("always_fail_2");
      expect(result.functionality.workingTools).toBe(2);
      // Verify accounting: broken + working = total
      expect(
        result.functionality.brokenTools.length +
          result.functionality.workingTools,
      ).toBe(result.functionality.totalTools);
    }, 30000);
  });
});
