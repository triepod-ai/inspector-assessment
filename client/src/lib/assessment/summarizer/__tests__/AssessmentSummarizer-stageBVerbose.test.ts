/**
 * Assessment Summarizer Stage B Verbose Integration Tests
 *
 * Tests for Issue #137 Stage 3 integration test requirement (TEST-REQ-003).
 * Validates that AssessmentSummarizer correctly populates stageBEnrichment
 * field when stageBVerbose is enabled.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/137
 */

import { AssessmentSummarizer } from "../AssessmentSummarizer";
import type {
  MCPDirectoryAssessment,
  SecurityTestResult,
} from "../../resultTypes";

// Helper to create minimal assessment results
function createMockAssessment(
  overrides: Partial<MCPDirectoryAssessment> = {},
): MCPDirectoryAssessment {
  return {
    serverName: "test-server",
    overallStatus: "PASS",
    totalTestsRun: 100,
    executionTime: 1000,
    functionality: {
      totalTools: 5,
      workingTools: 5,
      brokenTools: [],
      untestableTools: [],
      enhancedResults: [
        {
          toolName: "test_tool",
          overallStatus: "PASS",
          passes: 10,
          failures: 0,
          tests: [],
          inputSchemaValid: true,
          schemaTestsPassed: 0,
          schemaTestsFailed: 0,
          schemaValidationErrors: [],
        },
      ],
    },
    security: {
      testCount: 50,
      vulnerableCount: 2,
      promptInjectionTests: [
        {
          testName: "command_injection",
          description: "Command injection test",
          payload: "test; rm -rf /",
          vulnerable: true,
          riskLevel: "HIGH",
          toolName: "test_tool",
          response: "Command executed",
          evidence: "Shell command detected",
          confidence: "high",
        },
        {
          testName: "sql_injection",
          description: "SQL injection test",
          payload: "'; DROP TABLE users;--",
          vulnerable: true,
          riskLevel: "HIGH",
          toolName: "test_tool",
          response: "SQL query result",
          evidence: "SQL pattern detected",
          confidence: "medium",
        },
        {
          testName: "safe_test",
          description: "Safe test",
          payload: "normal input",
          vulnerable: false,
          riskLevel: "LOW",
          toolName: "test_tool",
          response: "Safe execution",
          confidence: "high",
        },
      ] as SecurityTestResult[],
      vulnerabilities: [],
      riskDistribution: { CRITICAL: 0, HIGH: 2, MEDIUM: 0, LOW: 0 },
      sanitizationDetected: false,
    },
    ...overrides,
  } as MCPDirectoryAssessment;
}

describe("AssessmentSummarizer Stage B Verbose Integration Tests", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("[TEST-003] stageBVerbose field integration (TEST-REQ-003)", () => {
    describe("stageBEnrichment field population", () => {
      it("should populate stageBEnrichment when stageBVerbose=true (happy path)", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });

        const toolSummaries = summarizer.generateToolSummaries(results);

        expect(toolSummaries.tools).toHaveLength(1);
        const toolSummary = toolSummaries.tools[0];

        // Critical: stageBEnrichment field should be populated
        expect(toolSummary.stageBEnrichment).toBeDefined();
        expect(toolSummary.stageBEnrichment?.sampleEvidence).toBeDefined();
        expect(toolSummary.stageBEnrichment?.confidenceBreakdown).toBeDefined();
        expect(toolSummary.stageBEnrichment?.patternDistribution).toBeDefined();
      });

      it("should NOT populate stageBEnrichment when stageBVerbose=false (happy path)", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer({ stageBVerbose: false });

        const toolSummaries = summarizer.generateToolSummaries(results);

        expect(toolSummaries.tools).toHaveLength(1);
        const toolSummary = toolSummaries.tools[0];

        // stageBEnrichment should be undefined
        expect(toolSummary.stageBEnrichment).toBeUndefined();
      });

      it("should NOT populate stageBEnrichment by default (default config)", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer(); // No config = default

        const toolSummaries = summarizer.generateToolSummaries(results);

        expect(toolSummaries.tools).toHaveLength(1);
        const toolSummary = toolSummaries.tools[0];

        // Default config has stageBVerbose: false
        expect(toolSummary.stageBEnrichment).toBeUndefined();
      });
    });

    describe("stageBEnrichment content validation", () => {
      it("should include sample evidence when stageBVerbose=true", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });

        const toolSummaries = summarizer.generateToolSummaries(results);
        const toolSummary = toolSummaries.tools[0];

        expect(toolSummary.stageBEnrichment?.sampleEvidence).toBeDefined();
        expect(
          toolSummary.stageBEnrichment!.sampleEvidence.length,
        ).toBeGreaterThan(0);

        // Verify evidence structure
        const evidence = toolSummary.stageBEnrichment!.sampleEvidence[0];
        expect(evidence).toHaveProperty("raw");
        expect(evidence).toHaveProperty("context");
        expect(evidence).toHaveProperty("location");
      });

      it("should include confidence breakdown when stageBVerbose=true", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });

        const toolSummaries = summarizer.generateToolSummaries(results);
        const toolSummary = toolSummaries.tools[0];

        expect(toolSummary.stageBEnrichment?.confidenceBreakdown).toBeDefined();
        expect(
          toolSummary.stageBEnrichment!.confidenceBreakdown,
        ).toHaveProperty("high");
        expect(
          toolSummary.stageBEnrichment!.confidenceBreakdown,
        ).toHaveProperty("medium");
        expect(
          toolSummary.stageBEnrichment!.confidenceBreakdown,
        ).toHaveProperty("low");

        // Should have at least one vulnerable test (from mock data)
        const breakdown = toolSummary.stageBEnrichment!.confidenceBreakdown;
        expect(
          breakdown.high + breakdown.medium + breakdown.low,
        ).toBeGreaterThan(0);
      });

      it("should include pattern distribution when stageBVerbose=true", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });

        const toolSummaries = summarizer.generateToolSummaries(results);
        const toolSummary = toolSummaries.tools[0];

        expect(toolSummary.stageBEnrichment?.patternDistribution).toBeDefined();

        // Should have pattern counts from mock data
        const patterns = toolSummary.stageBEnrichment!.patternDistribution;
        expect(Object.keys(patterns).length).toBeGreaterThan(0);

        // Mock has command_injection and sql_injection
        expect(patterns).toHaveProperty("command_injection");
        expect(patterns["command_injection"]).toBe(1);
      });

      it("should include highest risk correlation when vulnerabilities exist", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });

        const toolSummaries = summarizer.generateToolSummaries(results);
        const toolSummary = toolSummaries.tools[0];

        expect(
          toolSummary.stageBEnrichment?.highestRiskCorrelation,
        ).toBeDefined();

        const correlation =
          toolSummary.stageBEnrichment!.highestRiskCorrelation!;
        expect(correlation).toHaveProperty("inputPayload");
        expect(correlation).toHaveProperty("outputResponse");
        expect(correlation).toHaveProperty("classification");
        expect(correlation.classification).toBe("vulnerable");
      });
    });

    describe("multiple tools with stageBVerbose", () => {
      it("should populate stageBEnrichment for all tools when enabled", () => {
        const results = createMockAssessment({
          functionality: {
            totalTools: 3,
            workingTools: 3,
            brokenTools: [],
            untestableTools: [],
            enhancedResults: [
              {
                toolName: "tool_1",
                overallStatus: "PASS",
                passes: 10,
                failures: 0,
                tests: [],
                inputSchemaValid: true,
                schemaTestsPassed: 0,
                schemaTestsFailed: 0,
                schemaValidationErrors: [],
              },
              {
                toolName: "tool_2",
                overallStatus: "PASS",
                passes: 10,
                failures: 0,
                tests: [],
                inputSchemaValid: true,
                schemaTestsPassed: 0,
                schemaTestsFailed: 0,
                schemaValidationErrors: [],
              },
              {
                toolName: "tool_3",
                overallStatus: "PASS",
                passes: 10,
                failures: 0,
                tests: [],
                inputSchemaValid: true,
                schemaTestsPassed: 0,
                schemaTestsFailed: 0,
                schemaValidationErrors: [],
              },
            ],
          },
          security: {
            testCount: 90,
            vulnerableCount: 6,
            promptInjectionTests: [
              // Tool 1 tests
              {
                toolName: "tool_1",
                testName: "cmd_injection",
                vulnerable: true,
                riskLevel: "HIGH",
                payload: "test1",
                response: "response1",
                evidence: "evidence1",
                confidence: "high",
              },
              {
                toolName: "tool_1",
                testName: "sql_injection",
                vulnerable: true,
                riskLevel: "HIGH",
                payload: "test2",
                response: "response2",
                evidence: "evidence2",
                confidence: "medium",
              },
              // Tool 2 tests
              {
                toolName: "tool_2",
                testName: "xss",
                vulnerable: true,
                riskLevel: "MEDIUM",
                payload: "test3",
                response: "response3",
                evidence: "evidence3",
                confidence: "high",
              },
              // Tool 3 tests (no vulnerabilities)
              {
                toolName: "tool_3",
                testName: "safe_test",
                vulnerable: false,
                riskLevel: "LOW",
                payload: "test4",
                response: "response4",
                confidence: "high",
              },
            ] as SecurityTestResult[],
            vulnerabilities: [],
            riskDistribution: { CRITICAL: 0, HIGH: 2, MEDIUM: 1, LOW: 0 },
            sanitizationDetected: false,
          },
        });

        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });
        const toolSummaries = summarizer.generateToolSummaries(results);

        expect(toolSummaries.tools).toHaveLength(3);

        // All tools should have stageBEnrichment
        for (const tool of toolSummaries.tools) {
          expect(tool.stageBEnrichment).toBeDefined();
        }

        // Verify tool-specific data
        const tool1 = toolSummaries.tools.find((t) => t.toolName === "tool_1");
        expect(tool1?.stageBEnrichment?.sampleEvidence.length).toBeGreaterThan(
          0,
        );

        const tool2 = toolSummaries.tools.find((t) => t.toolName === "tool_2");
        expect(tool2?.stageBEnrichment?.sampleEvidence.length).toBeGreaterThan(
          0,
        );

        const tool3 = toolSummaries.tools.find((t) => t.toolName === "tool_3");
        expect(tool3?.stageBEnrichment?.sampleEvidence.length).toBe(0); // No vulnerabilities
      });
    });

    describe("edge cases", () => {
      it("should handle empty security results gracefully", () => {
        const results = createMockAssessment({
          security: {
            testCount: 0,
            vulnerableCount: 0,
            promptInjectionTests: [], // Empty test array
            vulnerabilities: [],
            riskDistribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
            sanitizationDetected: false,
          },
          functionality: {
            totalTools: 1,
            workingTools: 1,
            brokenTools: [],
            untestableTools: [],
            enhancedResults: [],
            toolResults: [
              // Need at least one tool result so extractToolNames returns a tool
              {
                toolName: "test_tool",
                tests: [],
                passes: 0,
                failures: 0,
                executionTime: 0,
                averageExecutionTime: 0,
                slowestExecution: 0,
              },
            ],
          },
        });

        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });
        const toolSummaries = summarizer.generateToolSummaries(results);

        expect(toolSummaries.tools).toHaveLength(1);
        const toolSummary = toolSummaries.tools[0];

        // stageBEnrichment should still be defined but with empty data
        expect(toolSummary.stageBEnrichment).toBeDefined();
        expect(toolSummary.stageBEnrichment?.sampleEvidence).toHaveLength(0);
      });

      it("should handle tool with no security tests", () => {
        const results = createMockAssessment({
          security: {
            testCount: 10,
            vulnerableCount: 0,
            promptInjectionTests: [
              // Tests for a different tool
              {
                toolName: "other_tool",
                testName: "test",
                vulnerable: false,
                riskLevel: "LOW",
                payload: "test",
                response: "response",
                confidence: "high",
              },
            ] as SecurityTestResult[],
            vulnerabilities: [],
            riskDistribution: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
            sanitizationDetected: false,
          },
        });

        const summarizer = new AssessmentSummarizer({ stageBVerbose: true });
        const toolSummaries = summarizer.generateToolSummaries(results);

        const toolSummary = toolSummaries.tools[0];

        // Should have stageBEnrichment but with empty data
        expect(toolSummary.stageBEnrichment).toBeDefined();
        expect(toolSummary.stageBEnrichment?.sampleEvidence).toHaveLength(0);
        expect(toolSummary.stageBEnrichment?.patternDistribution).toEqual({});
      });
    });

    describe("regression prevention", () => {
      it("should maintain backward compatibility when stageBVerbose=false", () => {
        const results = createMockAssessment();
        const summarizer = new AssessmentSummarizer({ stageBVerbose: false });

        const toolSummaries = summarizer.generateToolSummaries(results);
        const toolSummary = toolSummaries.tools[0];

        // All existing fields should still be present
        expect(toolSummary).toHaveProperty("toolName");
        expect(toolSummary).toHaveProperty("riskLevel");
        expect(toolSummary).toHaveProperty("vulnerabilityCount");
        expect(toolSummary).toHaveProperty("testCount");
        expect(toolSummary).toHaveProperty("passRate");
        expect(toolSummary).toHaveProperty("recommendations");

        // But stageBEnrichment should be absent
        expect(toolSummary.stageBEnrichment).toBeUndefined();
      });

      it("should not affect token estimates when stageBVerbose=false", () => {
        const results = createMockAssessment();

        const summarizerWithoutVerbose = new AssessmentSummarizer({
          stageBVerbose: false,
        });
        const summarizerWithVerbose = new AssessmentSummarizer({
          stageBVerbose: true,
        });

        const withoutVerbose =
          summarizerWithoutVerbose.generateToolSummaries(results);
        const withVerbose =
          summarizerWithVerbose.generateToolSummaries(results);

        // Token estimate should be lower without stageBEnrichment
        expect(withoutVerbose.estimatedTokens).toBeLessThan(
          withVerbose.estimatedTokens,
        );
      });
    });
  });
});
