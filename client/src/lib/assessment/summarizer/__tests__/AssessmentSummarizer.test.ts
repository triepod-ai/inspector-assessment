/**
 * Assessment Summarizer Unit Tests
 *
 * Tests for executive summary and tool summary generation.
 * Issue #136: Tiered output strategy for large assessments
 */

// Jest test file
import { AssessmentSummarizer } from "../AssessmentSummarizer";
import type { MCPDirectoryAssessment } from "../../resultTypes";

// Helper to create mock assessment results
function createMockResults(
  overrides: Partial<MCPDirectoryAssessment> = {},
): MCPDirectoryAssessment {
  return {
    serverName: "test-server",
    overallStatus: "PASS",
    summary: "Test summary",
    recommendations: ["Recommendation 1", "Recommendation 2"],
    totalTestsRun: 100,
    executionTime: 5000,
    functionality: {
      totalTools: 3,
      testedTools: 3,
      workingTools: 3,
      brokenTools: [],
      coveragePercentage: 100,
      status: "PASS",
      explanation: "All tools working",
      toolResults: [
        { toolName: "tool1", tested: true, status: "working" },
        { toolName: "tool2", tested: true, status: "working" },
        { toolName: "tool3", tested: true, status: "working" },
      ],
    },
    security: {
      promptInjectionTests: [
        {
          testName: "command_injection",
          description: "Command injection test",
          payload: "test; rm -rf",
          vulnerable: true,
          riskLevel: "HIGH",
          toolName: "tool1",
        },
        {
          testName: "sql_injection",
          description: "SQL injection test",
          payload: "'; DROP TABLE",
          vulnerable: false,
          riskLevel: "HIGH",
          toolName: "tool1",
        },
        {
          testName: "command_injection",
          description: "Command injection test",
          payload: "test; rm -rf",
          vulnerable: false,
          riskLevel: "HIGH",
          toolName: "tool2",
        },
        {
          testName: "command_injection",
          description: "Command injection test",
          payload: "test; rm -rf",
          vulnerable: false,
          riskLevel: "HIGH",
          toolName: "tool3",
        },
      ],
      vulnerabilities: ["Command injection in tool1"],
      overallRiskLevel: "HIGH",
      status: "FAIL",
      explanation: "Vulnerabilities found",
    },
    errorHandling: {
      metrics: {
        totalErrorCases: 10,
        totalCompliant: 8,
        mcpComplianceScore: 80,
        toolsWithMissingErrorCode: [],
        toolsWithNonJsonRpcCompliant: [],
        toolsWithJsonParseErrors: [],
        rawResults: [],
      },
      status: "PASS",
      score: 80,
      explanation: "Good error handling",
      recommendations: ["Improve error messages"],
    },
    aupCompliance: {
      violations: [],
      highRiskDomains: [],
      scannedLocations: {
        toolNames: true,
        toolDescriptions: true,
        readme: false,
        sourceCode: false,
      },
      status: "PASS",
      explanation: "No violations",
      recommendations: [],
    },
    toolAnnotations: {
      toolResults: [
        {
          toolName: "tool1",
          annotations: { readOnlyHint: false, destructiveHint: true },
          alignmentStatus: "ALIGNED",
          explanation: "Correctly annotated",
          inferredBehavior: {
            name: "tool1",
            isReadOnly: false,
            isDestructive: true,
          },
        },
        {
          toolName: "tool2",
          annotations: {},
          alignmentStatus: "UNKNOWN",
          explanation: "Missing annotations",
          inferredBehavior: {
            name: "tool2",
            isReadOnly: true,
            isDestructive: false,
          },
        },
        {
          toolName: "tool3",
          annotations: { readOnlyHint: true, destructiveHint: false },
          alignmentStatus: "MISALIGNED",
          explanation: "Annotations don't match behavior",
          inferredBehavior: {
            name: "tool3",
            isReadOnly: false,
            isDestructive: true,
          },
        },
      ],
      annotatedCount: 2,
      missingAnnotationsCount: 1,
      misalignedAnnotationsCount: 1,
      status: "FAIL",
      explanation: "Annotation issues",
      recommendations: ["Add annotations to tool2"],
    },
    ...overrides,
  } as MCPDirectoryAssessment;
}

describe("AssessmentSummarizer", () => {
  describe("generateExecutiveSummary", () => {
    it("should generate executive summary with all required fields", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const summary = summarizer.generateExecutiveSummary(results);

      expect(summary.serverName).toBe("test-server");
      expect(summary.overallStatus).toBe("PASS");
      expect(summary.toolCount).toBe(3);
      expect(summary.testCount).toBe(100);
      expect(summary.executionTime).toBe(5000);
      expect(summary.estimatedTokens).toBeGreaterThan(0);
      expect(summary.generatedAt).toBeDefined();
    });

    it("should calculate overall score from module scores", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const summary = summarizer.generateExecutiveSummary(results);

      // Score should be calculated from core modules
      expect(summary.overallScore).toBeGreaterThanOrEqual(0);
      expect(summary.overallScore).toBeLessThanOrEqual(100);
    });

    it("should extract critical findings", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const summary = summarizer.generateExecutiveSummary(results);

      expect(summary.criticalFindings.securityVulnerabilities).toBe(1);
      expect(summary.criticalFindings.aupViolations).toBe(0);
      expect(summary.criticalFindings.brokenTools).toBe(0);
      expect(summary.criticalFindings.missingAnnotations).toBe(1);
    });

    it("should calculate tool risk distribution", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const summary = summarizer.generateExecutiveSummary(results);

      // Based on mock data: tool1 has 1 vuln (LOW), tool2 and tool3 have 0 (SAFE)
      expect(summary.toolRiskDistribution.low).toBe(1);
      expect(summary.toolRiskDistribution.safe).toBe(2);
      expect(summary.toolRiskDistribution.high).toBe(0);
      expect(summary.toolRiskDistribution.medium).toBe(0);
    });

    it("should extract modules summary", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const summary = summarizer.generateExecutiveSummary(results);

      expect(summary.modulesSummary).toHaveProperty("functionality");
      expect(summary.modulesSummary).toHaveProperty("security");
      expect(summary.modulesSummary.functionality.status).toBe("PASS");
      expect(summary.modulesSummary.security.status).toBe("FAIL");
    });

    it("should aggregate recommendations", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const summary = summarizer.generateExecutiveSummary(results);

      expect(summary.recommendations.length).toBeGreaterThan(0);
      expect(summary.recommendations).toContain("Recommendation 1");
    });

    it("should respect maxRecommendations config", () => {
      const summarizer = new AssessmentSummarizer({ maxRecommendations: 1 });
      const results = createMockResults();

      const summary = summarizer.generateExecutiveSummary(results);

      expect(summary.recommendations.length).toBeLessThanOrEqual(1);
    });
  });

  describe("generateToolSummaries", () => {
    it("should generate summaries for all tools", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const collection = summarizer.generateToolSummaries(results);

      expect(collection.totalTools).toBe(3);
      expect(collection.tools.length).toBe(3);
      expect(collection.estimatedTokens).toBeGreaterThan(0);
    });

    it("should sort tools by risk level (highest first)", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const collection = summarizer.generateToolSummaries(results);

      // tool1 has vulnerability (LOW risk), should come before SAFE tools
      const riskLevels = collection.tools.map((t) => t.riskLevel);
      const riskOrder = { HIGH: 0, MEDIUM: 1, LOW: 2, SAFE: 3 };

      for (let i = 0; i < riskLevels.length - 1; i++) {
        expect(riskOrder[riskLevels[i]]).toBeLessThanOrEqual(
          riskOrder[riskLevels[i + 1]],
        );
      }
    });

    it("should calculate vulnerability count per tool", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const collection = summarizer.generateToolSummaries(results);

      const tool1 = collection.tools.find((t) => t.toolName === "tool1");
      expect(tool1?.vulnerabilityCount).toBe(1);

      const tool2 = collection.tools.find((t) => t.toolName === "tool2");
      expect(tool2?.vulnerabilityCount).toBe(0);
    });

    it("should extract top patterns", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const collection = summarizer.generateToolSummaries(results);

      const tool1 = collection.tools.find((t) => t.toolName === "tool1");
      expect(tool1?.topPatterns).toContain("command_injection");
    });

    it("should calculate pass rate", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const collection = summarizer.generateToolSummaries(results);

      const tool1 = collection.tools.find((t) => t.toolName === "tool1");
      // tool1: 1 vulnerable, 1 not vulnerable = 50% pass rate
      expect(tool1?.passRate).toBe(50);
    });

    it("should include annotation status", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const collection = summarizer.generateToolSummaries(results);

      const tool1 = collection.tools.find((t) => t.toolName === "tool1");
      expect(tool1?.hasAnnotations).toBe(true);
      expect(tool1?.annotationStatus).toBe("ALIGNED");

      const tool2 = collection.tools.find((t) => t.toolName === "tool2");
      expect(tool2?.hasAnnotations).toBe(false);
      expect(tool2?.annotationStatus).toBe("MISSING");

      const tool3 = collection.tools.find((t) => t.toolName === "tool3");
      expect(tool3?.hasAnnotations).toBe(true);
      expect(tool3?.annotationStatus).toBe("MISALIGNED");
    });

    it("should calculate aggregate statistics", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const collection = summarizer.generateToolSummaries(results);

      expect(collection.aggregate.totalVulnerabilities).toBe(1);
      expect(collection.aggregate.misalignedAnnotations).toBe(1);
      expect(collection.aggregate.averagePassRate).toBeGreaterThanOrEqual(0);
    });
  });

  describe("extractToolDetail", () => {
    it("should extract full detail for a tool", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const detail = summarizer.extractToolDetail("tool1", results);

      expect(detail.toolName).toBe("tool1");
      expect(detail.security).toBeDefined();
      expect(detail.functionality).toBeDefined();
      expect(detail.annotations).toBeDefined();
      expect(detail.estimatedTokens).toBeGreaterThan(0);
    });

    it("should include security tests for the tool", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const detail = summarizer.extractToolDetail("tool1", results);

      const security = detail.security as {
        tests: unknown[];
        vulnerableCount: number;
      };
      expect(security.tests.length).toBe(2);
      expect(security.vulnerableCount).toBe(1);
    });
  });

  describe("getAllToolNames", () => {
    it("should return all unique tool names", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const names = summarizer.getAllToolNames(results);

      expect(names).toContain("tool1");
      expect(names).toContain("tool2");
      expect(names).toContain("tool3");
      expect(names.length).toBe(3);
    });

    it("should return sorted tool names", () => {
      const summarizer = new AssessmentSummarizer();
      const results = createMockResults();

      const names = summarizer.getAllToolNames(results);

      expect(names).toEqual([...names].sort());
    });
  });
});
