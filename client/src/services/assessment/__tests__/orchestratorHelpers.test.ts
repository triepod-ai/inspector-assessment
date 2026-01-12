/**
 * Orchestrator Helpers Unit Tests
 *
 * Tests for pure functions extracted from AssessmentOrchestrator:
 * - buildAUPEnrichment: AUP violation sampling by severity
 * - determineOverallStatus: Status aggregation logic
 * - generateSummary: Summary text generation
 * - generateRecommendations: Recommendation deduplication
 */

import {
  buildAUPEnrichment,
  determineOverallStatus,
  generateSummary,
  generateRecommendations,
} from "../orchestratorHelpers";
import type { MCPDirectoryAssessment } from "@/lib/assessmentTypes";

// Helper to create partial assessment results for testing
const asPartialResults = (obj: Record<string, unknown>) =>
  obj as unknown as Partial<MCPDirectoryAssessment>;

describe("buildAUPEnrichment", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("empty/minimal results", () => {
    it("should return empty sample when no violations", () => {
      const result = buildAUPEnrichment({ violations: [] });

      expect(result.violationsSample).toHaveLength(0);
      expect(result.samplingNote).toBe("No violations detected.");
      expect(result.violationMetrics.total).toBe(0);
      expect(result.violationMetrics.critical).toBe(0);
      expect(result.violationMetrics.high).toBe(0);
      expect(result.violationMetrics.medium).toBe(0);
    });

    it("should handle missing violations array", () => {
      const result = buildAUPEnrichment({});

      expect(result.violationsSample).toHaveLength(0);
      expect(result.samplingNote).toBe("No violations detected.");
    });
  });

  describe("severity prioritization", () => {
    it("should sample CRITICAL violations first", () => {
      const result = buildAUPEnrichment(
        {
          violations: [
            { severity: "MEDIUM", category: "cat1" },
            { severity: "CRITICAL", category: "cat2" },
            { severity: "HIGH", category: "cat3" },
          ],
        },
        2,
      );

      expect(result.violationsSample[0].severity).toBe("CRITICAL");
      expect(result.violationsSample[1].severity).toBe("HIGH");
    });

    it("should sample HIGH after CRITICAL violations", () => {
      const result = buildAUPEnrichment(
        {
          violations: [
            { severity: "HIGH", category: "cat1" },
            { severity: "CRITICAL", category: "cat2" },
            { severity: "HIGH", category: "cat3" },
            { severity: "MEDIUM", category: "cat4" },
          ],
        },
        3,
      );

      expect(result.violationsSample[0].severity).toBe("CRITICAL");
      expect(result.violationsSample[1].severity).toBe("HIGH");
      expect(result.violationsSample[2].severity).toBe("HIGH");
    });

    it("should sample MEDIUM after HIGH when no more HIGH available", () => {
      const result = buildAUPEnrichment(
        {
          violations: [
            { severity: "MEDIUM", category: "cat1" },
            { severity: "MEDIUM", category: "cat2" },
            { severity: "HIGH", category: "cat3" },
          ],
        },
        3,
      );

      expect(result.violationsSample[0].severity).toBe("HIGH");
      expect(result.violationsSample[1].severity).toBe("MEDIUM");
      expect(result.violationsSample[2].severity).toBe("MEDIUM");
    });
  });

  describe("sample limits", () => {
    it("should limit samples to maxSamples parameter", () => {
      const violations = Array(20)
        .fill(null)
        .map((_, i) => ({
          severity: "HIGH",
          category: `cat${i}`,
        }));

      const result = buildAUPEnrichment({ violations }, 5);

      expect(result.violationsSample).toHaveLength(5);
      expect(result.samplingNote).toContain("Sampled 5 of 20");
    });

    it("should include all violations when under maxSamples", () => {
      const violations = [
        { severity: "CRITICAL", category: "cat1" },
        { severity: "HIGH", category: "cat2" },
        { severity: "MEDIUM", category: "cat3" },
      ];

      const result = buildAUPEnrichment({ violations }, 10);

      expect(result.violationsSample).toHaveLength(3);
      expect(result.samplingNote).toBe("All 3 violation(s) included.");
    });

    it("should use default maxSamples of 10", () => {
      const violations = Array(15)
        .fill(null)
        .map((_, i) => ({
          severity: "MEDIUM",
          category: `cat${i}`,
        }));

      const result = buildAUPEnrichment({ violations });

      expect(result.violationsSample).toHaveLength(10);
    });
  });

  describe("metrics calculation", () => {
    it("should calculate correct violation metrics", () => {
      const result = buildAUPEnrichment({
        violations: [
          { severity: "CRITICAL", category: "cat1" },
          { severity: "CRITICAL", category: "cat2" },
          { severity: "HIGH", category: "cat3" },
          { severity: "MEDIUM", category: "cat4" },
          { severity: "MEDIUM", category: "cat5" },
          { severity: "MEDIUM", category: "cat6" },
        ],
      });

      expect(result.violationMetrics.total).toBe(6);
      expect(result.violationMetrics.critical).toBe(2);
      expect(result.violationMetrics.high).toBe(1);
      expect(result.violationMetrics.medium).toBe(3);
    });

    it("should count violations by category", () => {
      const result = buildAUPEnrichment({
        violations: [
          { severity: "HIGH", category: "weapons" },
          { severity: "HIGH", category: "weapons" },
          { severity: "MEDIUM", category: "privacy" },
          { severity: "CRITICAL", category: "malware" },
        ],
      });

      expect(result.violationMetrics.byCategory["weapons"]).toBe(2);
      expect(result.violationMetrics.byCategory["privacy"]).toBe(1);
      expect(result.violationMetrics.byCategory["malware"]).toBe(1);
    });
  });

  describe("additional fields", () => {
    it("should preserve highRiskDomains (limited to 10)", () => {
      const domains = Array(15)
        .fill(null)
        .map((_, i) => `domain${i}.com`);

      const result = buildAUPEnrichment({
        violations: [],
        highRiskDomains: domains,
      });

      expect(result.highRiskDomains).toHaveLength(10);
      expect(result.highRiskDomains[0]).toBe("domain0.com");
    });

    it("should include scannedLocations from result", () => {
      const result = buildAUPEnrichment({
        violations: [],
        scannedLocations: {
          toolNames: true,
          toolDescriptions: true,
          readme: false,
          sourceCode: true,
        },
      });

      expect(result.scannedLocations.toolNames).toBe(true);
      expect(result.scannedLocations.toolDescriptions).toBe(true);
      expect(result.scannedLocations.readme).toBe(false);
      expect(result.scannedLocations.sourceCode).toBe(true);
    });

    it("should provide default scannedLocations when not present", () => {
      const result = buildAUPEnrichment({ violations: [] });

      expect(result.scannedLocations).toEqual({
        toolNames: false,
        toolDescriptions: false,
        readme: false,
        sourceCode: false,
      });
    });

    it("should provide empty highRiskDomains when not present", () => {
      const result = buildAUPEnrichment({ violations: [] });

      expect(result.highRiskDomains).toEqual([]);
    });
  });
});

describe("determineOverallStatus", () => {
  it("should return FAIL if any module fails", () => {
    const results = asPartialResults({
      functionality: { status: "PASS" },
      security: { status: "FAIL" },
      documentation: { status: "PASS" },
    });

    expect(determineOverallStatus(results)).toBe("FAIL");
  });

  it("should return NEED_MORE_INFO if any module needs info (no failures)", () => {
    const results = asPartialResults({
      functionality: { status: "PASS" },
      security: { status: "NEED_MORE_INFO" },
      documentation: { status: "PASS" },
    });

    expect(determineOverallStatus(results)).toBe("NEED_MORE_INFO");
  });

  it("should return PASS only when all modules pass", () => {
    const results = asPartialResults({
      functionality: { status: "PASS" },
      security: { status: "PASS" },
      documentation: { status: "PASS" },
    });

    expect(determineOverallStatus(results)).toBe("PASS");
  });

  it("should prioritize FAIL over NEED_MORE_INFO", () => {
    const results = asPartialResults({
      functionality: { status: "NEED_MORE_INFO" },
      security: { status: "FAIL" },
      documentation: { status: "PASS" },
    });

    expect(determineOverallStatus(results)).toBe("FAIL");
  });

  it("should handle empty results", () => {
    expect(determineOverallStatus(asPartialResults({}))).toBe("PASS");
  });

  it("should ignore non-assessment objects in results", () => {
    const results = asPartialResults({
      functionality: { status: "PASS" },
      serverName: "test-server",
      executionTime: 1234,
    });

    expect(determineOverallStatus(results)).toBe("PASS");
  });
});

describe("generateSummary", () => {
  it("should include category pass count", () => {
    const results = asPartialResults({
      functionality: { status: "PASS" },
      security: { status: "PASS" },
      documentation: { status: "FAIL" },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("2/3 categories passed");
  });

  it("should include security vulnerability count", () => {
    const results = asPartialResults({
      security: {
        status: "FAIL",
        vulnerabilities: ["vuln1", "vuln2", "vuln3"],
      },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("Found 3 security vulnerabilities");
  });

  it("should include broken tools count", () => {
    const results = asPartialResults({
      functionality: {
        status: "FAIL",
        brokenTools: ["tool1", "tool2"],
      },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("2 tools are not functioning correctly");
  });

  it("should include AUP critical violations", () => {
    const results = asPartialResults({
      aupCompliance: {
        status: "FAIL",
        violations: [
          { severity: "CRITICAL" },
          { severity: "CRITICAL" },
          { severity: "HIGH" },
        ],
      },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("CRITICAL: 2 AUP violation(s) detected");
  });

  it("should include non-critical AUP violations", () => {
    const results = asPartialResults({
      aupCompliance: {
        status: "PASS",
        violations: [{ severity: "MEDIUM" }, { severity: "HIGH" }],
      },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("2 AUP item(s) flagged for review");
  });

  it("should include missing annotations count", () => {
    const results = asPartialResults({
      toolAnnotations: {
        status: "FAIL",
        missingAnnotationsCount: 5,
      },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("5 tools missing annotations");
  });

  it("should include blocked libraries warning", () => {
    const results = asPartialResults({
      prohibitedLibraries: {
        status: "FAIL",
        matches: [
          { severity: "BLOCKING" },
          { severity: "BLOCKING" },
          { severity: "WARNING" },
        ],
      },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("BLOCKING: 2 prohibited library/libraries");
  });

  it("should include BUNDLE_ROOT anti-pattern warning", () => {
    const results = asPartialResults({
      portability: {
        status: "FAIL",
        usesBundleRoot: true,
      },
    });

    const summary = generateSummary(results);

    expect(summary).toContain("${BUNDLE_ROOT} anti-pattern");
  });

  it("should handle results with no findings", () => {
    const results = asPartialResults({
      functionality: { status: "PASS" },
      security: { status: "PASS", vulnerabilities: [] },
    });

    const summary = generateSummary(results);

    expect(summary).toBe("Assessment complete: 2/2 categories passed.");
  });
});

describe("generateRecommendations", () => {
  it("should aggregate recommendations from all assessments", () => {
    const results = asPartialResults({
      functionality: {
        status: "PASS",
        recommendations: ["rec1", "rec2"],
      },
      security: {
        status: "PASS",
        recommendations: ["rec3"],
      },
    });

    const recs = generateRecommendations(results);

    expect(recs).toContain("rec1");
    expect(recs).toContain("rec2");
    expect(recs).toContain("rec3");
    expect(recs).toHaveLength(3);
  });

  it("should deduplicate recommendations", () => {
    const results = asPartialResults({
      functionality: {
        status: "PASS",
        recommendations: ["same recommendation", "unique1"],
      },
      security: {
        status: "PASS",
        recommendations: ["same recommendation", "unique2"],
      },
    });

    const recs = generateRecommendations(results);

    expect(recs).toHaveLength(3);
    expect(recs.filter((r) => r === "same recommendation")).toHaveLength(1);
  });

  it("should limit to 10 recommendations", () => {
    const results = asPartialResults({
      functionality: {
        status: "PASS",
        recommendations: Array(8)
          .fill(null)
          .map((_, i) => `func-rec${i}`),
      },
      security: {
        status: "PASS",
        recommendations: Array(8)
          .fill(null)
          .map((_, i) => `sec-rec${i}`),
      },
    });

    const recs = generateRecommendations(results);

    expect(recs).toHaveLength(10);
  });

  it("should handle empty recommendations gracefully", () => {
    const results = asPartialResults({
      functionality: { status: "PASS" },
      security: { status: "PASS", recommendations: [] },
    });

    const recs = generateRecommendations(results);

    expect(recs).toEqual([]);
  });

  it("should ignore non-assessment objects", () => {
    const results = asPartialResults({
      functionality: {
        status: "PASS",
        recommendations: ["rec1"],
      },
      serverName: "test",
      executionTime: 1000,
    });

    const recs = generateRecommendations(results);

    expect(recs).toEqual(["rec1"]);
  });
});
