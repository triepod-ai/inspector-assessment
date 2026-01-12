/**
 * Stage B Enrichment Builder Unit Tests
 *
 * Tests for Stage B enrichment data generation.
 * Issue #137: Stage A data enrichment for Stage B Claude analysis
 */

import {
  buildToolSummaryStageBEnrichment,
  buildToolDetailStageBEnrichment,
} from "../stageBEnrichmentBuilder";
import type { SecurityTestResult } from "../../resultTypes";
import type { EnhancedToolAnnotationResult } from "../../../../services/assessment/modules/annotations/types";
import type { AUPViolation } from "../../extendedTypes";

// Helper to create mock security test results
function createMockSecurityTest(
  overrides: Partial<SecurityTestResult> = {},
): SecurityTestResult {
  return {
    testName: "command_injection",
    description: "Command injection test",
    payload: "test; rm -rf /",
    vulnerable: false,
    riskLevel: "HIGH",
    toolName: "test_tool",
    response: "Tool executed safely",
    confidence: "medium",
    ...overrides,
  };
}

describe("stageBEnrichmentBuilder", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("buildToolSummaryStageBEnrichment", () => {
    it("should return empty enrichment for empty tests", () => {
      const result = buildToolSummaryStageBEnrichment("test_tool", []);

      expect(result.sampleEvidence).toHaveLength(0);
      expect(result.confidenceBreakdown).toEqual({
        high: 0,
        medium: 0,
        low: 0,
      });
      expect(result.highestRiskCorrelation).toBeUndefined();
      expect(result.patternDistribution).toEqual({});
    });

    it("should extract evidence from vulnerable tests", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          payload: "malicious_payload",
          evidence: "Command executed",
          confidence: "high",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "sql_injection",
          payload: "'; DROP TABLE users;--",
          evidence: "SQL error",
          confidence: "medium",
        }),
        createMockSecurityTest({
          vulnerable: false,
          toolName: "test_tool",
          testName: "safe_test",
        }),
      ];

      const result = buildToolSummaryStageBEnrichment("test_tool", tests);

      expect(result.sampleEvidence).toHaveLength(2);
      expect(result.confidenceBreakdown).toEqual({
        high: 1,
        medium: 1,
        low: 0,
      });
      expect(result.highestRiskCorrelation).toBeDefined();
      expect(result.highestRiskCorrelation?.classification).toBe("vulnerable");
      expect(result.patternDistribution).toEqual({
        command_injection: 1,
        sql_injection: 1,
      });
    });

    it("should limit evidence samples to maxSamples", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({ vulnerable: true, toolName: "test_tool" }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "test2",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "test3",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "test4",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "test5",
        }),
      ];

      const result = buildToolSummaryStageBEnrichment("test_tool", tests, 3);

      expect(result.sampleEvidence).toHaveLength(3);
    });

    it("should detect sanitization and auth failure mode", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          toolName: "test_tool",
          vulnerable: true,
          sanitizationDetected: true,
          sanitizationLibraries: ["DOMPurify"],
        }),
        createMockSecurityTest({
          toolName: "test_tool",
          vulnerable: true,
          authFailureMode: "FAIL_OPEN",
          authBypassDetected: true,
        }),
      ];

      const result = buildToolSummaryStageBEnrichment("test_tool", tests);

      expect(result.sanitizationDetected).toBe(true);
      expect(result.authFailureMode).toBe("FAIL_OPEN");
    });

    it("should only include tests for the specified tool", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "included",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "other_tool",
          testName: "excluded",
        }),
      ];

      const result = buildToolSummaryStageBEnrichment("test_tool", tests);

      expect(result.patternDistribution).toEqual({ included: 1 });
    });

    it("should prioritize HIGH risk tests for highest risk correlation", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          riskLevel: "LOW",
          testName: "low_risk",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          riskLevel: "CRITICAL",
          testName: "critical_risk",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          riskLevel: "MEDIUM",
          testName: "medium_risk",
        }),
      ];

      const result = buildToolSummaryStageBEnrichment("test_tool", tests);

      expect(result.highestRiskCorrelation?.testName).toBe("critical_risk");
    });
  });

  describe("buildToolDetailStageBEnrichment", () => {
    it("should return comprehensive enrichment for tests", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          payload: "test_payload",
          response: "test_response",
          evidence: "test_evidence",
          confidence: "high",
        }),
        createMockSecurityTest({
          vulnerable: false,
          toolName: "test_tool",
          payload: "safe_payload",
          response: "safe_response",
        }),
        createMockSecurityTest({
          vulnerable: false,
          toolName: "test_tool",
          connectionError: true,
          errorType: "connection",
        }),
      ];

      const result = buildToolDetailStageBEnrichment("test_tool", tests);

      expect(result.payloadCorrelations).toHaveLength(3);
      expect(result.securityDetails.vulnerableCount).toBe(1);
      expect(result.securityDetails.safeCount).toBe(1);
      expect(result.securityDetails.errorCount).toBe(1);
      expect(result.confidenceDetails.overall).toBeGreaterThan(0);
    });

    it("should limit correlations to maxCorrelations", () => {
      const tests: SecurityTestResult[] = Array.from({ length: 100 }, (_, i) =>
        createMockSecurityTest({
          toolName: "test_tool",
          testName: `test_${i}`,
        }),
      );

      const result = buildToolDetailStageBEnrichment(
        "test_tool",
        tests,
        undefined,
        undefined,
        10,
      );

      expect(result.payloadCorrelations.length).toBeLessThanOrEqual(10);
    });

    it("should include annotation details when provided", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({ vulnerable: true, toolName: "test_tool" }),
      ];

      const annotationResult: Partial<EnhancedToolAnnotationResult> = {
        toolName: "test_tool",
        hasAnnotations: true,
        alignmentStatus: "ALIGNED",
        inferredBehavior: {
          expectedReadOnly: true,
          expectedDestructive: false,
          reason: "Name pattern match",
          confidence: "high",
          isAmbiguous: false,
        },
        descriptionPoisoning: {
          detected: true,
          patterns: [
            {
              name: "hidden_instruction",
              pattern: "<hidden>",
              evidence: "Found hidden tag",
              severity: "HIGH",
              category: "injection",
            },
          ],
          riskLevel: "HIGH",
        },
      };

      const result = buildToolDetailStageBEnrichment(
        "test_tool",
        tests,
        annotationResult as EnhancedToolAnnotationResult,
      );

      expect(result.annotationDetails).toBeDefined();
      expect(result.annotationDetails?.hasAnnotations).toBe(true);
      expect(result.annotationDetails?.alignmentStatus).toBe("ALIGNED");
      expect(result.annotationDetails?.inferredBehavior?.expectedReadOnly).toBe(
        true,
      );
      expect(result.annotationDetails?.descriptionPoisoning?.detected).toBe(
        true,
      );
      expect(
        result.annotationDetails?.descriptionPoisoning?.patterns,
      ).toHaveLength(1);
    });

    it("should include AUP violations for the tool", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({ toolName: "test_tool" }),
      ];

      const aupViolations: AUPViolation[] = [
        {
          pattern: "malware",
          matchedText: "virus_creator",
          severity: "CRITICAL",
          location: "test_tool description",
          category: "AUP_MALWARE",
        },
        {
          pattern: "harassment",
          matchedText: "target_user",
          severity: "HIGH",
          location: "other_tool description",
          category: "AUP_HARASSMENT",
        },
      ];

      const result = buildToolDetailStageBEnrichment(
        "test_tool",
        tests,
        undefined,
        aupViolations,
      );

      expect(result.aupViolations).toHaveLength(1);
      expect(result.aupViolations?.[0].pattern).toBe("malware");
    });

    it("should collect sanitization libraries", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          toolName: "test_tool",
          sanitizationDetected: true,
          sanitizationLibraries: ["DOMPurify"],
        }),
        createMockSecurityTest({
          toolName: "test_tool",
          sanitizationDetected: true,
          sanitizationLibraries: ["sanitize-html", "DOMPurify"],
        }),
      ];

      const result = buildToolDetailStageBEnrichment("test_tool", tests);

      expect(result.securityDetails.sanitizationLibraries).toContain(
        "DOMPurify",
      );
      expect(result.securityDetails.sanitizationLibraries).toContain(
        "sanitize-html",
      );
      // Should be deduplicated
      expect(result.securityDetails.sanitizationLibraries).toHaveLength(2);
    });

    it("should include auth bypass evidence when detected", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          toolName: "test_tool",
          authBypassDetected: true,
          authBypassEvidence: "Token not validated",
        }),
      ];

      const result = buildToolDetailStageBEnrichment("test_tool", tests);

      expect(result.securityDetails.authBypassEvidence).toBe(
        "Token not validated",
      );
    });

    it("should build context windows from evidence", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "test1",
          payload: "payload1",
          evidence: "Evidence text for test 1",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          testName: "test2",
          payload: "payload2",
          evidence: "Evidence text for test 2",
        }),
      ];

      const result = buildToolDetailStageBEnrichment("test_tool", tests);

      // Should have context windows for vulnerable tests with evidence
      expect(Object.keys(result.contextWindows).length).toBeGreaterThan(0);
    });

    it("should calculate confidence correctly", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          confidence: "high",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          confidence: "high",
        }),
        createMockSecurityTest({
          vulnerable: true,
          toolName: "test_tool",
          confidence: "low",
        }),
      ];

      const result = buildToolDetailStageBEnrichment("test_tool", tests);

      // 2 high (100%) + 1 low (40%) = 240/3 = 80%
      expect(result.confidenceDetails.overall).toBe(80);
    });

    it("should track manual review requirements", () => {
      const tests: SecurityTestResult[] = [
        createMockSecurityTest({
          toolName: "test_tool",
          requiresManualReview: true,
          manualReviewReason: "Uncertain response",
        }),
        createMockSecurityTest({
          toolName: "test_tool",
          requiresManualReview: true,
        }),
        createMockSecurityTest({
          toolName: "test_tool",
          requiresManualReview: false,
        }),
      ];

      const result = buildToolDetailStageBEnrichment("test_tool", tests);

      expect(result.confidenceDetails.requiresManualReview).toBe(2);
    });
  });
});
