/**
 * Stage B Enrichment Builder Fix Validation Tests
 *
 * Tests for Issue #137 Stage 3 FIX-002 (testToEvidence semantic consistency).
 * Validates that the location and context fields consistently prioritize
 * evidence over response.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/137
 */

import {
  buildToolSummaryStageBEnrichment,
  buildToolDetailStageBEnrichment,
} from "../stageBEnrichmentBuilder";
import type { SecurityTestResult } from "../../resultTypes";

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

describe("stageBEnrichmentBuilder Fix Validation Tests", () => {
  describe("[TEST-002] testToEvidence semantic consistency (FIX-002)", () => {
    describe("evidence and location field consistency", () => {
      it("should use response for both location and context when test has response only (happy path)", () => {
        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            payload: "malicious_payload",
            response: "Command executed: /bin/sh",
            // evidence: undefined (no evidence field)
          }),
        ];

        const result = buildToolSummaryStageBEnrichment("test_tool", tests);

        expect(result.sampleEvidence).toHaveLength(1);
        const evidence = result.sampleEvidence[0];

        // When only response exists, location should be "response"
        expect(evidence.location).toBe("response");
        // Context should also use response
        expect(evidence.context).toBe("Command executed: /bin/sh");
        expect(evidence.raw).toBe("malicious_payload");
      });

      it("should use evidence for both location and context when test has evidence only (happy path)", () => {
        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            payload: "malicious_payload",
            // response: undefined (no response)
            evidence: "Evidence of command injection",
          }),
        ];

        // Remove response to test evidence-only case
        delete (tests[0] as any).response;

        const result = buildToolSummaryStageBEnrichment("test_tool", tests);

        expect(result.sampleEvidence).toHaveLength(1);
        const evidence = result.sampleEvidence[0];

        // When only evidence exists, location should be "evidence"
        expect(evidence.location).toBe("evidence");
        // Context should also use evidence
        expect(evidence.context).toBe("Evidence of command injection");
        expect(evidence.raw).toBe("malicious_payload");
      });

      it("should consistently prioritize evidence for both location and context (edge case - FIX-002)", () => {
        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            payload: "malicious_payload",
            response: "Safe response text",
            evidence: "Detected malicious pattern in execution",
          }),
        ];

        const result = buildToolSummaryStageBEnrichment("test_tool", tests);

        expect(result.sampleEvidence).toHaveLength(1);
        const evidence = result.sampleEvidence[0];

        // CRITICAL: Both location and context should prioritize evidence
        expect(evidence.location).toBe("evidence");
        expect(evidence.context).toBe(
          "Detected malicious pattern in execution",
        );
        expect(evidence.raw).toBe("malicious_payload");

        // Should NOT use response when evidence exists
        expect(evidence.context).not.toBe("Safe response text");
      });

      it("should handle test with neither response nor evidence (edge case)", () => {
        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            payload: "malicious_payload",
            // No response or evidence
          }),
        ];

        // Remove both response and evidence
        delete (tests[0] as any).response;

        const result = buildToolSummaryStageBEnrichment("test_tool", tests);

        expect(result.sampleEvidence).toHaveLength(1);
        const evidence = result.sampleEvidence[0];

        // Location should be "unknown" when neither exists
        expect(evidence.location).toBe("unknown");
        // Context should be empty string
        expect(evidence.context).toBe("");
        expect(evidence.raw).toBe("malicious_payload");
      });
    });

    describe("testToEvidence in tool detail enrichment", () => {
      it("should maintain evidence priority in tool detail enrichment", () => {
        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            payload: "'; DROP TABLE users;--",
            response: "Database query executed",
            evidence: "SQL injection pattern detected in query",
          }),
        ];

        const result = buildToolDetailStageBEnrichment("test_tool", tests);

        // Check that payload correlations use consistent logic
        expect(result.payloadCorrelations).toHaveLength(1);
        const correlation = result.payloadCorrelations[0];

        expect(correlation.inputPayload).toBe("'; DROP TABLE users;--");
        expect(correlation.outputResponse).toBe("Database query executed");
        expect(correlation.classification).toBe("vulnerable");
      });

      it("should build context windows from evidence field", () => {
        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            testName: "sql_injection",
            payload: "' OR '1'='1",
            response: "Query result",
            evidence: "SQL pattern matched: OR '1'='1",
          }),
        ];

        const result = buildToolDetailStageBEnrichment("test_tool", tests);

        // Context windows should be built from evidence, not response
        const contextKeys = Object.keys(result.contextWindows);
        expect(contextKeys.length).toBeGreaterThan(0);

        // Verify the context window contains evidence text
        const contextValue = Object.values(result.contextWindows)[0];
        expect(contextValue).toBe("SQL pattern matched: OR '1'='1");
      });
    });

    describe("regression prevention for ISSUE-002", () => {
      it("should not have semantic inconsistency between location and context", () => {
        // This test ensures the bug described in ISSUE-002 is fixed
        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            payload: "attack_payload",
            response: "This is the response",
            evidence: "This is the evidence",
          }),
        ];

        const result = buildToolSummaryStageBEnrichment("test_tool", tests);
        const evidence = result.sampleEvidence[0];

        // BEFORE FIX-002:
        // - location would be "response" (prioritized response)
        // - context would be "This is the evidence" (prioritized evidence)
        // This was semantically inconsistent!

        // AFTER FIX-002:
        // - location should be "evidence" (prioritizes evidence)
        // - context should be "This is the evidence" (prioritizes evidence)
        // Now consistent!

        if (evidence.location === "evidence") {
          // If location is evidence, context must also use evidence
          expect(evidence.context).toBe("This is the evidence");
        } else if (evidence.location === "response") {
          // If location is response, context must also use response
          expect(evidence.context).toBe("This is the response");
        }

        // The fix ensures evidence is prioritized for both
        expect(evidence.location).toBe("evidence");
        expect(evidence.context).toBe("This is the evidence");
      });

      it("should document the prioritization order: evidence > response > unknown", () => {
        // Test case 1: Both exist -> evidence
        const bothTest = createMockSecurityTest({
          vulnerable: true,
          response: "response",
          evidence: "evidence",
        });
        const result1 = buildToolSummaryStageBEnrichment("test_tool", [
          bothTest,
        ]);
        expect(result1.sampleEvidence[0].location).toBe("evidence");
        expect(result1.sampleEvidence[0].context).toBe("evidence");

        // Test case 2: Only response -> response
        const responseTest = createMockSecurityTest({
          vulnerable: true,
          response: "response",
        });
        delete (responseTest as any).evidence;
        const result2 = buildToolSummaryStageBEnrichment("test_tool", [
          responseTest,
        ]);
        expect(result2.sampleEvidence[0].location).toBe("response");
        expect(result2.sampleEvidence[0].context).toBe("response");

        // Test case 3: Neither -> unknown
        const neitherTest = createMockSecurityTest({ vulnerable: true });
        delete (neitherTest as any).response;
        delete (neitherTest as any).evidence;
        const result3 = buildToolSummaryStageBEnrichment("test_tool", [
          neitherTest,
        ]);
        expect(result3.sampleEvidence[0].location).toBe("unknown");
        expect(result3.sampleEvidence[0].context).toBe("");
      });
    });

    describe("evidence truncation behavior", () => {
      it("should truncate long context to MAX_CONTEXT_WINDOW", () => {
        const longEvidence = "A".repeat(10000); // Very long evidence

        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            evidence: longEvidence,
          }),
        ];

        const result = buildToolSummaryStageBEnrichment("test_tool", tests);
        const evidence = result.sampleEvidence[0];

        // Should be truncated (MAX_CONTEXT_WINDOW is typically 1000)
        expect(evidence.context.length).toBeLessThan(longEvidence.length);
        expect(evidence.context).toContain("...");
      });

      it("should truncate long response to MAX_RESPONSE_LENGTH", () => {
        const longResponse = "B".repeat(10000); // Very long response

        const tests: SecurityTestResult[] = [
          createMockSecurityTest({
            vulnerable: true,
            toolName: "test_tool",
            response: longResponse,
          }),
        ];

        // Remove evidence so response is used
        delete (tests[0] as any).evidence;

        const result = buildToolSummaryStageBEnrichment("test_tool", tests);
        const evidence = result.sampleEvidence[0];

        // Should be truncated (MAX_RESPONSE_LENGTH is typically 500)
        expect(evidence.context.length).toBeLessThan(longResponse.length);
        expect(evidence.context).toContain("...");
      });
    });
  });
});
