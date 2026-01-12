/**
 * TestValidityAnalyzer Unit Tests
 *
 * Tests for detecting identical security test responses (test validity masking).
 * When tests return uniform responses, it indicates configuration or infrastructure
 * issues may be masking actual security behavior.
 *
 * @see Issue #134: Detect identical security test responses
 */

import { SecurityTestResult } from "@/lib/assessment/resultTypes";
import {
  TestValidityAnalyzer,
  TestValidityConfig,
} from "../modules/securityTests/TestValidityAnalyzer";

// Helper to create mock security test results
const createTestResult = (
  overrides: Partial<SecurityTestResult> = {},
): SecurityTestResult => ({
  testName: "Command Injection",
  description: "Tests for command injection vulnerabilities",
  payload: "test; ls",
  vulnerable: false,
  riskLevel: "HIGH",
  toolName: "test-tool",
  response: '{"status": "ok"}',
  ...overrides,
});

// Helper to generate N test results with the same response
const generateUniformResults = (
  count: number,
  response: string,
  toolName = "test-tool",
): SecurityTestResult[] => {
  return Array.from({ length: count }, (_, i) =>
    createTestResult({
      testName: `Test ${i}`,
      toolName,
      response,
    }),
  );
};

// Helper to generate diverse results
const generateDiverseResults = (count: number): SecurityTestResult[] => {
  const responses = [
    '{"status": "ok", "data": "result1"}',
    '{"status": "error", "message": "invalid input"}',
    '{"status": "ok", "items": []}',
    '{"success": true}',
    '{"result": "processed"}',
    '{"error": "not found"}',
    '{"status": "pending"}',
    '{"message": "completed"}',
    '{"output": "value123"}',
    '{"validated": true}',
  ];

  return Array.from({ length: count }, (_, i) =>
    createTestResult({
      testName: `Test ${i}`,
      response: responses[i % responses.length],
    }),
  );
};

describe("TestValidityAnalyzer", () => {
  let analyzer: TestValidityAnalyzer;

  beforeEach(() => {
    analyzer = new TestValidityAnalyzer();
  });

  describe("Basic Detection", () => {
    it("returns no warning for diverse responses", () => {
      const tests = generateDiverseResults(100);
      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(false);
      expect(result.warningLevel).toBe("none");
      expect(result.recommendedConfidence).toBe("high");
      expect(result.warning).toBeUndefined();
    });

    it("returns warning when 80-90% responses identical", () => {
      // 85% identical
      const identicalTests = generateUniformResults(
        85,
        '{"error": "config missing"}',
      );
      const diverseTests = generateDiverseResults(15);
      const tests = [...identicalTests, ...diverseTests];

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
      expect(result.warningLevel).toBe("warning");
      expect(result.recommendedConfidence).toBe("medium");
      expect(result.warning).toBeDefined();
      expect(result.warning!.percentageIdentical).toBeGreaterThanOrEqual(80);
      expect(result.warning!.percentageIdentical).toBeLessThan(90);
    });

    it("returns critical when >90% responses identical", () => {
      // 95% identical
      const identicalTests = generateUniformResults(
        95,
        '{"error": "Missing API_KEY"}',
      );
      const diverseTests = generateDiverseResults(5);
      const tests = [...identicalTests, ...diverseTests];

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
      expect(result.warningLevel).toBe("critical");
      expect(result.recommendedConfidence).toBe("low");
      expect(result.warning).toBeDefined();
      expect(result.warning!.percentageIdentical).toBeGreaterThanOrEqual(90);
    });

    it("returns critical when 100% responses identical", () => {
      const tests = generateUniformResults(
        100,
        '{"status":{"error":"Wrong input: Vector with name `fast-all-minilm-l6-v2` is not configured"}}',
      );

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
      expect(result.warningLevel).toBe("critical");
      expect(result.recommendedConfidence).toBe("low");
      expect(result.warning!.identicalResponseCount).toBe(100);
      expect(result.warning!.totalResponses).toBe(100);
      expect(result.warning!.percentageIdentical).toBe(100);
    });
  });

  describe("Response Normalization", () => {
    it("treats responses with different timestamps as identical", () => {
      const tests = [
        createTestResult({
          response: '{"error": "failed", "timestamp": "2025-01-01T00:00:00Z"}',
        }),
        createTestResult({
          response: '{"error": "failed", "timestamp": "2025-01-02T12:30:45Z"}',
        }),
        createTestResult({
          response:
            '{"error": "failed", "timestamp": "2026-03-15T08:15:30.123Z"}',
        }),
        ...Array.from({ length: 20 }, () =>
          createTestResult({
            response:
              '{"error": "failed", "timestamp": "2025-06-20T00:00:00Z"}',
          }),
        ),
      ];

      const result = analyzer.analyze(tests);

      // All should be treated as identical after timestamp normalization
      expect(result.warning?.identicalResponseCount).toBe(tests.length);
    });

    it("treats responses with different UUIDs as identical", () => {
      // Test that standard UUID v4 format is normalized
      const uuidV4Pattern =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
      const testUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

      // Verify our test UUID matches the expected pattern
      expect(testUUID).toMatch(uuidV4Pattern);

      // Generate tests with varying UUIDs (in UUID v4 format)
      const tests = Array.from({ length: 20 }, (_, i) =>
        createTestResult({
          response: `{"error": "failed", "correlation_id": "${i.toString(16).padStart(8, "a")}-bbbb-cccc-dddd-eeeeeeeeeeee"}`,
        }),
      );

      const result = analyzer.analyze(tests);

      // All responses should normalize to the same value after UUID replacement
      // 20 tests all identical = 100% uniformity = critical warning
      expect(result.isCompromised).toBe(true);
      expect(result.warning).toBeDefined();
      expect(result.warning!.identicalResponseCount).toBe(tests.length);
    });

    it("treats responses with different request IDs as identical", () => {
      const tests = Array.from({ length: 20 }, (_, i) =>
        createTestResult({
          response: `{"error": "failed", "request_id": "req_${i.toString().padStart(10, "0")}"}`,
        }),
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.identicalResponseCount).toBe(tests.length);
    });

    it("treats responses differing only in extra whitespace as identical", () => {
      // Normalization collapses multiple spaces to single space
      const tests = [
        createTestResult({
          response: '{"error":  "failed  with   extra    spaces"}',
        }),
        createTestResult({
          response: '{"error": "failed with extra spaces"}',
        }),
        createTestResult({
          response: '{"error":   "failed   with   extra   spaces"}',
        }),
        ...Array.from({ length: 20 }, () =>
          createTestResult({
            response: '{"error": "failed with extra spaces"}',
          }),
        ),
      ];

      const result = analyzer.analyze(tests);

      // All should be treated as identical after whitespace normalization
      expect(result.warning?.identicalResponseCount).toBe(tests.length);
    });
  });

  describe("Pattern Detection", () => {
    it("detects configuration error pattern", () => {
      const tests = generateUniformResults(
        50,
        '{"error": "Missing API_KEY configuration required for authentication"}',
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.detectedPattern).toBe("configuration_error");
    });

    it("detects connection error pattern", () => {
      const tests = generateUniformResults(
        50,
        "ECONNREFUSED: Connection refused to localhost:5432",
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.detectedPattern).toBe("connection_error");
    });

    it("detects timeout pattern", () => {
      const tests = generateUniformResults(
        50,
        '{"error": "Request timed out after 30000ms"}',
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.detectedPattern).toBe("timeout");
    });

    it("detects empty response pattern", () => {
      const tests = generateUniformResults(50, "{}");

      const result = analyzer.analyze(tests);

      expect(result.warning?.detectedPattern).toBe("empty_response");
    });

    it("detects generic error pattern", () => {
      // Response needs to be > 50 chars to not trigger empty_response
      const tests = generateUniformResults(
        50,
        '{"status": "error", "code": 500, "message": "Internal server error occurred during processing"}',
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.detectedPattern).toBe("generic_error");
    });

    it("returns unknown for unrecognized patterns", () => {
      // Response needs to be > 50 chars to not trigger empty_response
      const tests = generateUniformResults(
        50,
        '{"data": "some regular response data here that is longer than fifty characters to avoid triggering empty response detection"}',
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.detectedPattern).toBe("unknown");
    });
  });

  describe("Minimum Test Threshold", () => {
    it("skips analysis when below minimum test count", () => {
      // Default minimum is 10
      const tests = generateUniformResults(9, '{"error": "config"}');

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(false);
      expect(result.warning).toBeUndefined();
    });

    it("respects custom minimum test threshold", () => {
      const customAnalyzer = new TestValidityAnalyzer({
        minimumTestsForAnalysis: 5,
      });

      const tests = generateUniformResults(6, '{"error": "config"}');

      const result = customAnalyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
    });
  });

  describe("Custom Thresholds", () => {
    it("uses custom warning threshold", () => {
      const customAnalyzer = new TestValidityAnalyzer({
        warningThresholdPercent: 70, // Lower threshold
      });

      // 75% identical - should trigger warning with custom threshold
      const identicalTests = generateUniformResults(75, '{"error": "config"}');
      const diverseTests = generateDiverseResults(25);
      const tests = [...identicalTests, ...diverseTests];

      const result = customAnalyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
      expect(result.warningLevel).toBe("warning");
    });

    it("uses custom confidence reduce threshold", () => {
      const customAnalyzer = new TestValidityAnalyzer({
        confidenceReduceThresholdPercent: 85, // Lower threshold for critical
      });

      // 87% identical - should be critical with custom threshold
      const identicalTests = generateUniformResults(87, '{"error": "config"}');
      const diverseTests = generateDiverseResults(13);
      const tests = [...identicalTests, ...diverseTests];

      const result = customAnalyzer.analyze(tests);

      expect(result.warningLevel).toBe("critical");
      expect(result.recommendedConfidence).toBe("low");
    });
  });

  describe("Per-Tool Analysis", () => {
    it("provides per-tool uniformity breakdown", () => {
      const tool1Tests = generateUniformResults(
        30,
        '{"error": "config"}',
        "tool-1",
      );
      const tool2Tests = generateDiverseResults(20).map((t) => ({
        ...t,
        toolName: "tool-2",
      }));
      const tool3Tests = generateUniformResults(
        50,
        '{"error": "timeout"}',
        "tool-3",
      );

      const tests = [...tool1Tests, ...tool2Tests, ...tool3Tests];
      const result = analyzer.analyze(tests);

      expect(result.toolUniformity).toBeDefined();
      expect(result.toolUniformity!.get("tool-1")?.percentageIdentical).toBe(
        100,
      );
      expect(result.toolUniformity!.get("tool-3")?.percentageIdentical).toBe(
        100,
      );
      // tool-2 should have lower uniformity
      expect(
        result.toolUniformity!.get("tool-2")?.percentageIdentical,
      ).toBeLessThan(100);
    });
  });

  describe("Explanation Generation", () => {
    it("generates meaningful explanation for configuration errors", () => {
      const tests = generateUniformResults(
        100,
        '{"error": "Missing API_KEY required"}',
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.explanation).toContain("100%");
      expect(result.warning?.explanation).toContain("100/100");
      expect(result.warning?.explanation).toContain("configuration error");
      expect(result.warning?.explanation).toContain("re-run the assessment");
    });

    it("generates meaningful explanation for connection errors", () => {
      const tests = generateUniformResults(
        100,
        "Connection refused to database server",
      );

      const result = analyzer.analyze(tests);

      expect(result.warning?.explanation).toContain("connection failure");
    });
  });

  describe("Sample Response", () => {
    it("includes original (non-normalized) sample in warning", () => {
      const originalResponse =
        '{"error": "Missing API_KEY", "timestamp": "2025-01-15T10:30:00Z"}';
      const tests = generateUniformResults(50, originalResponse);

      const result = analyzer.analyze(tests);

      // Sample should contain original text, not normalized
      expect(result.warning?.sampleResponse).toContain("Missing API_KEY");
      expect(result.warning?.sampleResponse).toContain("timestamp");
    });

    it("truncates long sample responses", () => {
      const longResponse = "A".repeat(1000);
      const tests = generateUniformResults(50, longResponse);

      const result = analyzer.analyze(tests);

      // Sample should be truncated to 500 chars
      expect(result.warning?.sampleResponse.length).toBeLessThanOrEqual(500);
    });
  });

  describe("Edge Cases", () => {
    it("handles empty test array", () => {
      const result = analyzer.analyze([]);

      expect(result.isCompromised).toBe(false);
      expect(result.warning).toBeUndefined();
    });

    it("handles tests without response field", () => {
      const tests = Array.from({ length: 20 }, () =>
        createTestResult({ response: undefined }),
      );

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(false);
    });

    it("handles mix of tests with and without responses", () => {
      const withResponse = generateUniformResults(40, '{"error": "config"}');
      const withoutResponse = Array.from({ length: 10 }, () =>
        createTestResult({ response: undefined }),
      );
      const tests = [...withResponse, ...withoutResponse];

      const result = analyzer.analyze(tests);

      // Should only analyze tests with responses (40 tests)
      expect(result.warning?.totalResponses).toBe(40);
    });

    it("handles null response values", () => {
      const tests = Array.from({ length: 20 }, () =>
        createTestResult({ response: null as unknown as string }),
      );

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(false);
    });
  });

  describe("Real-World Scenarios", () => {
    it("detects Qdrant configuration error scenario from Issue #134", () => {
      const qdrantError = `Error calling tool 'qdrant-find': Unexpected Response: 400 (Bad Request)
Raw response content:
b'{"status":{"error":"Wrong input: Vector with name \`fast-all-minilm-l6-v2\` is not configured in this collection, available names: all-minilm-l6-v2"}}'`;

      const tests = generateUniformResults(348, qdrantError);

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
      expect(result.warningLevel).toBe("critical");
      expect(result.recommendedConfidence).toBe("low");
      expect(result.warning?.identicalResponseCount).toBe(348);
      expect(result.warning?.detectedPattern).toBe("configuration_error");
    });

    it("detects missing API key scenario", () => {
      const tests = generateUniformResults(
        100,
        '{"error": "ANTHROPIC_API_KEY environment variable is not set"}',
      );

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
      expect(result.warning?.detectedPattern).toBe("configuration_error");
    });

    it("detects database connection failure", () => {
      const tests = generateUniformResults(
        100,
        "Error: connect ECONNREFUSED 127.0.0.1:5432",
      );

      const result = analyzer.analyze(tests);

      expect(result.isCompromised).toBe(true);
      expect(result.warning?.detectedPattern).toBe("connection_error");
    });
  });

  // Issue #135: Enhanced data tests for Stage B semantic analysis
  describe("Enhanced Stage B Data", () => {
    describe("Response Diversity", () => {
      it("calculates low entropy for uniform responses", () => {
        const tests = generateUniformResults(
          100,
          '{"error": "config missing"}',
        );

        const result = analyzer.analyze(tests);

        expect(result.warning?.responseDiversity).toBeDefined();
        expect(result.warning?.responseDiversity?.uniqueResponses).toBe(1);
        expect(result.warning?.responseDiversity?.entropyScore).toBe(0);
      });

      it("calculates higher entropy for diverse responses triggering warning", () => {
        // 85 identical + 15 diverse = triggers warning but has some diversity
        const identicalTests = generateUniformResults(
          85,
          '{"error": "config missing"}',
        );
        const diverseTests = generateDiverseResults(15);
        const tests = [...identicalTests, ...diverseTests];

        const result = analyzer.analyze(tests);

        expect(result.warning?.responseDiversity).toBeDefined();
        expect(
          result.warning?.responseDiversity?.uniqueResponses,
        ).toBeGreaterThan(1);
        expect(result.warning?.responseDiversity?.entropyScore).toBeGreaterThan(
          0,
        );
      });

      it("includes response distribution sorted by frequency", () => {
        // 85% identical triggers warning, with some diversity
        const tests = [
          ...generateUniformResults(85, '{"error": "most common"}'),
          ...generateUniformResults(10, '{"error": "second"}'),
          ...generateUniformResults(5, '{"error": "third"}'),
        ];

        const result = analyzer.analyze(tests);

        expect(result.warning?.responseDiversity?.distribution).toBeDefined();
        expect(
          result.warning?.responseDiversity?.distribution?.length,
        ).toBeLessThanOrEqual(5);
        expect(result.warning?.responseDiversity?.distribution?.[0].count).toBe(
          85,
        );
        expect(
          result.warning?.responseDiversity?.distribution?.[0].percentage,
        ).toBeCloseTo(85, 0);
      });
    });

    describe("Tool Uniformity Export", () => {
      it("exports toolUniformity as JSON object (not Map)", () => {
        // Both tools have identical responses - triggers warning
        const tests = [
          ...generateUniformResults(50, '{"error": "config"}', "tool-1"),
          ...generateUniformResults(50, '{"error": "config"}', "tool-2"),
        ];

        const result = analyzer.analyze(tests);

        expect(result.warning?.toolUniformity).toBeDefined();
        expect(typeof result.warning?.toolUniformity).toBe("object");
        expect(result.warning?.toolUniformity?.["tool-1"]).toEqual({
          identicalCount: 50,
          totalCount: 50,
          percentageIdentical: 100,
        });
      });
    });

    describe("Attack Pattern Correlation", () => {
      it("categorizes tests by attack type", () => {
        const tests: SecurityTestResult[] = [
          ...Array(30)
            .fill(0)
            .map((_, i) =>
              createTestResult({
                testName: `SQL Injection Test ${i}`,
                response: '{"error": "config"}',
              }),
            ),
          ...Array(20)
            .fill(0)
            .map((_, i) =>
              createTestResult({
                testName: `XSS Script Test ${i}`,
                response: '{"error": "config"}',
              }),
            ),
          ...Array(50)
            .fill(0)
            .map((_, i) =>
              createTestResult({
                testName: `Command RCE Test ${i}`,
                response: '{"error": "config"}',
              }),
            ),
        ];

        const result = analyzer.analyze(tests);

        expect(result.warning?.attackPatternCorrelation).toBeDefined();
        expect(
          result.warning?.attackPatternCorrelation?.["injection"]?.testCount,
        ).toBe(30);
        expect(
          result.warning?.attackPatternCorrelation?.["xss"]?.testCount,
        ).toBe(20);
        expect(
          result.warning?.attackPatternCorrelation?.["command_injection"]
            ?.testCount,
        ).toBe(50);
      });

      it("includes sample payload and response per category", () => {
        const tests = generateUniformResults(100, '{"error": "config"}');
        tests[0].testName = "SQL Injection Test";
        tests[0].payload = "SELECT * FROM users";

        const result = analyzer.analyze(tests);

        expect(
          result.warning?.attackPatternCorrelation?.["injection"]
            ?.samplePayload,
        ).toBeDefined();
        expect(
          result.warning?.attackPatternCorrelation?.["injection"]
            ?.sampleResponse,
        ).toBeDefined();
      });
    });

    describe("Sample Pairs Collection", () => {
      it("collects diverse sample pairs up to maxSamplePairs", () => {
        const tests = generateUniformResults(100, '{"error": "config"}');
        // Give each test a different attack category
        tests.forEach((t, i) => {
          t.testName = i % 2 === 0 ? "SQL Injection" : "XSS Script";
          t.payload = `payload-${i}`;
        });

        const result = analyzer.analyze(tests);

        expect(result.warning?.samplePairs).toBeDefined();
        expect(result.warning?.samplePairs?.length).toBeLessThanOrEqual(10);
      });

      it("prioritizes category diversity in sample pairs", () => {
        const tests: SecurityTestResult[] = [
          createTestResult({
            testName: "SQL Injection",
            payload: "sql-payload",
            response: '{"error": "config"}',
          }),
          createTestResult({
            testName: "XSS Script",
            payload: "xss-payload",
            response: '{"error": "config"}',
          }),
          createTestResult({
            testName: "Command RCE",
            payload: "cmd-payload",
            response: '{"error": "config"}',
          }),
          ...generateUniformResults(97, '{"error": "config"}'),
        ];

        const result = analyzer.analyze(tests);

        // Should have at least 3 different categories in first 3 pairs
        const categories = new Set(
          result.warning?.samplePairs?.slice(0, 3).map((p) => p.attackCategory),
        );
        expect(categories.size).toBeGreaterThanOrEqual(3);
      });

      it("includes vulnerability status in sample pairs", () => {
        const tests = generateUniformResults(100, '{"error": "config"}');
        tests[0].vulnerable = true;

        const result = analyzer.analyze(tests);

        expect(
          result.warning?.samplePairs?.some((p) => p.vulnerable === true) ||
            result.warning?.samplePairs?.some((p) => p.vulnerable === false),
        ).toBe(true);
      });
    });

    describe("Response Metadata", () => {
      it("calculates response length statistics", () => {
        const tests = [
          createTestResult({ response: "a".repeat(100) }),
          createTestResult({ response: "b".repeat(200) }),
          createTestResult({ response: "c".repeat(300) }),
          ...generateUniformResults(97, '{"error": "config"}'),
        ];

        const result = analyzer.analyze(tests);

        expect(result.warning?.responseMetadata).toBeDefined();
        expect(result.warning?.responseMetadata?.avgLength).toBeGreaterThan(0);
        expect(result.warning?.responseMetadata?.minLength).toBeGreaterThan(0);
        expect(result.warning?.responseMetadata?.maxLength).toBeGreaterThan(
          result.warning?.responseMetadata?.minLength || 0,
        );
      });

      it("counts empty responses", () => {
        const tests = [
          createTestResult({ response: "{}" }),
          createTestResult({ response: "[]" }),
          createTestResult({ response: "null" }),
          createTestResult({ response: "" }),
          ...generateUniformResults(96, '{"error": "config"}'),
        ];

        const result = analyzer.analyze(tests);

        expect(
          result.warning?.responseMetadata?.emptyCount,
        ).toBeGreaterThanOrEqual(4);
      });

      it("counts error responses", () => {
        const tests = generateUniformResults(
          100,
          '{"error": "something failed"}',
        );

        const result = analyzer.analyze(tests);

        expect(result.warning?.responseMetadata?.errorCount).toBe(100);
      });
    });

    describe("Config Options", () => {
      it("respects custom maxSamplePairs", () => {
        const customAnalyzer = new TestValidityAnalyzer({ maxSamplePairs: 3 });
        const tests = generateUniformResults(100, '{"error": "config"}');
        tests.forEach((t, i) => (t.payload = `payload-${i}`));

        const result = customAnalyzer.analyze(tests);

        expect(result.warning?.samplePairs?.length).toBeLessThanOrEqual(3);
      });

      it("respects custom maxDistributionEntries", () => {
        const customAnalyzer = new TestValidityAnalyzer({
          maxDistributionEntries: 2,
        });
        // 85% identical triggers warning
        const tests = [
          ...generateUniformResults(85, '{"a": 1}'),
          ...generateUniformResults(10, '{"b": 2}'),
          ...generateUniformResults(5, '{"c": 3}'),
        ];

        const result = customAnalyzer.analyze(tests);

        expect(
          result.warning?.responseDiversity?.distribution?.length,
        ).toBeLessThanOrEqual(2);
      });
    });
  });
});
