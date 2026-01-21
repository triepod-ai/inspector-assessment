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
  buildAuthEnrichment,
  buildResourceEnrichment,
  buildPromptEnrichment,
  buildProhibitedLibrariesEnrichment,
  buildManifestEnrichment,
  buildEnrichment,
  hasEnrichmentBuilder,
  getEnrichableModules,
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

  describe("enrichmentData fields (Issue #194 - GAP-3)", () => {
    it("should include toolInventory from enrichmentData", () => {
      const result = buildAUPEnrichment({
        violations: [],
        enrichmentData: {
          toolInventory: [
            {
              name: "tool_1",
              description: "Tool 1 description",
              capabilities: ["file_system", "network"],
            },
            {
              name: "tool_2",
              description: "Tool 2 description",
              capabilities: ["exec"],
            },
          ],
          patternCoverage: {
            totalPatterns: 100,
            categoriesCovered: ["A"],
            samplePatterns: ["pattern1"],
            severityBreakdown: {
              critical: 0,
              high: 0,
              medium: 0,
              flag: 100,
            },
          },
          flagsForReview: [],
        },
      });

      expect(result.toolInventory).toBeDefined();
      expect(result.toolInventory).toHaveLength(2);
      expect(result.toolInventory![0].name).toBe("tool_1");
      expect(result.toolInventory![0].capabilities).toEqual([
        "file_system",
        "network",
      ]);
    });

    it("should include patternCoverage from enrichmentData", () => {
      const result = buildAUPEnrichment({
        violations: [],
        enrichmentData: {
          toolInventory: [],
          patternCoverage: {
            totalPatterns: 150,
            categoriesCovered: ["A", "B", "C"],
            samplePatterns: ["pattern1", "pattern2"],
            severityBreakdown: {
              critical: 10,
              high: 20,
              medium: 30,
              flag: 90,
            },
          },
          flagsForReview: [],
        },
      });

      expect(result.patternCoverage).toBeDefined();
      expect(result.patternCoverage!.totalPatterns).toBe(150);
      expect(result.patternCoverage!.categoriesCovered).toEqual([
        "A",
        "B",
        "C",
      ]);
      expect(result.patternCoverage!.samplePatterns).toEqual([
        "pattern1",
        "pattern2",
      ]);
      expect(result.patternCoverage!.severityBreakdown).toEqual({
        critical: 10,
        high: 20,
        medium: 30,
        flag: 90,
      });
    });

    it("should include flagsForReview from enrichmentData", () => {
      const result = buildAUPEnrichment({
        violations: [],
        enrichmentData: {
          toolInventory: [],
          patternCoverage: {
            totalPatterns: 100,
            categoriesCovered: ["A"],
            samplePatterns: ["pattern1"],
            severityBreakdown: {
              critical: 0,
              high: 0,
              medium: 0,
              flag: 100,
            },
          },
          flagsForReview: [
            {
              toolName: "exec_tool",
              reason: "Shell execution capability",
              capabilities: ["exec"],
              confidence: "low",
            },
            {
              toolName: "auth_tool",
              reason: "Authentication handling",
              capabilities: ["auth"],
              confidence: "medium",
            },
          ],
        },
      });

      expect(result.flagsForReview).toBeDefined();
      expect(result.flagsForReview).toHaveLength(2);
      expect(result.flagsForReview![0].toolName).toBe("exec_tool");
      expect(result.flagsForReview![0].capabilities).toEqual(["exec"]);
      expect(result.flagsForReview![1].toolName).toBe("auth_tool");
    });

    it("should truncate toolInventory to 50 items for token efficiency", () => {
      const tools = Array(75)
        .fill(null)
        .map((_, i) => ({
          name: `tool_${i}`,
          description: "Test description",
          capabilities: ["file_system"],
        }));

      const result = buildAUPEnrichment({
        violations: [],
        enrichmentData: {
          toolInventory: tools,
          patternCoverage: {
            totalPatterns: 100,
            categoriesCovered: ["A"],
            samplePatterns: ["pattern1"],
            severityBreakdown: {
              critical: 0,
              high: 0,
              medium: 0,
              flag: 100,
            },
          },
          flagsForReview: [],
        },
      });

      expect(result.toolInventory).toBeDefined();
      expect(result.toolInventory).toHaveLength(50);
      expect(result.toolInventory![0].name).toBe("tool_0");
      expect(result.toolInventory![49].name).toBe("tool_49");
    });

    it("should handle missing enrichmentData gracefully", () => {
      const result = buildAUPEnrichment({
        violations: [],
      });

      expect(result.toolInventory).toBeUndefined();
      expect(result.patternCoverage).toBeUndefined();
      expect(result.flagsForReview).toBeUndefined();
    });

    it("should handle partial enrichmentData", () => {
      const result = buildAUPEnrichment({
        violations: [],
        enrichmentData: {
          toolInventory: [
            {
              name: "tool_1",
              description: "Description",
              capabilities: ["network"],
            },
          ],
          patternCoverage: {
            totalPatterns: 100,
            categoriesCovered: ["A"],
            samplePatterns: ["pattern1"],
            severityBreakdown: {
              critical: 0,
              high: 0,
              medium: 0,
              flag: 100,
            },
          },
          // flagsForReview missing
        } as any,
      });

      expect(result.toolInventory).toBeDefined();
      expect(result.patternCoverage).toBeDefined();
      expect(result.flagsForReview).toBeUndefined();
    });

    it("should include enrichmentData even with violations present", () => {
      const result = buildAUPEnrichment({
        violations: [
          { severity: "HIGH", category: "C" },
          { severity: "CRITICAL", category: "A" },
        ],
        enrichmentData: {
          toolInventory: [
            {
              name: "tool_1",
              description: "Description",
              capabilities: ["exec"],
            },
          ],
          patternCoverage: {
            totalPatterns: 100,
            categoriesCovered: ["A", "C"],
            samplePatterns: ["pattern1"],
            severityBreakdown: {
              critical: 5,
              high: 10,
              medium: 20,
              flag: 65,
            },
          },
          flagsForReview: [
            {
              toolName: "tool_1",
              reason: "Exec capability",
              capabilities: ["exec"],
              confidence: "low",
            },
          ],
        },
      });

      // Both violations and enrichment data should be present
      expect(result.violationsSample).toHaveLength(2);
      expect(result.toolInventory).toBeDefined();
      expect(result.patternCoverage).toBeDefined();
      expect(result.flagsForReview).toBeDefined();
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

describe("buildAuthEnrichment", () => {
  it("should build enrichment with basic auth metrics", () => {
    const result = buildAuthEnrichment({
      authMethod: "oauth",
      hasLocalDependencies: true,
      transportType: "http",
      appropriateness: {
        isAppropriate: true,
        concerns: [],
        explanation: "OAuth is appropriate",
      },
      transportSecurity: {
        usesTLS: true,
        tlsEnforced: true,
        hasInsecurePatterns: false,
        insecurePatterns: [],
        corsConfigured: true,
        corsPermissive: false,
        sessionSecure: true,
      },
      authConfigAnalysis: {
        totalFindings: 0,
        hasHighSeverity: false,
        envDependentAuthCount: 0,
        failOpenPatternCount: 0,
        failOpenLogicCount: 0,
        devModeWarningCount: 0,
        hardcodedSecretCount: 0,
      },
    });

    expect(result.authMethod).toBe("oauth");
    expect(result.authMetrics.hasLocalDependencies).toBe(true);
    expect(result.authMetrics.tlsEnforced).toBe(true);
    expect(result.authMetrics.corsConfigured).toBe(true);
    expect(result.authMetrics.sessionSecure).toBe(true);
    expect(result.authMetrics.authConfigFindings).toBe(0);
    expect(result.authMetrics.hasHighSeverityFindings).toBe(false);
  });

  it("should include enrichment data fields", () => {
    const result = buildAuthEnrichment({
      authMethod: "apiKey",
      enrichmentData: {
        toolInventory: [
          {
            name: "auth_tool",
            description: "Authentication tool",
            authCapabilities: ["oauth", "apikey"],
            isSensitive: true,
          },
        ],
        oauthPatternCoverage: {
          totalPatterns: 10,
          matchedPatterns: ["oauth2", "pkce"],
          flowType: "authorization_code",
          pkceDetected: true,
        },
        apiKeyPatternCoverage: {
          totalPatterns: 5,
          matchedPatterns: ["api_key", "bearer"],
          envVarManaged: true,
        },
        flagsForReview: [
          {
            toolName: "auth_tool",
            reason: "Sensitive authentication",
            capabilities: ["oauth"],
            riskLevel: "medium",
          },
        ],
      },
    });

    expect(result.toolInventory).toHaveLength(1);
    expect(result.toolInventory![0].name).toBe("auth_tool");
    expect(result.oauthCoverage?.pkceDetected).toBe(true);
    expect(result.apiKeyCoverage?.envVarManaged).toBe(true);
    expect(result.flagsForReview).toHaveLength(1);
  });

  it("should truncate toolInventory to 50 items", () => {
    const tools = Array(75)
      .fill(null)
      .map((_, i) => ({
        name: `tool_${i}`,
        description: "Test",
        authCapabilities: ["oauth"],
        isSensitive: false,
      }));

    const result = buildAuthEnrichment({
      enrichmentData: { toolInventory: tools },
    });

    expect(result.toolInventory).toHaveLength(50);
  });

  it("should handle missing fields gracefully", () => {
    const result = buildAuthEnrichment({});

    expect(result.authMethod).toBe("unknown");
    expect(result.authMetrics.hasLocalDependencies).toBe(false);
    expect(result.authMetrics.tlsEnforced).toBe(false);
    expect(result.concerns).toEqual([]);
  });
});

describe("buildResourceEnrichment", () => {
  it("should build enrichment with resource metrics", () => {
    const result = buildResourceEnrichment({
      resourcesTested: 10,
      resourceTemplatesTested: 5,
      accessibleResources: 8,
      securityIssuesFound: 2,
      pathTraversalVulnerabilities: 1,
      sensitiveDataExposures: 1,
      promptInjectionVulnerabilities: 0,
      blobDosVulnerabilities: 0,
      polyglotVulnerabilities: 0,
      mimeValidationFailures: 0,
    });

    expect(result.resourceMetrics.totalResources).toBe(10);
    expect(result.resourceMetrics.totalTemplates).toBe(5);
    expect(result.resourceMetrics.accessibleResources).toBe(8);
    expect(result.resourceMetrics.vulnerableResources).toBe(2);
    expect(result.resourceMetrics.pathTraversalVulnerabilities).toBe(1);
    expect(result.resourceMetrics.sensitiveDataExposures).toBe(1);
  });

  it("should include enrichment data fields", () => {
    const result = buildResourceEnrichment({
      resourcesTested: 5,
      enrichmentData: {
        resourceInventory: [
          {
            uri: "file:///data/users.db",
            name: "User Database",
            mimeType: "application/x-sqlite3",
            resourceType: "database",
            securityFlags: ["sensitive", "pii"],
            dataClassification: "confidential",
          },
        ],
        patternCoverage: {
          sensitiveUriPatterns: 10,
          pathTraversalPayloads: 15,
          uriInjectionPayloads: 8,
          hiddenResourcePatterns: 5,
          samplePatterns: ["../../../etc/passwd", "file://"],
        },
        flagsForReview: [
          {
            resourceUri: "file:///data/users.db",
            reason: "Sensitive database access",
            flags: ["pii", "sensitive"],
            riskLevel: "high",
          },
        ],
      },
    });

    expect(result.resourceInventory).toHaveLength(1);
    expect(result.resourceInventory![0].uri).toBe("file:///data/users.db");
    expect(result.patternCoverage?.pathTraversalPayloads).toBe(15);
    expect(result.flagsForReview).toHaveLength(1);
  });

  it("should truncate resourceInventory to 50 items", () => {
    const resources = Array(75)
      .fill(null)
      .map((_, i) => ({
        uri: `file:///resource_${i}`,
        resourceType: "file",
        securityFlags: [],
        dataClassification: "public",
      }));

    const result = buildResourceEnrichment({
      enrichmentData: { resourceInventory: resources },
    });

    expect(result.resourceInventory).toHaveLength(50);
  });

  it("should handle missing fields gracefully", () => {
    const result = buildResourceEnrichment({});

    expect(result.resourceMetrics.totalResources).toBe(0);
    expect(result.resourceMetrics.vulnerableResources).toBe(0);
  });
});

describe("buildPromptEnrichment", () => {
  it("should build enrichment with prompt metrics", () => {
    const result = buildPromptEnrichment({
      promptsTested: 15,
      aupViolations: 2,
      injectionVulnerabilities: 1,
      argumentValidationIssues: 3,
    });

    expect(result.promptMetrics.totalPrompts).toBe(15);
    expect(result.promptMetrics.aupViolations).toBe(2);
    expect(result.promptMetrics.injectionVulnerabilities).toBe(1);
    expect(result.promptMetrics.argumentValidationIssues).toBe(3);
  });

  it("should include enrichment data fields", () => {
    const result = buildPromptEnrichment({
      promptsTested: 5,
      enrichmentData: {
        promptInventory: [
          {
            name: "search_prompt",
            description: "Search data",
            argumentCount: 2,
            requiredArgs: ["query"],
            optionalArgs: ["limit"],
            category: "search",
            securityFlags: ["injection_risk"],
          },
        ],
        patternCoverage: {
          injectionPatternsChecked: 20,
          aupPatternsChecked: 15,
          argumentValidationChecks: 10,
          samplePatterns: ["{{malicious}}", "${injection}"],
        },
        flagsForReview: [
          {
            promptName: "search_prompt",
            reason: "Injection vulnerability",
            flags: ["injection_risk"],
            riskLevel: "medium",
          },
        ],
      },
    });

    expect(result.promptInventory).toHaveLength(1);
    expect(result.promptInventory![0].name).toBe("search_prompt");
    expect(result.patternCoverage?.injectionPatternsChecked).toBe(20);
    expect(result.flagsForReview).toHaveLength(1);
  });

  it("should truncate promptInventory to 50 items", () => {
    const prompts = Array(75)
      .fill(null)
      .map((_, i) => ({
        name: `prompt_${i}`,
        argumentCount: 1,
        requiredArgs: ["arg"],
        optionalArgs: [],
        category: "test",
        securityFlags: [],
      }));

    const result = buildPromptEnrichment({
      enrichmentData: { promptInventory: prompts },
    });

    expect(result.promptInventory).toHaveLength(50);
  });

  it("should handle missing fields gracefully", () => {
    const result = buildPromptEnrichment({});

    expect(result.promptMetrics.totalPrompts).toBe(0);
    expect(result.promptMetrics.aupViolations).toBe(0);
  });
});

describe("buildProhibitedLibrariesEnrichment", () => {
  it("should build enrichment with library metrics", () => {
    const result = buildProhibitedLibrariesEnrichment({
      matches: [
        {
          name: "plaid",
          category: "financial",
          severity: "BLOCKING",
          location: "package.json",
          usageStatus: "ACTIVE",
          importCount: 5,
        },
        {
          name: "stripe",
          category: "financial",
          severity: "HIGH",
          location: "package.json",
          usageStatus: "UNUSED",
          importCount: 0,
        },
      ],
      scannedFiles: ["package.json", "server.js"],
      hasFinancialLibraries: true,
      hasMediaLibraries: false,
    });

    expect(result.libraryMetrics.totalMatches).toBe(2);
    expect(result.libraryMetrics.blockingCount).toBe(1);
    expect(result.libraryMetrics.highCount).toBe(1);
    expect(result.libraryMetrics.activeCount).toBe(1);
    expect(result.libraryMetrics.unusedCount).toBe(1);
    expect(result.libraryMetrics.hasFinancialLibraries).toBe(true);
  });

  it("should include enrichment data fields", () => {
    const result = buildProhibitedLibrariesEnrichment({
      matches: [],
      enrichmentData: {
        libraryInventory: [
          {
            name: "plaid",
            category: "financial",
            severity: "BLOCKING",
            location: "package.json",
            usageStatus: "ACTIVE",
            importCount: 5,
            importFiles: ["server.js", "auth.js"],
            policyReference: "MCP_FINANCIAL_LIBS_001",
          },
        ],
        policyCoverage: {
          totalProhibitedLibraries: 25,
          scannedFiles: 10,
          policiesChecked: ["financial", "media"],
          sampleLibraries: ["plaid", "stripe", "ffmpeg"],
        },
        flagsForReview: [
          {
            libraryName: "plaid",
            reason: "Financial API library",
            flags: ["blocking", "active"],
            riskLevel: "critical",
          },
        ],
      },
    });

    expect(result.libraryInventory).toHaveLength(1);
    expect(result.libraryInventory![0].name).toBe("plaid");
    expect(result.policyCoverage?.totalProhibitedLibraries).toBe(25);
    expect(result.flagsForReview).toHaveLength(1);
  });

  it("should truncate libraryInventory to 50 items", () => {
    const libraries = Array(75)
      .fill(null)
      .map((_, i) => ({
        name: `lib_${i}`,
        category: "financial",
        severity: "HIGH",
        location: "package.json",
        usageStatus: "ACTIVE",
        importCount: 1,
        importFiles: ["file.js"],
        policyReference: "POLICY_001",
      }));

    const result = buildProhibitedLibrariesEnrichment({
      enrichmentData: { libraryInventory: libraries },
    });

    expect(result.libraryInventory).toHaveLength(50);
  });

  it("should handle missing fields gracefully", () => {
    const result = buildProhibitedLibrariesEnrichment({});

    expect(result.libraryMetrics.totalMatches).toBe(0);
    expect(result.libraryMetrics.blockingCount).toBe(0);
    expect(result.libraryMetrics.hasFinancialLibraries).toBe(false);
  });
});

describe("buildManifestEnrichment", () => {
  it("should build enrichment with manifest metrics", () => {
    const result = buildManifestEnrichment({
      hasManifest: true,
      manifestVersion: "0.3",
      hasRequiredFields: true,
      hasIcon: true,
      missingFields: [],
      validationResults: [
        {
          field: "name",
          valid: true,
          value: "test-server",
          severity: "INFO",
        },
        {
          field: "version",
          valid: false,
          value: undefined,
          issue: "Missing required field",
          severity: "ERROR",
        },
      ],
      privacyPolicies: {
        declared: ["https://example.com/privacy"],
        validationResults: [
          { url: "https://example.com/privacy", accessible: true },
        ],
        allAccessible: true,
      },
      contactInfo: {
        email: "test@example.com",
        name: "Test Author",
        source: "manifest.json",
      },
    });

    expect(result.manifestMetrics.hasManifest).toBe(true);
    expect(result.manifestMetrics.hasRequiredFields).toBe(true);
    expect(result.manifestMetrics.hasIcon).toBe(true);
    expect(result.manifestMetrics.hasContactInfo).toBe(true);
    expect(result.manifestMetrics.privacyPoliciesAccessible).toBe(true);
    expect(result.manifestMetrics.totalChecks).toBe(2);
    expect(result.manifestMetrics.passedChecks).toBe(1);
    expect(result.manifestMetrics.errorCount).toBe(1);
  });

  it("should include enrichment data fields", () => {
    const result = buildManifestEnrichment({
      hasManifest: true,
      enrichmentData: {
        fieldInventory: [
          {
            field: "name",
            valid: true,
            value: "test-server",
            severity: "INFO",
            category: "required",
          },
          {
            field: "version",
            valid: false,
            issue: "Invalid version format",
            severity: "ERROR",
            category: "required",
          },
        ],
        fieldCoverage: {
          totalRequired: 10,
          requiredPresent: 8,
          recommendedChecked: 5,
          sampleFields: ["name", "version", "description"],
          policiesChecked: ["required_fields", "recommended_fields"],
        },
        flagsForReview: [
          {
            field: "version",
            reason: "Invalid format",
            flags: ["error", "required"],
            riskLevel: "high",
          },
        ],
      },
    });

    expect(result.fieldInventory).toHaveLength(2);
    expect(result.fieldInventory![0].field).toBe("name");
    expect(result.fieldCoverage?.totalRequired).toBe(10);
    expect(result.flagsForReview).toHaveLength(1);
  });

  it("should truncate fieldInventory to 50 items", () => {
    const fields = Array(75)
      .fill(null)
      .map((_, i) => ({
        field: `field_${i}`,
        valid: true,
        severity: "INFO" as const,
        category: "optional",
      }));

    const result = buildManifestEnrichment({
      enrichmentData: { fieldInventory: fields },
    });

    expect(result.fieldInventory).toHaveLength(50);
  });

  it("should handle missing fields gracefully", () => {
    const result = buildManifestEnrichment({});

    expect(result.manifestMetrics.hasManifest).toBe(false);
    expect(result.manifestMetrics.hasRequiredFields).toBe(false);
    expect(result.manifestMetrics.totalChecks).toBe(0);
  });
});

// ============================================================================
// Enrichment Registry Tests (Issue #200 - V2 Refactoring)
// ============================================================================

describe("Enrichment Registry", () => {
  describe("getEnrichableModules", () => {
    it("should return all registered module names", () => {
      const modules = getEnrichableModules();

      expect(modules).toContain("aup");
      expect(modules).toContain("authentication");
      expect(modules).toContain("resources");
      expect(modules).toContain("prompts");
      expect(modules).toContain("prohibitedLibraries");
      expect(modules).toContain("manifestValidation");
      expect(modules).toHaveLength(6);
    });
  });

  describe("hasEnrichmentBuilder", () => {
    it("should return true for registered modules", () => {
      expect(hasEnrichmentBuilder("aup")).toBe(true);
      expect(hasEnrichmentBuilder("authentication")).toBe(true);
      expect(hasEnrichmentBuilder("resources")).toBe(true);
      expect(hasEnrichmentBuilder("prompts")).toBe(true);
      expect(hasEnrichmentBuilder("prohibitedLibraries")).toBe(true);
      expect(hasEnrichmentBuilder("manifestValidation")).toBe(true);
    });

    it("should return false for unregistered modules", () => {
      expect(hasEnrichmentBuilder("security")).toBe(false);
      expect(hasEnrichmentBuilder("functionality")).toBe(false);
      expect(hasEnrichmentBuilder("temporal")).toBe(false);
      expect(hasEnrichmentBuilder("unknown")).toBe(false);
    });

    // ========================================================================
    // Priority 2: Case-Sensitivity Documentation Tests (QA Analysis)
    // ========================================================================
    describe("case sensitivity", () => {
      it("should be case-sensitive for module names", () => {
        // Lowercase (correct) - should return true
        expect(hasEnrichmentBuilder("aup")).toBe(true);
        expect(hasEnrichmentBuilder("authentication")).toBe(true);

        // Uppercase (incorrect) - should return false
        expect(hasEnrichmentBuilder("AUP")).toBe(false);
        expect(hasEnrichmentBuilder("AUTHENTICATION")).toBe(false);

        // Mixed case (incorrect) - should return false
        expect(hasEnrichmentBuilder("Aup")).toBe(false);
        expect(hasEnrichmentBuilder("Authentication")).toBe(false);
      });

      it("should handle camelCase module names correctly", () => {
        // prohibitedLibraries is camelCase (correct)
        expect(hasEnrichmentBuilder("prohibitedLibraries")).toBe(true);

        // All lowercase or uppercase variants should return false
        expect(hasEnrichmentBuilder("prohibitedlibraries")).toBe(false);
        expect(hasEnrichmentBuilder("PROHIBITEDLIBRARIES")).toBe(false);
        expect(hasEnrichmentBuilder("ProhibitedLibraries")).toBe(false);
      });
    });
  });

  describe("buildEnrichment", () => {
    it("should return enrichment data for registered modules", () => {
      const aupResult = { violations: [] };
      const enrichment = buildEnrichment("aup", aupResult);

      expect(enrichment).not.toBeNull();
      expect(enrichment).toHaveProperty("violationsSample");
      expect(enrichment).toHaveProperty("violationMetrics");
    });

    it("should return null for unregistered modules", () => {
      const result = { someData: "test" };
      const enrichment = buildEnrichment("security", result);

      expect(enrichment).toBeNull();
    });

    it("should return null when result is null", () => {
      const enrichment = buildEnrichment("aup", null);

      expect(enrichment).toBeNull();
    });

    it("should return null when result is undefined", () => {
      const enrichment = buildEnrichment("aup", undefined);

      expect(enrichment).toBeNull();
    });

    // ========================================================================
    // Priority 2: Malformed Result Object Handling (QA Analysis)
    // ========================================================================
    describe("malformed result handling", () => {
      it("should handle string result gracefully", () => {
        const enrichment = buildEnrichment("aup", "invalid string result");

        // Should not throw, but may return empty or minimal enrichment
        expect(() => enrichment).not.toThrow();
      });

      it("should handle number result gracefully", () => {
        const enrichment = buildEnrichment("aup", 12345);

        // Should not throw, but may return empty or minimal enrichment
        expect(() => enrichment).not.toThrow();
      });

      it("should handle array result gracefully", () => {
        const enrichment = buildEnrichment("aup", [1, 2, 3]);

        // Should not throw, but may return empty or minimal enrichment
        expect(() => enrichment).not.toThrow();
      });

      it("should handle boolean result gracefully", () => {
        const enrichment = buildEnrichment("aup", true);

        // Should not throw, but may return empty or minimal enrichment
        expect(() => enrichment).not.toThrow();
      });

      it("should handle empty object gracefully", () => {
        const enrichment = buildEnrichment("aup", {});

        // Should not throw and return valid enrichment structure
        expect(enrichment).not.toBeNull();
        expect(enrichment).toHaveProperty("violationsSample");
        expect(enrichment).toHaveProperty("violationMetrics");
      });

      it("should handle object with unexpected properties gracefully", () => {
        const enrichment = buildEnrichment("aup", {
          unexpected: "field",
          random: 123,
          array: [1, 2, 3],
        });

        // Should not throw and return valid enrichment structure
        expect(enrichment).not.toBeNull();
        expect(enrichment).toHaveProperty("violationsSample");
        expect(enrichment).toHaveProperty("violationMetrics");
      });
    });

    it("should call correct builder for each module", () => {
      // AUP
      const aupResult = buildEnrichment("aup", { violations: [] });
      expect(aupResult).toHaveProperty("violationsSample");

      // Authentication
      const authResult = buildEnrichment("authentication", {
        authMethod: "oauth",
      });
      expect(authResult).toHaveProperty("authMethod");

      // Resources
      const resourceResult = buildEnrichment("resources", {
        resourcesTested: 5,
      });
      expect(resourceResult).toHaveProperty("resourceMetrics");

      // Prompts
      const promptResult = buildEnrichment("prompts", { promptsTested: 3 });
      expect(promptResult).toHaveProperty("promptMetrics");

      // Prohibited Libraries
      const libResult = buildEnrichment("prohibitedLibraries", { matches: [] });
      expect(libResult).toHaveProperty("libraryMetrics");

      // Manifest
      const manifestResult = buildEnrichment("manifestValidation", {
        hasManifest: true,
      });
      expect(manifestResult).toHaveProperty("manifestMetrics");
    });
  });
});
