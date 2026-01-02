/**
 * Module Field Validation Tests
 *
 * Tests that assessment module outputs contain required fields for scoring.
 * Catches field name mismatches like the v1.21.3 bug where calculateModuleScore()
 * checked for "workingPercentage" but FunctionalityAssessor returns "coveragePercentage".
 */

// Jest test suite for module field validation
import {
  validateModuleOutput,
  validateAllModuleOutputs,
  MODULE_FIELD_SPECS,
  isFunctionalityAssessment,
  isSecurityAssessment,
  isErrorHandlingAssessment,
} from "../moduleFieldValidator";
import { calculateModuleScore } from "../moduleScoring";

describe("moduleFieldValidator", () => {
  describe("validateModuleOutput", () => {
    it("should validate a complete functionality result", () => {
      const result = {
        totalTools: 10,
        testedTools: 8,
        workingTools: 7,
        brokenTools: ["broken_tool"],
        coveragePercentage: 70,
        status: "PASS",
        explanation: "Most tools working",
        toolResults: [],
      };

      const validation = validateModuleOutput("functionality", result);
      expect(validation.valid).toBe(true);
      expect(validation.missingFields).toHaveLength(0);
      expect(validation.scoringFieldMissing).toBe(false);
    });

    it("should detect missing coveragePercentage (v1.21.3 bug prevention)", () => {
      // This simulates the bug where workingPercentage was used instead of coveragePercentage
      const result = {
        totalTools: 10,
        testedTools: 8,
        workingTools: 7,
        brokenTools: ["broken_tool"],
        workingPercentage: 70, // WRONG field name - should be coveragePercentage
        status: "PASS",
        explanation: "Most tools working",
        toolResults: [],
      };

      const validation = validateModuleOutput("functionality", result);
      expect(validation.valid).toBe(false);
      expect(validation.missingFields).toContain("coveragePercentage");
      expect(validation.scoringFieldMissing).toBe(true);
      // Should suggest the similar field name
      expect(
        validation.warnings.some((w) => w.includes("coveragePercentage")),
      ).toBe(true);
    });

    it("should validate a complete security result", () => {
      const result = {
        promptInjectionTests: [],
        vulnerabilities: ["vuln1", "vuln2"],
        overallRiskLevel: "HIGH",
        status: "FAIL",
        explanation: "Vulnerabilities found",
      };

      const validation = validateModuleOutput("security", result);
      expect(validation.valid).toBe(true);
    });

    it("should validate errorHandling with nested mcpComplianceScore", () => {
      const result = {
        metrics: {
          mcpComplianceScore: 85,
          errorResponseQuality: "good",
          hasProperErrorCodes: true,
          hasDescriptiveMessages: true,
          validatesInputs: true,
        },
        status: "PASS",
        explanation: "Good error handling",
        recommendations: [],
      };

      const validation = validateModuleOutput("errorHandling", result);
      expect(validation.valid).toBe(true);
      expect(validation.scoringFieldMissing).toBe(false);
    });

    it("should detect missing nested mcpComplianceScore", () => {
      const result = {
        metrics: {
          // mcpComplianceScore is missing!
          errorResponseQuality: "good",
          hasProperErrorCodes: true,
          hasDescriptiveMessages: true,
          validatesInputs: true,
        },
        status: "PASS",
        explanation: "Good error handling",
        recommendations: [],
      };

      const validation = validateModuleOutput("errorHandling", result);
      expect(validation.scoringFieldMissing).toBe(true);
      expect(
        validation.warnings.some((w) => w.includes("mcpComplianceScore")),
      ).toBe(true);
    });

    it("should validate aupCompliance result", () => {
      const result = {
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
      };

      const validation = validateModuleOutput("aupCompliance", result);
      expect(validation.valid).toBe(true);
    });

    it("should validate mcpSpecCompliance result", () => {
      const result = {
        protocolVersion: "2025-06",
        protocolChecks: {
          jsonRpcCompliance: { passed: true, confidence: "high" },
          serverInfoValidity: { passed: true, confidence: "high" },
          schemaCompliance: { passed: true, confidence: "high" },
          errorResponseCompliance: { passed: true, confidence: "high" },
          structuredOutputSupport: { passed: true, confidence: "high" },
        },
        complianceScore: 100,
        status: "PASS",
        explanation: "Fully compliant",
        recommendations: [],
      };

      const validation = validateModuleOutput("mcpSpecCompliance", result);
      expect(validation.valid).toBe(true);
    });

    it("should return error for unknown module", () => {
      const result = { foo: "bar" };
      const validation = validateModuleOutput("unknownModule", result);
      expect(validation.valid).toBe(false);
      expect(validation.warnings).toContain("Unknown module: unknownModule");
    });

    it("should handle null result", () => {
      const validation = validateModuleOutput("functionality", null);
      expect(validation.valid).toBe(false);
      expect(validation.warnings).toContain("Result is null or not an object");
    });
  });

  describe("validateAllModuleOutputs", () => {
    it("should validate multiple modules at once", () => {
      const results = {
        functionality: {
          totalTools: 5,
          testedTools: 5,
          workingTools: 5,
          coveragePercentage: 100,
          status: "PASS",
          toolResults: [],
        },
        security: {
          promptInjectionTests: [],
          vulnerabilities: [],
          overallRiskLevel: "LOW",
          status: "PASS",
        },
      };

      const validations = validateAllModuleOutputs(results);
      expect(validations.size).toBe(2);
      expect(validations.get("functionality")?.valid).toBe(true);
      expect(validations.get("security")?.valid).toBe(true);
    });

    it("should catch field mismatches across multiple modules", () => {
      const results = {
        functionality: {
          totalTools: 5,
          testedTools: 5,
          workingTools: 5,
          workingPercentage: 100, // Wrong field name
          status: "PASS",
          toolResults: [],
        },
        errorHandling: {
          metrics: {}, // Missing mcpComplianceScore
          status: "PASS",
          recommendations: [],
        },
      };

      const validations = validateAllModuleOutputs(results);
      expect(validations.get("functionality")?.valid).toBe(false);
      expect(validations.get("errorHandling")?.scoringFieldMissing).toBe(true);
    });
  });

  describe("type guards", () => {
    it("isFunctionalityAssessment should validate correctly", () => {
      const valid = {
        totalTools: 5,
        testedTools: 5,
        workingTools: 5,
        coveragePercentage: 100,
        status: "PASS",
        toolResults: [],
      };
      const invalid = { foo: "bar" };

      expect(isFunctionalityAssessment(valid)).toBe(true);
      expect(isFunctionalityAssessment(invalid)).toBe(false);
    });

    it("isSecurityAssessment should validate correctly", () => {
      const valid = {
        promptInjectionTests: [],
        vulnerabilities: [],
        overallRiskLevel: "LOW",
        status: "PASS",
      };
      const invalid = { foo: "bar" };

      expect(isSecurityAssessment(valid)).toBe(true);
      expect(isSecurityAssessment(invalid)).toBe(false);
    });

    it("isErrorHandlingAssessment should validate correctly", () => {
      const valid = {
        metrics: {
          mcpComplianceScore: 100,
        },
        status: "PASS",
        recommendations: [],
      };
      const invalid = { foo: "bar" };

      expect(isErrorHandlingAssessment(valid)).toBe(true);
      expect(isErrorHandlingAssessment(invalid)).toBe(false);
    });
  });

  describe("integration with calculateModuleScore", () => {
    it("should validate that functionality scoring field is correct", () => {
      // This test ensures calculateModuleScore uses the same field name
      // that FunctionalityAssessor outputs
      const result = {
        coveragePercentage: 75,
        status: "PASS",
      };

      const score = calculateModuleScore(result);
      expect(score).toBe(75);

      // Verify the field spec matches
      const spec = MODULE_FIELD_SPECS.functionality;
      expect(spec.scoringField).toBe("coveragePercentage");
    });

    it("should validate that errorHandling scoring path is correct", () => {
      const result = {
        metrics: {
          mcpComplianceScore: 85,
        },
        status: "PASS",
      };

      const score = calculateModuleScore(result);
      expect(score).toBe(85);

      // Verify the field spec matches
      const spec = MODULE_FIELD_SPECS.errorHandling;
      expect(spec.scoringPath).toBe("metrics.mcpComplianceScore");
    });

    it("should validate that mcpSpecCompliance scoring field is correct", () => {
      const result = {
        complianceScore: 90,
        status: "PASS",
      };

      const score = calculateModuleScore(result);
      expect(score).toBe(90);

      // Verify the field spec matches
      const spec = MODULE_FIELD_SPECS.mcpSpecCompliance;
      expect(spec.scoringField).toBe("complianceScore");
    });

    it("should validate that security scoring uses vulnerabilities array", () => {
      const result = {
        vulnerabilities: ["v1", "v2", "v3"],
        status: "FAIL",
      };

      const score = calculateModuleScore(result);
      // Score should be 100 - (3 * 10) = 70
      expect(score).toBe(70);

      // Verify the field spec matches
      const spec = MODULE_FIELD_SPECS.security;
      expect(spec.scoringField).toBe("vulnerabilities");
    });

    it("should validate that aupCompliance scoring uses violations array", () => {
      const result = {
        violations: [{ category: "A" }, { category: "B" }],
        status: "FAIL",
      };

      const score = calculateModuleScore(result);
      // Score should be 100 - (2 * 10) = 80
      expect(score).toBe(80);

      // Verify the field spec matches
      const spec = MODULE_FIELD_SPECS.aupCompliance;
      expect(spec.scoringField).toBe("violations");
    });
  });

  describe("MODULE_FIELD_SPECS completeness", () => {
    it("should have specs for all core assessment modules", () => {
      const coreModules = [
        "functionality",
        "security",
        "documentation",
        "errorHandling",
        "usability",
      ];

      for (const mod of coreModules) {
        expect(MODULE_FIELD_SPECS[mod]).toBeDefined();
        expect(MODULE_FIELD_SPECS[mod].requiredFields.length).toBeGreaterThan(
          0,
        );
      }
    });

    it("should have specs for all extended assessment modules", () => {
      const extendedModules = [
        "mcpSpecCompliance",
        "aupCompliance",
        "toolAnnotations",
        "prohibitedLibraries",
        "manifestValidation",
        "portability",
        "externalAPIScanner",
        "authentication",
        "temporal",
        "resources",
        "prompts",
        "crossCapability",
      ];

      for (const mod of extendedModules) {
        expect(MODULE_FIELD_SPECS[mod]).toBeDefined();
        expect(MODULE_FIELD_SPECS[mod].requiredFields.length).toBeGreaterThan(
          0,
        );
      }
    });

    it("should have status as required field for all modules", () => {
      for (const [moduleName, spec] of Object.entries(MODULE_FIELD_SPECS)) {
        expect(spec.requiredFields).toContain("status");
      }
    });
  });
});
