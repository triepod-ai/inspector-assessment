/**
 * Tests for Assessment Configuration Zod Schemas
 *
 * Validates the schema definitions used for assessment configuration.
 *
 * @module assessment/__tests__/configSchemas
 */

// Uses Jest globals (describe, test, expect)
import { ZodError } from "zod";
import {
  LoggingConfigSchema,
  HttpTransportConfigSchema,
  ClaudeCodeFeaturesSchema,
  ClaudeCodeConfigSchema,
  AssessmentCategoriesSchema,
  DocumentationVerbositySchema,
  AssessmentConfigurationSchema,
  parseAssessmentConfig,
  safeParseAssessmentConfig,
  validateAssessmentConfig,
  validateClaudeCodeConfig,
  LogLevelSchema,
  ZOD_SCHEMA_VERSION,
} from "../configSchemas";

describe("configSchemas", () => {
  describe("Re-exported schemas", () => {
    test("exports ZOD_SCHEMA_VERSION", () => {
      expect(ZOD_SCHEMA_VERSION).toBe(1);
    });

    test("exports LogLevelSchema", () => {
      const validLevels = ["silent", "error", "warn", "info", "debug"];
      for (const level of validLevels) {
        expect(LogLevelSchema.safeParse(level).success).toBe(true);
      }
    });
  });

  describe("LoggingConfigSchema", () => {
    test("accepts all log levels", () => {
      const validLevels = ["silent", "error", "warn", "info", "debug"];
      for (const level of validLevels) {
        const result = LoggingConfigSchema.safeParse({ level });
        expect(result.success).toBe(true);
      }
    });

    test("accepts optional format field", () => {
      const textResult = LoggingConfigSchema.safeParse({
        level: "info",
        format: "text",
      });
      expect(textResult.success).toBe(true);

      const jsonResult = LoggingConfigSchema.safeParse({
        level: "info",
        format: "json",
      });
      expect(jsonResult.success).toBe(true);
    });

    test("accepts optional includeTimestamp field", () => {
      const result = LoggingConfigSchema.safeParse({
        level: "info",
        includeTimestamp: true,
      });
      expect(result.success).toBe(true);
    });

    test("rejects missing level", () => {
      const result = LoggingConfigSchema.safeParse({
        format: "json",
      });
      expect(result.success).toBe(false);
    });

    test("rejects invalid log level", () => {
      const result = LoggingConfigSchema.safeParse({
        level: "verbose",
      });
      expect(result.success).toBe(false);
    });

    test("rejects invalid format", () => {
      const result = LoggingConfigSchema.safeParse({
        level: "info",
        format: "xml",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("HttpTransportConfigSchema", () => {
    test("accepts valid baseUrl", () => {
      const result = HttpTransportConfigSchema.safeParse({
        baseUrl: "http://localhost:8085",
      });
      expect(result.success).toBe(true);
    });

    test("accepts optional apiKey", () => {
      const result = HttpTransportConfigSchema.safeParse({
        baseUrl: "http://localhost:8085",
        apiKey: "secret-key-123",
      });
      expect(result.success).toBe(true);
    });

    test("accepts optional headers record", () => {
      const result = HttpTransportConfigSchema.safeParse({
        baseUrl: "https://api.example.com",
        headers: {
          Authorization: "Bearer token",
          "Content-Type": "application/json",
        },
      });
      expect(result.success).toBe(true);
    });

    test("rejects invalid URL", () => {
      const result = HttpTransportConfigSchema.safeParse({
        baseUrl: "not-a-valid-url",
      });
      expect(result.success).toBe(false);
    });

    test("rejects missing baseUrl", () => {
      const result = HttpTransportConfigSchema.safeParse({
        apiKey: "some-key",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ClaudeCodeFeaturesSchema", () => {
    test("accepts all boolean fields", () => {
      const result = ClaudeCodeFeaturesSchema.safeParse({
        intelligentTestGeneration: true,
        aupSemanticAnalysis: false,
        annotationInference: true,
        documentationQuality: false,
      });
      expect(result.success).toBe(true);
    });

    test("rejects missing required fields", () => {
      const result = ClaudeCodeFeaturesSchema.safeParse({
        intelligentTestGeneration: true,
        // Missing other required fields
      });
      expect(result.success).toBe(false);
    });

    test("rejects non-boolean values", () => {
      const result = ClaudeCodeFeaturesSchema.safeParse({
        intelligentTestGeneration: "true", // string, not boolean
        aupSemanticAnalysis: true,
        annotationInference: true,
        documentationQuality: true,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ClaudeCodeConfigSchema", () => {
    const validFeatures = {
      intelligentTestGeneration: true,
      aupSemanticAnalysis: true,
      annotationInference: true,
      documentationQuality: true,
    };

    describe("basic validation", () => {
      test("accepts minimal valid config", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
        });
        expect(result.success).toBe(true);
      });

      test("accepts full config with all optional fields", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
          workingDir: "/home/user/project",
          maxRetries: 3,
          transport: "cli",
        });
        expect(result.success).toBe(true);
      });

      test("rejects negative timeout", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: -1,
        });
        expect(result.success).toBe(false);
      });

      test("rejects zero timeout", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 0,
        });
        expect(result.success).toBe(false);
      });

      test("rejects non-integer timeout", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30.5,
        });
        expect(result.success).toBe(false);
      });

      test("accepts zero maxRetries (nonnegative)", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
          maxRetries: 0,
        });
        expect(result.success).toBe(true);
      });

      test("rejects negative maxRetries", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
          maxRetries: -1,
        });
        expect(result.success).toBe(false);
      });
    });

    describe("refinement: http requires httpConfig", () => {
      test("accepts transport http with httpConfig", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
          transport: "http",
          httpConfig: {
            baseUrl: "http://localhost:8085",
          },
        });
        expect(result.success).toBe(true);
      });

      test("accepts transport cli without httpConfig", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
          transport: "cli",
        });
        expect(result.success).toBe(true);
      });

      test("accepts no transport without httpConfig", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
        });
        expect(result.success).toBe(true);
      });

      test("rejects transport http without httpConfig", () => {
        const result = ClaudeCodeConfigSchema.safeParse({
          enabled: true,
          features: validFeatures,
          timeout: 30000,
          transport: "http",
        });
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error.errors[0].message).toContain(
            "httpConfig is required when transport is 'http'",
          );
        }
      });
    });
  });

  describe("AssessmentCategoriesSchema", () => {
    test("accepts empty object (all optional)", () => {
      const result = AssessmentCategoriesSchema.safeParse({});
      expect(result.success).toBe(true);
    });

    test("accepts all boolean flags", () => {
      const result = AssessmentCategoriesSchema.safeParse({
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        protocolCompliance: true,
        aupCompliance: true,
        toolAnnotations: true,
        prohibitedLibraries: false,
        manifestValidation: true,
        portability: true,
        externalAPIScanner: false,
        authentication: true,
        temporal: true,
        resources: true,
        prompts: true,
        crossCapability: true,
        fileModularization: false,
      });
      expect(result.success).toBe(true);
    });

    test("accepts deprecated mcpSpecCompliance", () => {
      const result = AssessmentCategoriesSchema.safeParse({
        mcpSpecCompliance: true,
      });
      expect(result.success).toBe(true);
    });

    test("accepts deprecated protocolConformance", () => {
      const result = AssessmentCategoriesSchema.safeParse({
        protocolConformance: true,
      });
      expect(result.success).toBe(true);
    });

    test("rejects non-boolean values", () => {
      const result = AssessmentCategoriesSchema.safeParse({
        functionality: "true", // string, not boolean
      });
      expect(result.success).toBe(false);
    });
  });

  describe("DocumentationVerbositySchema", () => {
    test('accepts "minimal"', () => {
      const result = DocumentationVerbositySchema.safeParse("minimal");
      expect(result.success).toBe(true);
    });

    test('accepts "standard"', () => {
      const result = DocumentationVerbositySchema.safeParse("standard");
      expect(result.success).toBe(true);
    });

    test('accepts "verbose"', () => {
      const result = DocumentationVerbositySchema.safeParse("verbose");
      expect(result.success).toBe(true);
    });

    test("rejects invalid values", () => {
      const invalidValues = ["high", "low", "none", "", null];
      for (const value of invalidValues) {
        const result = DocumentationVerbositySchema.safeParse(value);
        expect(result.success).toBe(false);
      }
    });
  });

  describe("AssessmentConfigurationSchema", () => {
    const minimalValidConfig = {
      testTimeout: 30000,
      skipBrokenTools: true,
    };

    describe("required fields", () => {
      test("requires testTimeout", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          skipBrokenTools: true,
        });
        expect(result.success).toBe(false);
      });

      test("requires skipBrokenTools", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          testTimeout: 30000,
        });
        expect(result.success).toBe(false);
      });

      test("accepts minimal valid config", () => {
        const result =
          AssessmentConfigurationSchema.safeParse(minimalValidConfig);
        expect(result.success).toBe(true);
      });
    });

    describe("optional fields", () => {
      test("accepts configVersion", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          configVersion: 1,
        });
        expect(result.success).toBe(true);
      });

      test("accepts securityTestTimeout", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          securityTestTimeout: 60000,
        });
        expect(result.success).toBe(true);
      });

      test("accepts delayBetweenTests (including zero)", () => {
        const zeroResult = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          delayBetweenTests: 0,
        });
        expect(zeroResult.success).toBe(true);

        const positiveResult = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          delayBetweenTests: 1000,
        });
        expect(positiveResult.success).toBe(true);
      });

      test("accepts documentationVerbosity", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          documentationVerbosity: "verbose",
        });
        expect(result.success).toBe(true);
      });

      test("accepts selectedToolsForTesting as string array", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          selectedToolsForTesting: ["tool1", "tool2", "tool3"],
        });
        expect(result.success).toBe(true);
      });

      test("accepts nested claudeCode config", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          claudeCode: {
            enabled: true,
            features: {
              intelligentTestGeneration: true,
              aupSemanticAnalysis: true,
              annotationInference: true,
              documentationQuality: true,
            },
            timeout: 30000,
          },
        });
        expect(result.success).toBe(true);
      });

      test("accepts nested logging config", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          logging: {
            level: "debug",
            format: "json",
          },
        });
        expect(result.success).toBe(true);
      });

      test("accepts nested assessmentCategories config", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          assessmentCategories: {
            functionality: true,
            security: true,
          },
        });
        expect(result.success).toBe(true);
      });

      test("accepts deprecated maxToolsToTestForErrors", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          maxToolsToTestForErrors: 10,
        });
        expect(result.success).toBe(true);
      });
    });

    describe("validation", () => {
      test("rejects non-positive testTimeout", () => {
        const zeroResult = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          testTimeout: 0,
        });
        expect(zeroResult.success).toBe(false);

        const negativeResult = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          testTimeout: -1000,
        });
        expect(negativeResult.success).toBe(false);
      });

      test("rejects negative delayBetweenTests", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          delayBetweenTests: -100,
        });
        expect(result.success).toBe(false);
      });

      test("cascades nested schema errors", () => {
        const result = AssessmentConfigurationSchema.safeParse({
          ...minimalValidConfig,
          claudeCode: {
            enabled: true,
            features: {
              intelligentTestGeneration: true,
              aupSemanticAnalysis: true,
              annotationInference: true,
              documentationQuality: true,
            },
            timeout: 30000,
            transport: "http",
            // Missing httpConfig - should fail refinement
          },
        });
        expect(result.success).toBe(false);
      });
    });
  });

  describe("parseAssessmentConfig", () => {
    test("parses valid config", () => {
      const config = parseAssessmentConfig({
        testTimeout: 30000,
        skipBrokenTools: true,
      });
      expect(config.testTimeout).toBe(30000);
      expect(config.skipBrokenTools).toBe(true);
    });

    test("throws ZodError for invalid config", () => {
      expect(() =>
        parseAssessmentConfig({
          skipBrokenTools: true,
          // Missing testTimeout
        }),
      ).toThrow(ZodError);
    });
  });

  describe("safeParseAssessmentConfig", () => {
    test("returns success for valid config", () => {
      const result = safeParseAssessmentConfig({
        testTimeout: 30000,
        skipBrokenTools: true,
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.testTimeout).toBe(30000);
      }
    });

    test("returns error for invalid config", () => {
      const result = safeParseAssessmentConfig({
        testTimeout: -1000,
        skipBrokenTools: true,
      });
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeInstanceOf(ZodError);
      }
    });
  });

  describe("validateAssessmentConfig", () => {
    test("returns empty array for valid config", () => {
      const errors = validateAssessmentConfig({
        testTimeout: 30000,
        skipBrokenTools: true,
      });
      expect(errors).toEqual([]);
    });

    test("returns error messages for invalid config", () => {
      const errors = validateAssessmentConfig({
        skipBrokenTools: true,
        // Missing testTimeout
      });
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain("testTimeout");
    });
  });

  describe("validateClaudeCodeConfig", () => {
    const validFeatures = {
      intelligentTestGeneration: true,
      aupSemanticAnalysis: true,
      annotationInference: true,
      documentationQuality: true,
    };

    test("returns empty array for valid config", () => {
      const errors = validateClaudeCodeConfig({
        enabled: true,
        features: validFeatures,
        timeout: 30000,
      });
      expect(errors).toEqual([]);
    });

    test("returns error messages for invalid config", () => {
      const errors = validateClaudeCodeConfig({
        enabled: true,
        features: validFeatures,
        timeout: -1, // Invalid - must be positive
      });
      expect(errors.length).toBeGreaterThan(0);
    });

    test("returns error for missing httpConfig with http transport", () => {
      const errors = validateClaudeCodeConfig({
        enabled: true,
        features: validFeatures,
        timeout: 30000,
        transport: "http",
        // Missing httpConfig
      });
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain("httpConfig");
    });
  });
});
