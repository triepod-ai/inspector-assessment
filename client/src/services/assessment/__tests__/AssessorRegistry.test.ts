/**
 * AssessorRegistry Unit Tests
 *
 * Tests for the registry pattern implementation (Issue #91)
 *
 * @module assessment/__tests__/AssessorRegistry
 */

import { AssessorRegistry, ASSESSOR_DEFINITIONS } from "../registry";
import { AssessmentPhase } from "../registry/types";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessmentTypes";

describe("AssessorRegistry", () => {
  describe("constructor", () => {
    it("should initialize with empty assessors map", () => {
      const registry = new AssessorRegistry(DEFAULT_ASSESSMENT_CONFIG);
      expect(registry.size).toBe(0);
    });
  });

  describe("registerAll", () => {
    it("should register enabled assessors based on config", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      // Core assessors should be registered
      expect(registry.isRegistered("functionality")).toBe(true);
      expect(registry.isRegistered("security")).toBe(true);
      expect(registry.isRegistered("documentation")).toBe(true);
      expect(registry.isRegistered("errorHandling")).toBe(true);
      expect(registry.isRegistered("usability")).toBe(true);
    });

    it("should skip disabled assessors", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: false,
          security: true,
          documentation: false,
          errorHandling: false,
          usability: false,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(registry.isRegistered("functionality")).toBe(false);
      expect(registry.isRegistered("security")).toBe(true);
      expect(registry.isRegistered("documentation")).toBe(false);
    });

    it("should skip extended assessors when enableExtendedAssessment is false", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: false,
        assessmentCategories: {
          protocolCompliance: true,
          aupCompliance: true,
          toolAnnotations: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      // Extended assessors require enableExtendedAssessment
      expect(registry.isRegistered("protocolCompliance")).toBe(false);
      expect(registry.isRegistered("aupCompliance")).toBe(false);
      expect(registry.isRegistered("toolAnnotations")).toBe(false);
    });

    it("should register extended assessors when enableExtendedAssessment is true", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: true,
        assessmentCategories: {
          protocolCompliance: true,
          aupCompliance: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(registry.isRegistered("protocolCompliance")).toBe(true);
      expect(registry.isRegistered("aupCompliance")).toBe(true);
    });
  });

  describe("isEnabled (deprecated flag OR logic)", () => {
    it("should enable protocolCompliance with primary flag", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: true,
        assessmentCategories: {
          protocolCompliance: true,
          mcpSpecCompliance: false,
          protocolConformance: false,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(registry.isRegistered("protocolCompliance")).toBe(true);
    });

    it("should enable protocolCompliance with deprecated mcpSpecCompliance flag", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: true,
        assessmentCategories: {
          protocolCompliance: false,
          mcpSpecCompliance: true, // Deprecated BC flag
          protocolConformance: false,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(registry.isRegistered("protocolCompliance")).toBe(true);
    });

    it("should enable protocolCompliance with deprecated protocolConformance flag", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: true,
        assessmentCategories: {
          protocolCompliance: false,
          mcpSpecCompliance: false,
          protocolConformance: true, // Deprecated BC flag
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(registry.isRegistered("protocolCompliance")).toBe(true);
    });

    it("should not enable protocolCompliance when all flags are false", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: true,
        assessmentCategories: {
          protocolCompliance: false,
          mcpSpecCompliance: false,
          protocolConformance: false,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(registry.isRegistered("protocolCompliance")).toBe(false);
    });
  });

  describe("getByPhase", () => {
    it("should return assessors grouped by phase", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      const coreAssessors = registry.getByPhase(AssessmentPhase.CORE);
      expect(coreAssessors.length).toBeGreaterThan(0);

      // All returned assessors should be in CORE phase
      for (const assessor of coreAssessors) {
        expect(assessor.definition.phase).toBe(AssessmentPhase.CORE);
      }
    });

    it("should return empty array for phases with no registered assessors", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: false,
        assessmentCategories: {
          functionality: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      // PRE phase requires extended assessment for Temporal
      const preAssessors = registry.getByPhase(AssessmentPhase.PRE);
      expect(preAssessors.length).toBe(0);
    });
  });

  describe("getAssessor", () => {
    it("should return assessor instance by id", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      const assessor = registry.getAssessor("functionality");
      expect(assessor).toBeDefined();
      expect(typeof assessor?.assess).toBe("function");
    });

    it("should return undefined for unregistered assessor", () => {
      const registry = new AssessorRegistry(DEFAULT_ASSESSMENT_CONFIG);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      const assessor = registry.getAssessor("nonexistent");
      expect(assessor).toBeUndefined();
    });
  });

  describe("getTotalTestCount", () => {
    it("should aggregate test counts from all registered assessors", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: true,
          security: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      // Initial test count should be 0 (no assessments run yet)
      const totalCount = registry.getTotalTestCount();
      expect(totalCount).toBe(0);
    });
  });

  describe("resetAllTestCounts", () => {
    it("should not throw when called", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(() => registry.resetAllTestCounts()).not.toThrow();
    });
  });

  describe("getRegisteredIds", () => {
    it("should return array of registered assessor ids", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      const ids = registry.getRegisteredIds();
      expect(ids).toContain("functionality");
      expect(ids).toContain("security");
      expect(ids).toContain("documentation");
    });
  });

  describe("size", () => {
    it("should return count of registered assessors", () => {
      const config = {
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: true,
          security: true,
          // Explicitly disable others that might be default-enabled
          documentation: false,
          errorHandling: false,
          usability: false,
        },
      };
      const registry = new AssessorRegistry(config);
      registry.registerAll(ASSESSOR_DEFINITIONS);

      expect(registry.size).toBe(2);
    });
  });
});
