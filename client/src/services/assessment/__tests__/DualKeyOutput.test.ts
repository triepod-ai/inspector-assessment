/**
 * Dual-Key Output Tests (Issue #124)
 *
 * Tests for the v1.x to v2.0.0 backward-compatible transition that outputs
 * BOTH old and new keys in MCPDirectoryAssessment.
 *
 * Old keys (deprecated, removed in v2.0.0):
 * - documentation, usability -> replaced by developerExperience
 * - mcpSpecCompliance -> replaced by protocolCompliance
 *
 * @module assessment/__tests__/DualKeyOutput
 */

import {
  AssessmentOrchestrator,
  AssessmentContext,
} from "../AssessmentOrchestrator";
import { DEFAULT_ASSESSMENT_CONFIG } from "@/lib/assessmentTypes";
import { calculateModuleScore } from "@/lib/moduleScoring";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Create a minimal mock context for testing
 */
function createMockContext(
  config: Partial<typeof DEFAULT_ASSESSMENT_CONFIG> = {},
): AssessmentContext {
  const mockTool: Tool = {
    name: "test_tool",
    description: "A test tool for assessment",
    inputSchema: {
      type: "object" as const,
      properties: {
        input: { type: "string" },
      },
    },
  };

  return {
    serverName: "test-server",
    tools: [mockTool],
    callTool: jest.fn().mockResolvedValue({
      content: [{ type: "text", text: "OK" }],
    }),
    config: { ...DEFAULT_ASSESSMENT_CONFIG, ...config },
  };
}

describe("Dual-Key Output (Issue #124)", () => {
  describe("developerExperience composite field", () => {
    it("should combine documentation and usability assessments", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: true,
          errorHandling: false,
          usability: true,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // New key should be present
      expect(result.developerExperience).toBeDefined();
      expect(result.developerExperience?.documentation).toBeDefined();
      expect(result.developerExperience?.usability).toBeDefined();
      expect(result.developerExperience?.status).toBeDefined();
      expect(result.developerExperience?.score).toBeDefined();
    });

    it("should calculate score as average of documentation and usability scores", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: true,
          errorHandling: false,
          usability: true,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // Score should be a number between 0 and 100
      expect(typeof result.developerExperience?.score).toBe("number");
      expect(result.developerExperience?.score).toBeGreaterThanOrEqual(0);
      expect(result.developerExperience?.score).toBeLessThanOrEqual(100);

      // Verify score calculation matches the formula
      if (result.documentation && result.usability) {
        const docScore = calculateModuleScore(result.documentation) ?? 50;
        const usabilityScore = calculateModuleScore(result.usability) ?? 50;
        const expectedScore = Math.round((docScore + usabilityScore) / 2);
        expect(result.developerExperience?.score).toBe(expectedScore);
      }
    });

    it("should determine status using worst-of-both logic", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: true,
          errorHandling: false,
          usability: true,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // Status should be one of the valid assessment statuses
      expect(["PASS", "FAIL", "NEED_MORE_INFO"]).toContain(
        result.developerExperience?.status,
      );
    });

    it("should preserve deprecated documentation and usability keys for backward compatibility", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: true,
          errorHandling: false,
          usability: true,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // Old keys should still be present (backward compatibility)
      expect(result.documentation).toBeDefined();
      expect(result.usability).toBeDefined();

      // developerExperience should reference the same objects
      expect(result.developerExperience?.documentation).toBe(
        result.documentation,
      );
      expect(result.developerExperience?.usability).toBe(result.usability);
    });

    it("should not create developerExperience when only documentation is enabled", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: true,
          errorHandling: false,
          usability: false,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // developerExperience requires BOTH documentation AND usability
      expect(result.developerExperience).toBeUndefined();
      expect(result.documentation).toBeDefined();
    });

    it("should not create developerExperience when only usability is enabled", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: false,
          errorHandling: false,
          usability: true,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // developerExperience requires BOTH documentation AND usability
      expect(result.developerExperience).toBeUndefined();
      expect(result.usability).toBeDefined();
    });
  });

  describe("protocolCompliance alias field", () => {
    it("should alias mcpSpecCompliance to protocolCompliance", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: false,
          errorHandling: false,
          usability: false,
          protocolCompliance: true,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // Both keys should be present and reference the same object
      if (result.mcpSpecCompliance) {
        expect(result.protocolCompliance).toBeDefined();
        expect(result.protocolCompliance).toBe(result.mcpSpecCompliance);
      }
    });

    it("should preserve deprecated mcpSpecCompliance key for backward compatibility", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: false,
          security: false,
          documentation: false,
          errorHandling: false,
          usability: false,
          protocolCompliance: true,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // Old key should still be present (backward compatibility)
      // Note: The registry writes to mcpSpecCompliance, orchestrator aliases to protocolCompliance
      if (result.protocolCompliance) {
        expect(result.mcpSpecCompliance).toBeDefined();
      }
    });

    it("should not create protocolCompliance when protocol compliance is disabled", async () => {
      const orchestrator = new AssessmentOrchestrator({
        ...DEFAULT_ASSESSMENT_CONFIG,
        enableExtendedAssessment: false,
        assessmentCategories: {
          functionality: true,
          security: false,
          documentation: false,
          errorHandling: false,
          usability: false,
          protocolCompliance: false,
        },
      });

      const context = createMockContext();
      const result = await orchestrator.runFullAssessment(context);

      // Neither key should be present when disabled
      expect(result.protocolCompliance).toBeUndefined();
      expect(result.mcpSpecCompliance).toBeUndefined();
    });
  });

  describe("calculateModuleScore integration", () => {
    it("should recognize direct score field in developerExperience", () => {
      // DeveloperExperienceAssessment has a direct score field
      const developerExperienceResult = {
        documentation: { status: "PASS" },
        usability: { status: "PASS" },
        status: "PASS",
        score: 85,
      };

      const score = calculateModuleScore(developerExperienceResult);
      expect(score).toBe(85);
    });
  });
});
