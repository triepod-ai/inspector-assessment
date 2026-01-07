/**
 * AssessmentOrchestrator Unit Tests
 *
 * Tests for the AssessmentOrchestrator class behavior:
 * - Constructor initialization based on config
 * - Tool filtering with getToolCountForTesting
 * - Configuration accessors (getConfig, updateConfig)
 * - Claude Code bridge management
 */

import { AssessmentOrchestrator } from "../AssessmentOrchestrator";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
} from "@/lib/assessmentTypes";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Helper to create a minimal config
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): Partial<AssessmentConfiguration> => ({
  ...overrides,
});

// Helper to create mock tools
const createMockTools = (count: number): Tool[] =>
  Array(count)
    .fill(null)
    .map((_, i) => ({
      name: `tool-${i}`,
      description: `Test tool ${i}`,
      inputSchema: { type: "object" as const, properties: {} },
    }));

describe("AssessmentOrchestrator constructor", () => {
  describe("default initialization", () => {
    it("should initialize with default config when no config provided", () => {
      const orchestrator = new AssessmentOrchestrator();
      const config = orchestrator.getConfig();

      expect(config.testTimeout).toBe(DEFAULT_ASSESSMENT_CONFIG.testTimeout);
      expect(config.skipBrokenTools).toBe(
        DEFAULT_ASSESSMENT_CONFIG.skipBrokenTools,
      );
    });

    it("should merge provided config with defaults", () => {
      const orchestrator = new AssessmentOrchestrator({
        testTimeout: 10000,
        skipBrokenTools: true,
      });
      const config = orchestrator.getConfig();

      expect(config.testTimeout).toBe(10000);
      expect(config.skipBrokenTools).toBe(true);
    });
  });

  describe("core assessor initialization", () => {
    it("should initialize all core assessors with default config", () => {
      const orchestrator = new AssessmentOrchestrator();

      // Core assessors are initialized by default - verify through config
      const config = orchestrator.getConfig();
      expect(config.assessmentCategories?.functionality).not.toBe(false);
      expect(config.assessmentCategories?.security).not.toBe(false);
      expect(config.assessmentCategories?.documentation).not.toBe(false);
    });

    it("should skip functionality assessor when disabled in config", () => {
      const orchestrator = new AssessmentOrchestrator({
        assessmentCategories: {
          functionality: false,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
        },
      });

      const config = orchestrator.getConfig();
      expect(config.assessmentCategories?.functionality).toBe(false);
    });

    it("should skip security assessor when disabled in config", () => {
      const orchestrator = new AssessmentOrchestrator({
        assessmentCategories: {
          functionality: true,
          security: false,
          documentation: true,
          errorHandling: true,
          usability: true,
        },
      });

      const config = orchestrator.getConfig();
      expect(config.assessmentCategories?.security).toBe(false);
    });
  });

  describe("extended assessor initialization", () => {
    it("should initialize extended assessors when enableExtendedAssessment true", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: true,
          aupCompliance: true,
          toolAnnotations: true,
        },
      });

      const config = orchestrator.getConfig();
      expect(config.enableExtendedAssessment).toBe(true);
      expect(config.assessmentCategories?.protocolCompliance).toBe(true);
      expect(config.assessmentCategories?.aupCompliance).toBe(true);
    });

    it("should not initialize extended assessors when enableExtendedAssessment false", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: false,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: true, // Ignored because enableExtendedAssessment is false
        },
      });

      const config = orchestrator.getConfig();
      expect(config.enableExtendedAssessment).toBe(false);
    });
  });

  /**
   * Protocol Compliance Backwards Compatibility Tests (v1.25.2)
   *
   * These tests verify that deprecated config flags (mcpSpecCompliance, protocolConformance)
   * still initialize the unified ProtocolComplianceAssessor correctly.
   *
   * The orchestrator uses OR logic to accept any of three flags:
   * - protocolCompliance (new, preferred)
   * - mcpSpecCompliance (deprecated, BC)
   * - protocolConformance (deprecated, BC)
   */
  describe("protocol compliance backwards compatibility", () => {
    it("should accept protocolCompliance flag (new preferred flag)", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: true,
          mcpSpecCompliance: false,
          protocolConformance: false,
        },
      });

      const config = orchestrator.getConfig();
      expect(config.assessmentCategories?.protocolCompliance).toBe(true);
      // Verify assessor is accessible via private property (internal check)
      expect(
        (orchestrator as unknown as { protocolComplianceAssessor: unknown })
          .protocolComplianceAssessor,
      ).toBeDefined();
    });

    it("should accept deprecated mcpSpecCompliance flag for BC", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: false,
          mcpSpecCompliance: true, // Deprecated but should still work
          protocolConformance: false,
        },
      });

      const config = orchestrator.getConfig();
      expect(config.assessmentCategories?.mcpSpecCompliance).toBe(true);
      // The unified assessor should be initialized due to BC OR logic
      expect(
        (orchestrator as unknown as { protocolComplianceAssessor: unknown })
          .protocolComplianceAssessor,
      ).toBeDefined();
    });

    it("should accept deprecated protocolConformance flag for BC", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: false,
          mcpSpecCompliance: false,
          protocolConformance: true, // Deprecated but should still work
        },
      });

      const config = orchestrator.getConfig();
      expect(config.assessmentCategories?.protocolConformance).toBe(true);
      // The unified assessor should be initialized due to BC OR logic
      expect(
        (orchestrator as unknown as { protocolComplianceAssessor: unknown })
          .protocolComplianceAssessor,
      ).toBeDefined();
    });

    it("should not initialize assessor when all protocol flags are false", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: false,
          mcpSpecCompliance: false,
          protocolConformance: false,
        },
      });

      // No protocol assessor should be initialized
      expect(
        (orchestrator as unknown as { protocolComplianceAssessor: unknown })
          .protocolComplianceAssessor,
      ).toBeUndefined();
    });

    it("should only initialize one assessor even with multiple flags true", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: true,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: true,
          mcpSpecCompliance: true, // Also true, but should not cause duplicate
          protocolConformance: true, // Also true, but should not cause duplicate
        },
      });

      // Should have exactly one assessor instance
      const assessor = (
        orchestrator as unknown as { protocolComplianceAssessor: unknown }
      ).protocolComplianceAssessor;
      expect(assessor).toBeDefined();
      // Verify it's a single instance (not array)
      expect(Array.isArray(assessor)).toBe(false);
    });

    it("should not initialize assessor when enableExtendedAssessment is false even with BC flags true", () => {
      const orchestrator = new AssessmentOrchestrator({
        enableExtendedAssessment: false, // This guard should prevent initialization
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          protocolCompliance: true, // Ignored because enableExtendedAssessment is false
          mcpSpecCompliance: true, // BC flag true, but should be ignored
          protocolConformance: true, // BC flag true, but should be ignored
        },
      });

      // No protocol assessor should be initialized due to enableExtendedAssessment guard
      expect(
        (orchestrator as unknown as { protocolComplianceAssessor: unknown })
          .protocolComplianceAssessor,
      ).toBeUndefined();
    });
  });
});

describe("Claude Code Bridge", () => {
  it("should not have Claude enabled by default", () => {
    const orchestrator = new AssessmentOrchestrator();

    expect(orchestrator.isClaudeEnabled()).toBe(false);
    expect(orchestrator.getClaudeBridge()).toBeUndefined();
  });

  it("should enable Claude when configured", () => {
    const orchestrator = new AssessmentOrchestrator({
      claudeCode: {
        enabled: true,
        timeout: 30000,
        features: {
          intelligentTestGeneration: false,
          aupSemanticAnalysis: false,
          annotationInference: false,
          documentationQuality: false,
        },
      },
    });

    // Note: Claude bridge may not initialize if Claude Code is not available
    // This tests the config is set correctly
    const config = orchestrator.getConfig();
    expect(config.claudeCode?.enabled).toBe(true);
  });

  it("should enable Claude programmatically", () => {
    const orchestrator = new AssessmentOrchestrator();

    // Before enabling
    expect(orchestrator.isClaudeEnabled()).toBe(false);

    // Enable programmatically (may fail if Claude not available, which is OK)
    orchestrator.enableClaudeCode({
      features: {
        intelligentTestGeneration: false,
        aupSemanticAnalysis: false,
        annotationInference: false,
        documentationQuality: false,
      },
    });

    // Config should reflect the attempt
    const config = orchestrator.getConfig();
    // This test verifies the method doesn't throw, not that Claude is actually enabled
    expect(config).toBeDefined();
  });
});

describe("getToolCountForTesting", () => {
  // Access private method for testing
  const getToolCount = (
    orchestrator: AssessmentOrchestrator,
    tools: Tool[],
  ): number => {
    return (
      orchestrator as unknown as {
        getToolCountForTesting: (tools: Tool[]) => number;
      }
    ).getToolCountForTesting(tools);
  };

  it("should return all tools when no selectedToolsForTesting", () => {
    const orchestrator = new AssessmentOrchestrator();
    const tools = createMockTools(5);

    const count = getToolCount(orchestrator, tools);

    expect(count).toBe(5);
  });

  it("should filter tools by selectedToolsForTesting names", () => {
    const orchestrator = new AssessmentOrchestrator({
      selectedToolsForTesting: ["tool-1", "tool-3"],
    });
    const tools = createMockTools(5);

    const count = getToolCount(orchestrator, tools);

    expect(count).toBe(2);
  });

  it("should return 0 for empty selectedToolsForTesting", () => {
    const orchestrator = new AssessmentOrchestrator({
      selectedToolsForTesting: [],
    });
    const tools = createMockTools(5);

    const count = getToolCount(orchestrator, tools);

    expect(count).toBe(0);
  });

  it("should return 0 for no matching tools", () => {
    const orchestrator = new AssessmentOrchestrator({
      selectedToolsForTesting: ["nonexistent-tool"],
    });
    const tools = createMockTools(5);

    const count = getToolCount(orchestrator, tools);

    expect(count).toBe(0);
  });
});

describe("getConfig / updateConfig", () => {
  it("should return current configuration", () => {
    const orchestrator = new AssessmentOrchestrator({
      testTimeout: 15000,
    });

    const config = orchestrator.getConfig();

    expect(config.testTimeout).toBe(15000);
  });

  it("should merge partial config updates", () => {
    const orchestrator = new AssessmentOrchestrator({
      testTimeout: 5000,
      skipBrokenTools: false,
    });

    orchestrator.updateConfig({
      skipBrokenTools: true,
    });

    const config = orchestrator.getConfig();
    expect(config.testTimeout).toBe(5000); // Unchanged
    expect(config.skipBrokenTools).toBe(true); // Updated
  });

  it("should preserve existing config on partial update", () => {
    const orchestrator = new AssessmentOrchestrator({
      testTimeout: 10000,
      delayBetweenTests: 100,
      skipBrokenTools: true,
    });

    orchestrator.updateConfig({
      testTimeout: 20000,
    });

    const config = orchestrator.getConfig();
    expect(config.testTimeout).toBe(20000);
    expect(config.delayBetweenTests).toBe(100);
    expect(config.skipBrokenTools).toBe(true);
  });
});
