/**
 * Stage B Enrichment Builder - AUP Module Tests
 *
 * Tests for buildAUPModuleStageBEnrichment function.
 * Issue #194: Stage B enrichment for AUP compliance module
 *
 * High-priority test gaps addressed:
 * - GAP-1: Unit tests for buildAUPModuleStageBEnrichment
 * - Test undefined enrichmentData input
 * - Test empty toolInventory handling
 * - Test maxInventoryItems truncation (>50 items)
 * - Test capabilityBreakdown aggregation
 * - Test flagsForReview mapping
 */

import { buildAUPModuleStageBEnrichment } from "../stageBEnrichmentBuilder";
import type { AUPEnrichmentData } from "../../extendedTypes";

describe("buildAUPModuleStageBEnrichment", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("edge cases", () => {
    it("should return undefined when enrichmentData is undefined", () => {
      const result = buildAUPModuleStageBEnrichment(undefined);

      expect(result).toBeUndefined();
    });

    it("should handle empty toolInventory", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [],
        patternCoverage: {
          totalPatterns: 100,
          categoriesCovered: ["A", "B", "C"],
          samplePatterns: ["pattern1", "pattern2"],
          severityBreakdown: {
            critical: 10,
            high: 20,
            medium: 30,
            flag: 40,
          },
        },
        flagsForReview: [],
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.toolInventory).toHaveLength(0);
      expect(result!.summary.totalTools).toBe(0);
      expect(result!.summary.toolsWithSensitiveCapabilities).toBe(0);
      expect(result!.summary.capabilityBreakdown).toEqual({});
    });

    it("should handle empty flagsForReview", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "safe_tool",
            description: "A safe tool",
            capabilities: ["unknown"],
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
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.flagsForReview).toHaveLength(0);
      expect(result!.summary.toolsWithSensitiveCapabilities).toBe(0);
    });
  });

  describe("toolInventory truncation", () => {
    it("should truncate toolInventory to maxInventoryItems when exceeding limit", () => {
      const tools = Array.from({ length: 75 }, (_, i) => ({
        name: `tool_${i}`,
        description: `Description for tool ${i}`,
        capabilities: [`capability_${i % 5}`],
      }));

      const enrichmentData: AUPEnrichmentData = {
        toolInventory: tools,
        patternCoverage: {
          totalPatterns: 100,
          categoriesCovered: ["A", "B"],
          samplePatterns: ["pattern1"],
          severityBreakdown: {
            critical: 10,
            high: 20,
            medium: 30,
            flag: 40,
          },
        },
        flagsForReview: [],
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData, 50);

      expect(result).toBeDefined();
      expect(result!.toolInventory).toHaveLength(50);
      expect(result!.toolInventory[0].name).toBe("tool_0");
      expect(result!.toolInventory[49].name).toBe("tool_49");
      expect(result!.summary.totalTools).toBe(75); // Original count preserved
    });

    it("should use default maxInventoryItems of 50", () => {
      const tools = Array.from({ length: 60 }, (_, i) => ({
        name: `tool_${i}`,
        description: "Test description",
        capabilities: ["file_system"],
      }));

      const enrichmentData: AUPEnrichmentData = {
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
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.toolInventory).toHaveLength(50);
    });

    it("should NOT truncate when under maxInventoryItems", () => {
      const tools = Array.from({ length: 30 }, (_, i) => ({
        name: `tool_${i}`,
        description: "Test description",
        capabilities: ["network"],
      }));

      const enrichmentData: AUPEnrichmentData = {
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
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData, 50);

      expect(result).toBeDefined();
      expect(result!.toolInventory).toHaveLength(30);
    });

    it("should truncate long descriptions for token efficiency", () => {
      const longDescription = "A".repeat(5000); // Very long description
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "tool_with_long_description",
            description: longDescription,
            capabilities: ["file_system"],
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
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.toolInventory[0].description.length).toBeLessThan(
        longDescription.length,
      );
      expect(result!.toolInventory[0].description.endsWith("...")).toBe(true);
    });
  });

  describe("capabilityBreakdown aggregation", () => {
    it("should aggregate capabilities across all tools", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "tool_1",
            description: "Tool 1",
            capabilities: ["file_system", "network"],
          },
          {
            name: "tool_2",
            description: "Tool 2",
            capabilities: ["file_system", "exec"],
          },
          {
            name: "tool_3",
            description: "Tool 3",
            capabilities: ["network", "database"],
          },
        ],
        patternCoverage: {
          totalPatterns: 100,
          categoriesCovered: ["A", "B"],
          samplePatterns: ["pattern1"],
          severityBreakdown: {
            critical: 0,
            high: 0,
            medium: 0,
            flag: 100,
          },
        },
        flagsForReview: [],
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.summary.capabilityBreakdown).toEqual({
        file_system: 2,
        network: 2,
        exec: 1,
        database: 1,
      });
    });

    it("should handle tools with multiple capabilities", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "multi_capability_tool",
            description: "A tool with many capabilities",
            capabilities: ["exec", "auth", "system", "network", "crypto"],
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
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.summary.capabilityBreakdown).toEqual({
        exec: 1,
        auth: 1,
        system: 1,
        network: 1,
        crypto: 1,
      });
    });

    it("should handle tools with no capabilities", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "tool_no_caps",
            description: "Tool with no capabilities",
            capabilities: [],
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
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.summary.capabilityBreakdown).toEqual({});
    });
  });

  describe("flagsForReview mapping", () => {
    it("should map flagsForReview fields correctly", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "exec_tool",
            description: "Executes commands",
            capabilities: ["exec"],
          },
        ],
        patternCoverage: {
          totalPatterns: 100,
          categoriesCovered: ["A"],
          samplePatterns: ["pattern1"],
          severityBreakdown: {
            critical: 10,
            high: 20,
            medium: 30,
            flag: 40,
          },
        },
        flagsForReview: [
          {
            toolName: "exec_tool",
            reason: "Tool has shell execution capabilities",
            capabilities: ["exec"],
            confidence: "low",
          },
          {
            toolName: "auth_tool",
            reason: "Tool handles authentication",
            capabilities: ["auth"],
            confidence: "medium",
          },
        ],
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.flagsForReview).toHaveLength(2);
      expect(result!.flagsForReview[0]).toEqual({
        toolName: "exec_tool",
        reason: "Tool has shell execution capabilities",
        capabilities: ["exec"],
        confidence: "low",
      });
      expect(result!.flagsForReview[1]).toEqual({
        toolName: "auth_tool",
        reason: "Tool handles authentication",
        capabilities: ["auth"],
        confidence: "medium",
      });
      expect(result!.summary.toolsWithSensitiveCapabilities).toBe(2);
    });

    it("should preserve all fields from flagsForReview", () => {
      const enrichmentData: AUPEnrichmentData = {
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
            toolName: "system_tool",
            reason: "System-level access",
            capabilities: ["system", "exec"],
            confidence: "high",
          },
        ],
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.flagsForReview[0].toolName).toBe("system_tool");
      expect(result!.flagsForReview[0].reason).toBe("System-level access");
      expect(result!.flagsForReview[0].capabilities).toEqual([
        "system",
        "exec",
      ]);
      expect(result!.flagsForReview[0].confidence).toBe("high");
    });
  });

  describe("patternCoverage preservation", () => {
    it("should preserve patternCoverage structure", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [],
        patternCoverage: {
          totalPatterns: 150,
          categoriesCovered: ["A", "B", "C", "D", "E"],
          samplePatterns: ["pattern1", "pattern2", "pattern3"],
          severityBreakdown: {
            critical: 15,
            high: 30,
            medium: 45,
            flag: 60,
          },
        },
        flagsForReview: [],
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.patternCoverage).toEqual({
        totalPatterns: 150,
        categoriesCovered: ["A", "B", "C", "D", "E"],
        samplePatterns: ["pattern1", "pattern2", "pattern3"],
        severityBreakdown: {
          critical: 15,
          high: 30,
          medium: 45,
          flag: 60,
        },
      });
    });
  });

  describe("summary field calculations", () => {
    it("should calculate summary fields correctly", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "tool_1",
            description: "Tool 1",
            capabilities: ["file_system"],
          },
          {
            name: "tool_2",
            description: "Tool 2",
            capabilities: ["network"],
          },
          {
            name: "tool_3",
            description: "Tool 3",
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
        flagsForReview: [
          {
            toolName: "tool_3",
            reason: "Exec capability",
            capabilities: ["exec"],
            confidence: "low",
          },
        ],
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.summary.totalTools).toBe(3);
      expect(result!.summary.toolsWithSensitiveCapabilities).toBe(1);
      expect(result!.summary.capabilityBreakdown).toEqual({
        file_system: 1,
        network: 1,
        exec: 1,
      });
    });

    it("should handle complex capability aggregation", () => {
      const enrichmentData: AUPEnrichmentData = {
        toolInventory: [
          {
            name: "tool_1",
            description: "Tool 1",
            capabilities: ["exec", "auth"],
          },
          {
            name: "tool_2",
            description: "Tool 2",
            capabilities: ["exec", "system"],
          },
          {
            name: "tool_3",
            description: "Tool 3",
            capabilities: ["auth", "crypto"],
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
      };

      const result = buildAUPModuleStageBEnrichment(enrichmentData);

      expect(result).toBeDefined();
      expect(result!.summary.capabilityBreakdown).toEqual({
        exec: 2,
        auth: 2,
        system: 1,
        crypto: 1,
      });
    });
  });
});
