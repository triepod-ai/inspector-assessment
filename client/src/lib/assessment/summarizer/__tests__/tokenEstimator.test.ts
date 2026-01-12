/**
 * Token Estimator Unit Tests
 *
 * Tests for token estimation and auto-tier threshold detection.
 * Issue #136: Tiered output strategy for large assessments
 */

// Jest test file
import {
  estimateTokens,
  estimateJsonFileTokens,
  shouldAutoTier,
  formatTokenEstimate,
  estimateSectionTokens,
  getTopSections,
} from "../tokenEstimator";
import type { MCPDirectoryAssessment } from "../../resultTypes";

describe("tokenEstimator", () => {
  describe("estimateTokens", () => {
    it("should estimate tokens for a simple string", () => {
      const text = "Hello, world!"; // 13 chars
      const tokens = estimateTokens(text);
      expect(tokens).toBe(4); // ceil(13/4) = 4
    });

    it("should estimate tokens for an object", () => {
      const obj = { name: "test", value: 123 };
      const tokens = estimateTokens(obj);
      // JSON.stringify(obj, null, 2) adds formatting
      expect(tokens).toBeGreaterThan(0);
    });

    it("should return 0 for null/undefined", () => {
      expect(estimateTokens(null)).toBe(0);
      expect(estimateTokens(undefined)).toBe(0);
    });

    it("should handle arrays", () => {
      const arr = [1, 2, 3, 4, 5];
      const tokens = estimateTokens(arr);
      expect(tokens).toBeGreaterThan(0);
    });

    it("should handle large objects", () => {
      const largeObj = { data: "x".repeat(1000) };
      const tokens = estimateTokens(largeObj);
      expect(tokens).toBeGreaterThan(250); // ~1000 chars / 4 = ~250 tokens
    });
  });

  describe("estimateJsonFileTokens", () => {
    it("should estimate tokens for JSON file content", () => {
      const obj = { key: "value" };
      const tokens = estimateJsonFileTokens(obj);
      expect(tokens).toBeGreaterThan(0);
    });

    it("should return 0 for null", () => {
      expect(estimateJsonFileTokens(null)).toBe(0);
    });
  });

  describe("shouldAutoTier", () => {
    it("should return false for small results", () => {
      const smallResults = {
        serverName: "test",
        overallStatus: "PASS",
        functionality: { totalTools: 1 },
      } as unknown as MCPDirectoryAssessment;

      expect(shouldAutoTier(smallResults)).toBe(false);
    });

    it("should return true for large results exceeding threshold", () => {
      // Create a large results object
      const largeData = "x".repeat(500000); // ~500K chars = ~125K tokens
      const largeResults = {
        serverName: "test",
        overallStatus: "PASS",
        summary: largeData,
      } as unknown as MCPDirectoryAssessment;

      expect(shouldAutoTier(largeResults)).toBe(true);
    });

    it("should respect custom threshold", () => {
      const mediumResults = {
        serverName: "test",
        summary: "x".repeat(50000), // ~50K chars = ~12.5K tokens
      } as unknown as MCPDirectoryAssessment;

      expect(shouldAutoTier(mediumResults, 10000)).toBe(true);
      expect(shouldAutoTier(mediumResults, 20000)).toBe(false);
    });
  });

  describe("formatTokenEstimate", () => {
    it("should categorize small token counts", () => {
      const result = formatTokenEstimate(5000);
      expect(result.category).toBe("small");
      expect(result.fitsContext).toBe(true);
    });

    it("should categorize medium token counts", () => {
      const result = formatTokenEstimate(30000);
      expect(result.category).toBe("medium");
      expect(result.fitsContext).toBe(true);
    });

    it("should categorize large token counts", () => {
      const result = formatTokenEstimate(80000);
      expect(result.category).toBe("large");
      expect(result.fitsContext).toBe(true);
    });

    it("should categorize very-large token counts", () => {
      const result = formatTokenEstimate(150000);
      expect(result.category).toBe("very-large");
      expect(result.fitsContext).toBe(false);
    });

    it("should categorize oversized token counts", () => {
      const result = formatTokenEstimate(300000);
      expect(result.category).toBe("oversized");
      expect(result.fitsContext).toBe(false);
      expect(result.recommendation).toContain("required");
    });

    it("should format token count with commas", () => {
      const result = formatTokenEstimate(1234567);
      expect(result.tokens).toBe("1,234,567");
    });
  });

  describe("estimateSectionTokens", () => {
    it("should estimate tokens for each section", () => {
      const results = {
        serverName: "test",
        overallStatus: "PASS",
        functionality: {
          totalTools: 5,
          testedTools: 5,
          workingTools: 5,
          brokenTools: [],
        },
        security: {
          promptInjectionTests: [],
          vulnerabilities: [],
          overallRiskLevel: "LOW",
          status: "PASS",
        },
      } as unknown as MCPDirectoryAssessment;

      const sections = estimateSectionTokens(results);

      expect(sections).toHaveProperty("functionality");
      expect(sections).toHaveProperty("security");
      expect(sections).toHaveProperty("metadata");
      expect(sections).toHaveProperty("_total");
      expect(sections._total).toBeGreaterThan(0);
    });

    it("should skip undefined sections", () => {
      const results = {
        serverName: "test",
        overallStatus: "PASS",
        functionality: { totalTools: 1 },
        // security: undefined (missing)
      } as unknown as MCPDirectoryAssessment;

      const sections = estimateSectionTokens(results);

      expect(sections).toHaveProperty("functionality");
      expect(sections).not.toHaveProperty("security");
    });
  });

  describe("getTopSections", () => {
    it("should return top sections by size", () => {
      const results = {
        serverName: "test",
        overallStatus: "PASS",
        summary: "x".repeat(1000), // Largest
        functionality: { totalTools: 1 },
        security: { status: "PASS" },
      } as unknown as MCPDirectoryAssessment;

      const top = getTopSections(results, 3);

      expect(top.length).toBeLessThanOrEqual(3);
      // First item should be largest
      if (top.length > 1) {
        expect(top[0][1]).toBeGreaterThanOrEqual(top[1][1]);
      }
    });

    it("should respect topN limit", () => {
      const results = {
        serverName: "test",
        overallStatus: "PASS",
        functionality: {},
        security: {},
        errorHandling: {},
        aupCompliance: {},
      } as unknown as MCPDirectoryAssessment;

      const top2 = getTopSections(results, 2);
      expect(top2.length).toBeLessThanOrEqual(2);
    });
  });
});
