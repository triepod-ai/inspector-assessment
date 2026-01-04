import { calculateModuleScore, normalizeModuleKey } from "../moduleScoring";

describe("moduleScoring", () => {
  describe("normalizeModuleKey", () => {
    it("should convert to lowercase", () => {
      expect(normalizeModuleKey("Functionality")).toBe("functionality");
    });

    it("should replace spaces with underscores", () => {
      expect(normalizeModuleKey("Error Handling")).toBe("error_handling");
    });

    it("should handle multiple words", () => {
      expect(normalizeModuleKey("MCP Spec Compliance")).toBe(
        "mcp_spec_compliance",
      );
    });
  });

  describe("calculateModuleScore", () => {
    describe("functionality module", () => {
      it("should use coveragePercentage for functionality score", () => {
        const result = {
          coveragePercentage: 84.6,
          status: "PASS",
        };
        expect(calculateModuleScore(result)).toBe(85); // Rounded from 84.6
      });

      it("should not fallthrough to status-based scoring when coveragePercentage exists", () => {
        // This is the critical test - even with PASS status, score should be
        // based on coveragePercentage, not the status fallback
        const result = {
          coveragePercentage: 50,
          status: "PASS", // Would return 100 if fallthrough occurred
        };
        expect(calculateModuleScore(result)).toBe(50);
      });

      it("should round coveragePercentage correctly", () => {
        expect(calculateModuleScore({ coveragePercentage: 84.4 })).toBe(84);
        expect(calculateModuleScore({ coveragePercentage: 84.5 })).toBe(85);
        expect(calculateModuleScore({ coveragePercentage: 84.6 })).toBe(85);
      });

      it("should handle 0% coverage", () => {
        const result = {
          coveragePercentage: 0,
          status: "FAIL",
        };
        expect(calculateModuleScore(result)).toBe(0);
      });

      it("should handle 100% coverage", () => {
        const result = {
          coveragePercentage: 100,
          status: "PASS",
        };
        expect(calculateModuleScore(result)).toBe(100);
      });
    });

    describe("error handling module", () => {
      it("should use metrics.mcpComplianceScore", () => {
        const result = {
          metrics: {
            mcpComplianceScore: 75.5,
          },
        };
        expect(calculateModuleScore(result)).toBe(76);
      });
    });

    describe("MCP spec compliance module", () => {
      it("should use complianceScore", () => {
        const result = {
          complianceScore: 83.2,
        };
        expect(calculateModuleScore(result)).toBe(83);
      });
    });

    describe("security module", () => {
      it("should return 100 for no vulnerabilities", () => {
        const result = {
          vulnerabilities: [],
        };
        expect(calculateModuleScore(result)).toBe(100);
      });

      it("should reduce score by 10 per vulnerability", () => {
        const result = {
          vulnerabilities: ["vuln1", "vuln2"],
        };
        expect(calculateModuleScore(result)).toBe(80);
      });

      it("should not go below 0", () => {
        const result = {
          vulnerabilities: Array(15).fill("vuln"),
        };
        expect(calculateModuleScore(result)).toBe(0);
      });
    });

    describe("AUP compliance module", () => {
      it("should return 100 for no violations", () => {
        const result = {
          violations: [],
        };
        expect(calculateModuleScore(result)).toBe(100);
      });

      it("should reduce score by 10 per violation", () => {
        const result = {
          violations: ["violation1"],
        };
        expect(calculateModuleScore(result)).toBe(90);
      });
    });

    describe("status-based fallback", () => {
      it("should return 100 for PASS status when no specific field exists", () => {
        const result = {
          status: "PASS",
        };
        expect(calculateModuleScore(result)).toBe(100);
      });

      it("should return 0 for FAIL status", () => {
        const result = {
          status: "FAIL",
        };
        expect(calculateModuleScore(result)).toBe(0);
      });

      it("should return 50 for NEED_MORE_INFO status", () => {
        const result = {
          status: "NEED_MORE_INFO",
        };
        expect(calculateModuleScore(result)).toBe(50);
      });

      it("should return 50 for unknown status", () => {
        const result = {
          status: "UNKNOWN",
        };
        expect(calculateModuleScore(result)).toBe(50);
      });
    });

    describe("edge cases", () => {
      it("should return null for null input (skipped module)", () => {
        expect(calculateModuleScore(null)).toBeNull();
      });

      it("should return null for undefined input (skipped module)", () => {
        expect(calculateModuleScore(undefined)).toBeNull();
      });

      it("should return null for non-object input (skipped module)", () => {
        expect(calculateModuleScore("string")).toBeNull();
        expect(calculateModuleScore(123)).toBeNull();
      });

      it("should return 50 for empty object", () => {
        expect(calculateModuleScore({})).toBe(50);
      });
    });

    describe("skip-modules integration", () => {
      it("should return null for skipped module results to enable filtering", () => {
        // Simulate skipped module (undefined result)
        const skippedModuleResult = undefined;
        const score = calculateModuleScore(skippedModuleResult);
        expect(score).toBeNull();
      });

      it("should allow filtering skipped modules from results object", () => {
        // Simulate assessment results with skipped modules
        const results: Record<string, unknown> = {
          security: { status: "PASS", vulnerabilities: [] },
          functionality: undefined, // Skipped via --skip-modules
          errorHandling: undefined, // Skipped via --skip-modules
          documentation: { status: "PASS" },
        };

        // Apply the same filter used in assess-full.ts
        const filteredResults = Object.fromEntries(
          Object.entries(results).filter(([_, v]) => v !== undefined),
        );

        // Verify skipped modules are excluded
        expect(Object.keys(filteredResults)).toEqual([
          "security",
          "documentation",
        ]);
        expect(filteredResults).not.toHaveProperty("functionality");
        expect(filteredResults).not.toHaveProperty("errorHandling");
      });

      it("should calculate scores only for non-skipped modules", () => {
        const results: Record<string, unknown> = {
          security: { status: "PASS", vulnerabilities: [] },
          functionality: undefined,
        };

        const scores = Object.entries(results).map(([name, result]) => ({
          name,
          score: calculateModuleScore(result),
        }));

        expect(scores).toEqual([
          { name: "security", score: 100 },
          { name: "functionality", score: null },
        ]);

        // Only non-null scores should be emitted
        const emittableScores = scores.filter((s) => s.score !== null);
        expect(emittableScores).toHaveLength(1);
        expect(emittableScores[0].name).toBe("security");
      });
    });
  });
});
