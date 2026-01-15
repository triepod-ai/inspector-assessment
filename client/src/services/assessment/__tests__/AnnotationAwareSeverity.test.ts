/**
 * AnnotationAwareSeverity Tests
 *
 * Issue #170: Tests for annotation-aware security severity adjustment.
 * Verifies that read-only tools get execution-type vulnerabilities
 * downgraded and closed-world tools get exfiltration vulnerabilities downgraded.
 */

import { describe, it, expect } from "@jest/globals";
import { adjustSeverityForAnnotations } from "../modules/securityTests/AnnotationAwareSeverity";
import type { SecurityAnnotations } from "@/lib/assessment/coreTypes";

describe("AnnotationAwareSeverity", () => {
  describe("adjustSeverityForAnnotations", () => {
    describe("readOnlyHint=true tools", () => {
      const readOnlyAnnotations: SecurityAnnotations = {
        readOnlyHint: true,
        source: "mcp",
      };

      it("should downgrade Command Injection to LOW", () => {
        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
        expect(result.originalRiskLevel).toBe("HIGH");
        expect(result.adjustmentReason).toContain("readOnlyHint=true");
      });

      it("should downgrade Calculator Injection to LOW", () => {
        const result = adjustSeverityForAnnotations(
          "Calculator Injection",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should downgrade Code Execution to LOW", () => {
        const result = adjustSeverityForAnnotations(
          "Code Execution",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should downgrade Path Traversal to LOW", () => {
        const result = adjustSeverityForAnnotations(
          "Path Traversal",
          "MEDIUM",
          readOnlyAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should NOT downgrade SQL Injection (not an execution-type attack)", () => {
        const result = adjustSeverityForAnnotations(
          "SQL Injection",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it("should NOT downgrade Type Safety (validation pattern)", () => {
        const result = adjustSeverityForAnnotations(
          "Type Safety",
          "LOW",
          readOnlyAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });
    });

    describe("openWorldHint=false tools", () => {
      const closedWorldAnnotations: SecurityAnnotations = {
        openWorldHint: false,
        source: "mcp",
      };

      it("should downgrade Indirect Prompt Injection to LOW", () => {
        const result = adjustSeverityForAnnotations(
          "Indirect Prompt Injection",
          "HIGH",
          closedWorldAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
        expect(result.adjustmentReason).toContain("openWorldHint=false");
      });

      it("should downgrade Data Exfiltration to LOW", () => {
        const result = adjustSeverityForAnnotations(
          "Data Exfiltration",
          "HIGH",
          closedWorldAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should downgrade Token Theft to LOW", () => {
        const result = adjustSeverityForAnnotations(
          "Token Theft",
          "MEDIUM",
          closedWorldAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should NOT downgrade Command Injection (not exfiltration type)", () => {
        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          closedWorldAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });
    });

    describe("combined readOnlyHint=true and openWorldHint=false", () => {
      const fullAnnotations: SecurityAnnotations = {
        readOnlyHint: true,
        openWorldHint: false,
        source: "mcp",
      };

      it("should downgrade execution attacks", () => {
        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          fullAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should downgrade exfiltration attacks", () => {
        const result = adjustSeverityForAnnotations(
          "Data Exfiltration",
          "HIGH",
          fullAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });
    });

    describe("server-level flags", () => {
      it("should downgrade execution attacks when server is read-only", () => {
        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          undefined, // No per-tool annotation
          true, // serverIsReadOnly
          false,
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
        expect(result.adjustmentReason).toContain("Server is 100% read-only");
      });

      it("should downgrade exfiltration attacks when server is closed", () => {
        const result = adjustSeverityForAnnotations(
          "Token Theft",
          "HIGH",
          undefined, // No per-tool annotation
          false,
          true, // serverIsClosed
        );

        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
        expect(result.adjustmentReason).toContain(
          "Server is 100% closed-world",
        );
      });
    });

    describe("no annotations (conservative default)", () => {
      it("should NOT adjust when no annotations present", () => {
        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          undefined,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it("should NOT adjust when source is 'none'", () => {
        const noSourceAnnotations: SecurityAnnotations = {
          readOnlyHint: true,
          source: "none",
        };

        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          noSourceAnnotations,
          false,
          false,
        );

        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });
    });

    describe("edge cases", () => {
      it("should handle partial attack name matches", () => {
        const readOnlyAnnotations: SecurityAnnotations = {
          readOnlyHint: true,
          source: "mcp",
        };

        // Attack name includes "Command" (partial match)
        const result = adjustSeverityForAnnotations(
          "OS Command Injection via eval",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Should match because "Command Injection" is contained
        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should handle different annotation sources", () => {
        const inferredAnnotations: SecurityAnnotations = {
          readOnlyHint: true,
          source: "inferred",
        };

        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          inferredAnnotations,
          false,
          false,
        );

        // Should still adjust for inferred annotations
        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should preserve original risk level in result", () => {
        const readOnlyAnnotations: SecurityAnnotations = {
          readOnlyHint: true,
          source: "mcp",
        };

        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "MEDIUM",
          readOnlyAnnotations,
          false,
          false,
        );

        expect(result.originalRiskLevel).toBe("MEDIUM");
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should handle empty attack name", () => {
        const readOnlyAnnotations: SecurityAnnotations = {
          readOnlyHint: true,
          source: "mcp",
        };

        const result = adjustSeverityForAnnotations(
          "",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Empty attack name should not match any pattern
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it("should handle conflicting annotations (readOnly + execution attack)", () => {
        const conflictAnnotations: SecurityAnnotations = {
          readOnlyHint: true,
          destructiveHint: true, // Conflicting hint
          source: "mcp",
        };

        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          conflictAnnotations,
          false,
          false,
        );

        // readOnlyHint takes precedence, should still downgrade
        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it("should handle null annotations gracefully", () => {
        const result = adjustSeverityForAnnotations(
          "Command Injection",
          "HIGH",
          null as unknown as SecurityAnnotations,
          false,
          false,
        );

        // Null annotations should be treated as no annotations
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it("should prevent bypass with short attack name", () => {
        const readOnlyAnnotations: SecurityAnnotations = {
          readOnlyHint: true,
          source: "mcp",
        };

        // Short attack name like "command" should NOT match "Command Injection"
        // This is the security bypass we're preventing
        const result = adjustSeverityForAnnotations(
          "command",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Should NOT match (attack name is shorter than pattern)
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });
    });

    describe("FIX-001: Security bypass prevention (TEST-REQ-001)", () => {
      const readOnlyAnnotations: SecurityAnnotations = {
        readOnlyHint: true,
        source: "mcp",
      };

      it('should NOT match "command" to "Command Injection" pattern', () => {
        const result = adjustSeverityForAnnotations(
          "command",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Attack name "command" is shorter than pattern "Command Injection"
        // Should NOT downgrade (bypass prevented)
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it('should NOT match "calc" to "Calculator Injection" pattern', () => {
        const result = adjustSeverityForAnnotations(
          "calc",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Attack name "calc" is shorter than pattern "Calculator Injection"
        // Should NOT downgrade (bypass prevented)
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it('should NOT match "code" to "Code Execution" pattern', () => {
        const result = adjustSeverityForAnnotations(
          "code",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Attack name "code" is shorter than pattern "Code Execution"
        // Should NOT downgrade (bypass prevented)
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it('should NOT match "path" to "Path Traversal" pattern', () => {
        const result = adjustSeverityForAnnotations(
          "path",
          "MEDIUM",
          readOnlyAnnotations,
          false,
          false,
        );

        // Attack name "path" is shorter than pattern "Path Traversal"
        // Should NOT downgrade (bypass prevented)
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("MEDIUM");
      });

      it('should NOT match "exec" to any execution patterns', () => {
        const result = adjustSeverityForAnnotations(
          "exec",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Generic "exec" should not trigger any pattern
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it('should MATCH "Command Injection via eval" (contains full pattern)', () => {
        const result = adjustSeverityForAnnotations(
          "Command Injection via eval",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Full pattern "Command Injection" is contained in attack name
        // Should downgrade (valid match)
        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      it('should MATCH "Calculator Injection attack" (contains full pattern)', () => {
        const result = adjustSeverityForAnnotations(
          "Calculator Injection attack",
          "HIGH",
          readOnlyAnnotations,
          false,
          false,
        );

        // Full pattern "Calculator Injection" is contained
        expect(result.wasAdjusted).toBe(true);
        expect(result.adjustedRiskLevel).toBe("LOW");
      });

      const closedWorldAnnotations: SecurityAnnotations = {
        openWorldHint: false,
        source: "mcp",
      };

      it('should NOT match "data" to "Data Exfiltration" pattern', () => {
        const result = adjustSeverityForAnnotations(
          "data",
          "HIGH",
          closedWorldAnnotations,
          false,
          false,
        );

        // Short name should not match
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });

      it('should NOT match "token" to "Token Theft" pattern', () => {
        const result = adjustSeverityForAnnotations(
          "token",
          "MEDIUM",
          closedWorldAnnotations,
          false,
          false,
        );

        // Short name should not match
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("MEDIUM");
      });

      it('should NOT match "prompt" to "Indirect Prompt Injection" pattern', () => {
        const result = adjustSeverityForAnnotations(
          "prompt",
          "HIGH",
          closedWorldAnnotations,
          false,
          false,
        );

        // Short name should not match
        expect(result.wasAdjusted).toBe(false);
        expect(result.adjustedRiskLevel).toBe("HIGH");
      });
    });
  });
});
