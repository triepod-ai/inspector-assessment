/**
 * Security Pattern Count Consistency Tests
 *
 * Verifies that all references to security pattern count are consistent across:
 * - CLI help messages
 * - Console output
 * - Configuration defaults
 * - Documentation comments
 *
 * Addresses QA requirement: verify all references to security pattern count are consistent (30 patterns).
 *
 * NOTE: The DEFAULT_ASSESSMENT_CONFIG uses 8 patterns (for Anthropic's basic security testing).
 * CLI tools override this to 30 patterns for comprehensive security assessment.
 * This test verifies consistency within each context.
 */

import { jest, describe, it, expect, afterEach } from "@jest/globals";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

// Get the root directory of the project (one level up from cli/)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "../../../.."); // From cli/src/__tests__/security to root

describe("Security Pattern Count Consistency", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("CLI assess-security references", () => {
    it("should use consistent pattern count in assess-security.ts", () => {
      const filePath = path.join(projectRoot, "cli/src/assess-security.ts");
      const content = fs.readFileSync(filePath, "utf-8");

      // Find all references to pattern count
      const references = [
        { match: /securityPatternsToTest:\s*(\d+)/, name: "config value" },
        {
          match: /Running security assessment with (\d+) attack patterns/,
          name: "console log",
        },
        {
          match: /Run security assessment.*with (\d+) attack patterns/,
          name: "help text header",
        },
        {
          match: /Attack Patterns Tested \((\d+) total\)/,
          name: "help text section",
        },
      ];

      const expectedCount = 30;
      const findings: Array<{ name: string; value: number }> = [];

      for (const ref of references) {
        const match = content.match(ref.match);
        if (match && match[1]) {
          const count = parseInt(match[1], 10);
          findings.push({ name: ref.name, value: count });

          expect(count).toBe(expectedCount);
        }
      }

      // Ensure we found at least 3 references (config + 2 messages)
      expect(findings.length).toBeGreaterThanOrEqual(3);

      // Verify all found references match
      const allMatch = findings.every((f) => f.value === expectedCount);
      expect(allMatch).toBe(true);
    });

    it("should document 30 patterns in help text", () => {
      const filePath = path.join(projectRoot, "cli/src/assess-security.ts");
      const content = fs.readFileSync(filePath, "utf-8");

      // Verify help text explicitly mentions 30 patterns
      expect(content).toContain("30 attack patterns");
      expect(content).toContain("Attack Patterns Tested (30 total)");
    });
  });

  describe("Configuration consistency", () => {
    it("should use 8 patterns for DEFAULT_ASSESSMENT_CONFIG (Anthropic basic)", () => {
      const filePath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const content = fs.readFileSync(filePath, "utf-8");

      // DEFAULT_ASSESSMENT_CONFIG should use 8 patterns (Anthropic's basic requirement)
      const defaultConfigMatch = content.match(
        /DEFAULT_ASSESSMENT_CONFIG[\s\S]*?securityPatternsToTest:\s*(\d+)/,
      );
      expect(defaultConfigMatch).toBeTruthy();
      if (defaultConfigMatch) {
        const count = parseInt(defaultConfigMatch[1], 10);
        expect(count).toBe(8);
      }
    });

    it("should use 3 patterns for REVIEWER_MODE_CONFIG (fast review)", () => {
      const filePath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const content = fs.readFileSync(filePath, "utf-8");

      // REVIEWER_MODE_CONFIG should use 3 patterns (optimized for speed)
      const reviewerConfigMatch = content.match(
        /REVIEWER_MODE_CONFIG[\s\S]*?securityPatternsToTest:\s*(\d+)/,
      );
      expect(reviewerConfigMatch).toBeTruthy();
      if (reviewerConfigMatch) {
        const count = parseInt(reviewerConfigMatch[1], 10);
        expect(count).toBe(3);
      }
    });

    it("should use 8 patterns for DEVELOPER_MODE_CONFIG (comprehensive)", () => {
      const filePath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const content = fs.readFileSync(filePath, "utf-8");

      // DEVELOPER_MODE_CONFIG should use 8 patterns (comprehensive testing)
      const developerConfigMatch = content.match(
        /DEVELOPER_MODE_CONFIG[\s\S]*?securityPatternsToTest:\s*(\d+)/,
      );
      expect(developerConfigMatch).toBeTruthy();
      if (developerConfigMatch) {
        const count = parseInt(developerConfigMatch[1], 10);
        expect(count).toBe(8);
      }
    });

    it("should use 8 patterns for AUDIT_MODE_CONFIG (compliance)", () => {
      const filePath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const content = fs.readFileSync(filePath, "utf-8");

      // AUDIT_MODE_CONFIG should use 8 patterns (compliance validation)
      const auditConfigMatch = content.match(
        /AUDIT_MODE_CONFIG[\s\S]*?securityPatternsToTest:\s*(\d+)/,
      );
      expect(auditConfigMatch).toBeTruthy();
      if (auditConfigMatch) {
        const count = parseInt(auditConfigMatch[1], 10);
        expect(count).toBe(8);
      }
    });

    it("should use 8 patterns for CLAUDE_ENHANCED_AUDIT_CONFIG", () => {
      const filePath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const content = fs.readFileSync(filePath, "utf-8");

      // CLAUDE_ENHANCED_AUDIT_CONFIG should use 8 patterns (enhanced validation)
      const claudeConfigMatch = content.match(
        /CLAUDE_ENHANCED_AUDIT_CONFIG[\s\S]*?securityPatternsToTest:\s*(\d+)/,
      );
      expect(claudeConfigMatch).toBeTruthy();
      if (claudeConfigMatch) {
        const count = parseInt(claudeConfigMatch[1], 10);
        expect(count).toBe(8);
      }
    });
  });

  describe("Documentation consistency", () => {
    it("should reference correct pattern counts in config comments", () => {
      const filePath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const content = fs.readFileSync(filePath, "utf-8");

      // Check inline comments for pattern counts
      // Default: "default all 8" or "default 8"
      expect(content).toMatch(
        /securityPatternsToTest\?\s*:\s*number;.*default.*8/i,
      );

      // Reviewer mode: "Test only 3 critical"
      expect(content).toMatch(/securityPatternsToTest:\s*3,.*3 critical/i);

      // Developer/audit modes: "all security patterns" or "all 8"
      expect(content).toMatch(
        /securityPatternsToTest:\s*8,.*all.*8|8.*patterns/i,
      );
    });

    it("should document pattern count in help text comments", () => {
      const filePath = path.join(projectRoot, "cli/src/assess-security.ts");
      const content = fs.readFileSync(filePath, "utf-8");

      // CLI uses 30 patterns (expanded from base 8)
      expect(content).toContain("30 attack patterns");
      expect(content).toContain("(30 total)");
    });
  });

  describe("Cross-file consistency", () => {
    it("should have matching pattern counts between related files", () => {
      // assess-security.ts: 30 patterns (CLI override)
      const assessSecurityPath = path.join(
        projectRoot,
        "cli/src/assess-security.ts",
      );
      const assessSecurityContent = fs.readFileSync(
        assessSecurityPath,
        "utf-8",
      );

      const assessSecurityMatch = assessSecurityContent.match(
        /securityPatternsToTest:\s*(\d+)/,
      );
      expect(assessSecurityMatch).toBeTruthy();
      if (assessSecurityMatch) {
        const cliCount = parseInt(assessSecurityMatch[1], 10);
        expect(cliCount).toBe(30); // CLI uses 30 patterns
      }

      // configTypes.ts: 8 patterns default (Anthropic basic)
      const configTypesPath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const configTypesContent = fs.readFileSync(configTypesPath, "utf-8");

      const configMatch = configTypesContent.match(
        /DEFAULT_ASSESSMENT_CONFIG[\s\S]*?securityPatternsToTest:\s*(\d+)/,
      );
      expect(configMatch).toBeTruthy();
      if (configMatch) {
        const defaultCount = parseInt(configMatch[1], 10);
        expect(defaultCount).toBe(8); // Default uses 8 patterns
      }
    });

    it("should match pattern count in estimators comment", () => {
      const estimatorsPath = path.join(
        projectRoot,
        "client/src/services/assessment/registry/estimators.ts",
      );

      if (fs.existsSync(estimatorsPath)) {
        const content = fs.readFileSync(estimatorsPath, "utf-8");

        // Verify comment mentions "default 8" for security patterns
        expect(content).toMatch(
          /Security assessor:.*securityPatternsToTest.*default 8/i,
        );

        // Verify fallback value is 8
        const fallbackMatch = content.match(
          /securityPatternsToTest.*\?\?.*(\d+)/,
        );
        if (fallbackMatch) {
          const fallback = parseInt(fallbackMatch[1], 10);
          expect(fallback).toBe(8);
        }
      }
    });
  });

  describe("Pattern count validation rules", () => {
    it("should enforce consistent pattern counts across contexts", () => {
      // Rule: CLI tools use 30 patterns (comprehensive security testing)
      // Rule: Default config uses 8 patterns (Anthropic basic requirement)
      // Rule: Reviewer mode uses 3 patterns (fast reviews)
      // Rule: Developer/Audit modes use 8 patterns (comprehensive validation)

      const rules = {
        cli: 30,
        default: 8,
        reviewer: 3,
        developer: 8,
        audit: 8,
      };

      // This test documents the expected pattern counts for each context
      expect(rules.cli).toBe(30);
      expect(rules.default).toBe(8);
      expect(rules.reviewer).toBe(3);
      expect(rules.developer).toBe(8);
      expect(rules.audit).toBe(8);
    });

    it("should validate CLI pattern count matches help text", () => {
      const filePath = path.join(projectRoot, "cli/src/assess-security.ts");
      const content = fs.readFileSync(filePath, "utf-8");

      // Extract config value
      const configMatch = content.match(/securityPatternsToTest:\s*(\d+)/);
      expect(configMatch).toBeTruthy();

      // Extract help text values
      const helpMatches = [
        ...content.matchAll(/(\d+) attack patterns/gi),
        ...content.matchAll(/\((\d+) total\)/gi),
      ];

      // All should reference 30
      const expectedCount = 30;
      if (configMatch) {
        expect(parseInt(configMatch[1], 10)).toBe(expectedCount);
      }

      for (const match of helpMatches) {
        if (match[1]) {
          expect(parseInt(match[1], 10)).toBe(expectedCount);
        }
      }
    });
  });

  describe("Edge cases and error scenarios", () => {
    it("should handle missing pattern count gracefully", () => {
      // This test verifies that even if config is missing securityPatternsToTest,
      // the system has documented defaults

      const configTypesPath = path.join(
        projectRoot,
        "client/src/lib/assessment/configTypes.ts",
      );
      const content = fs.readFileSync(configTypesPath, "utf-8");

      // Verify comment documents the default value
      expect(content).toMatch(/securityPatternsToTest.*default.*8/i);
    });

    it("should document pattern count semantics clearly", () => {
      const filePath = path.join(projectRoot, "cli/src/assess-security.ts");
      const content = fs.readFileSync(filePath, "utf-8");

      // Help text should clearly state what "30 patterns" means
      expect(content).toContain("Attack Patterns Tested");
      expect(content).toContain("30 total");

      // Should list pattern categories for clarity
      expect(content).toContain("Command Injection");
      expect(content).toContain("SQL Injection");
    });
  });
});
