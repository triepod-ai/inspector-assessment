/**
 * Stage 3 Fix Validation Tests
 *
 * Tests for Issue #137 Stage 3 fixes (code review and corrections).
 * Validates that FIX-001 (stageBVerbose schema) is correctly implemented.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/137
 */

import { jest, describe, it, expect, afterEach } from "@jest/globals";
import {
  AssessmentOptionsSchema,
  safeParseAssessmentOptions,
  validateAssessmentOptions,
} from "../lib/cli-parserSchemas.js";

describe("Stage 3 Fix Validation Tests", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("[TEST-001] cli-parserSchemas.ts - stageBVerbose field (FIX-001)", () => {
    describe("stageBVerbose field validation", () => {
      it("should accept stageBVerbose with true value (happy path)", () => {
        const options = {
          serverName: "test-server",
          stageBVerbose: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.stageBVerbose).toBe(true);
        }
      });

      it("should accept stageBVerbose with false value (edge case)", () => {
        const options = {
          serverName: "test-server",
          stageBVerbose: false,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.stageBVerbose).toBe(false);
        }
      });

      it("should accept undefined stageBVerbose - optional field (edge case)", () => {
        const options = {
          serverName: "test-server",
          // stageBVerbose omitted
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.stageBVerbose).toBeUndefined();
        }
      });

      it("should validate with validateAssessmentOptions() accepting stageBVerbose (error case prevention)", () => {
        const options = {
          serverName: "test-server",
          stageBVerbose: true,
        };

        const errors = validateAssessmentOptions(options);

        expect(errors).toHaveLength(0);
      });

      it("should reject non-boolean stageBVerbose values (error case)", () => {
        const testCases = [
          { stageBVerbose: "true" }, // string instead of boolean
          { stageBVerbose: 1 }, // number instead of boolean
          { stageBVerbose: null },
          { stageBVerbose: {} },
          { stageBVerbose: [] },
        ];

        testCases.forEach((testCase) => {
          const options = {
            serverName: "test-server",
            ...testCase,
          };

          const result = safeParseAssessmentOptions(options);

          expect(result.success).toBe(false);
        });
      });
    });

    describe("stageBVerbose integration with other fields", () => {
      it("should accept stageBVerbose with outputFormat=tiered", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "tiered" as const,
          stageBVerbose: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.outputFormat).toBe("tiered");
          expect(result.data.stageBVerbose).toBe(true);
        }
      });

      it("should accept stageBVerbose with other CLI options", () => {
        const options = {
          serverName: "test-server",
          verbose: true,
          jsonOnly: false,
          fullAssessment: true,
          stageBVerbose: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.verbose).toBe(true);
          expect(result.data.jsonOnly).toBe(false);
          expect(result.data.fullAssessment).toBe(true);
          expect(result.data.stageBVerbose).toBe(true);
        }
      });

      it("should work with validateAssessmentOptions for complex options", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "tiered" as const,
          autoTier: true,
          stageBVerbose: true,
          verbose: true,
        };

        const errors = validateAssessmentOptions(options);

        expect(errors).toHaveLength(0);
      });
    });

    describe("regression prevention for ISSUE-001", () => {
      it("should maintain stageBVerbose in schema after validation", () => {
        // Verify the field exists in the schema shape
        const options = {
          serverName: "test-server",
          stageBVerbose: true,
        };

        const result = AssessmentOptionsSchema.safeParse(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data).toHaveProperty("stageBVerbose");
          expect(result.data.stageBVerbose).toBe(true);
        }
      });

      it("should not strip stageBVerbose field during validation", () => {
        const options = {
          serverName: "test-server",
          stageBVerbose: true,
          outputFormat: "tiered" as const,
        };

        const parsed = AssessmentOptionsSchema.parse(options);

        // Field should be present after parsing
        expect(parsed.stageBVerbose).toBe(true);
        expect(parsed.outputFormat).toBe("tiered");
      });

      it("should backward compatibility - existing fields unaffected", () => {
        const options = {
          serverName: "test-server",
          verbose: true,
          jsonOnly: false,
          format: "json" as const,
          fullAssessment: true,
          // New field
          stageBVerbose: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.verbose).toBe(true);
          expect(result.data.jsonOnly).toBe(false);
          expect(result.data.format).toBe("json");
          expect(result.data.fullAssessment).toBe(true);
          expect(result.data.stageBVerbose).toBe(true);
        }
      });
    });
  });
});
