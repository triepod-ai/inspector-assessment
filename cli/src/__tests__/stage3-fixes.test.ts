/**
 * Stage 3 Fixes Regression Tests
 *
 * Tests for Issue #134 code review fixes to ensure they don't regress.
 * These tests validate schema validation and JSONL event emission.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/134
 */

import {
  describe,
  it,
  expect,
  jest,
  beforeEach,
  afterEach,
} from "@jest/globals";
import {
  AssessmentOptionsSchema,
  OutputFormatSchema,
  safeParseAssessmentOptions,
} from "../lib/cli-parserSchemas.js";
import {
  emitTieredOutput,
  TieredOutputEvent,
  SCHEMA_VERSION,
} from "../lib/jsonl-events.js";
import { INSPECTOR_VERSION } from "../../../client/lib/lib/moduleScoring.js";

describe("Stage 3 Fixes Regression Tests", () => {
  describe("[TEST-REQ-001] cli-parserSchemas.ts - AssessmentOptionsSchema", () => {
    describe("outputFormat field validation", () => {
      it("should accept outputFormat with 'full' value", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "full",
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.outputFormat).toBe("full");
        }
      });

      it("should accept outputFormat with 'tiered' value", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "tiered",
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.outputFormat).toBe("tiered");
        }
      });

      it("should accept outputFormat with 'summary-only' value", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "summary-only",
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.outputFormat).toBe("summary-only");
        }
      });

      it("should accept undefined outputFormat (optional field)", () => {
        const options = {
          serverName: "test-server",
          // outputFormat omitted
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.outputFormat).toBeUndefined();
        }
      });

      it("should reject invalid outputFormat value", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "invalid",
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(false);
        if (!result.success) {
          // Zod error messages include the full path and expected values
          const errors = result.error.errors;
          const hasOutputFormatError = errors.some(
            (e) =>
              e.path.includes("outputFormat") ||
              e.message.includes("full") ||
              e.message.includes("tiered") ||
              e.message.includes("summary-only"),
          );
          expect(hasOutputFormatError).toBe(true);
        }
      });

      it("should reject non-string outputFormat values", () => {
        const testCases = [
          { outputFormat: 123 },
          { outputFormat: true },
          { outputFormat: null },
          { outputFormat: {} },
          { outputFormat: [] },
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

    describe("autoTier field validation", () => {
      it("should accept autoTier with true value", () => {
        const options = {
          serverName: "test-server",
          autoTier: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.autoTier).toBe(true);
        }
      });

      it("should accept autoTier with false value", () => {
        const options = {
          serverName: "test-server",
          autoTier: false,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.autoTier).toBe(false);
        }
      });

      it("should accept undefined autoTier (optional field)", () => {
        const options = {
          serverName: "test-server",
          // autoTier omitted
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.autoTier).toBeUndefined();
        }
      });

      it("should reject non-boolean autoTier values", () => {
        const testCases = [
          { autoTier: "true" }, // string instead of boolean
          { autoTier: 1 }, // number instead of boolean
          { autoTier: null },
          { autoTier: {} },
          { autoTier: [] },
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

    describe("combined outputFormat and autoTier validation", () => {
      it("should accept both outputFormat and autoTier together", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "tiered",
          autoTier: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.outputFormat).toBe("tiered");
          expect(result.data.autoTier).toBe(true);
        }
      });

      it("should accept outputFormat without autoTier", () => {
        const options = {
          serverName: "test-server",
          outputFormat: "summary-only",
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.outputFormat).toBe("summary-only");
          expect(result.data.autoTier).toBeUndefined();
        }
      });

      it("should accept autoTier without outputFormat", () => {
        const options = {
          serverName: "test-server",
          autoTier: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.autoTier).toBe(true);
          expect(result.data.outputFormat).toBeUndefined();
        }
      });
    });

    describe("regression prevention", () => {
      it("should fail if outputFormat schema loses required enum values", () => {
        // Verify all three enum values are present
        const validValues = OutputFormatSchema.options;

        expect(validValues).toContain("full");
        expect(validValues).toContain("tiered");
        expect(validValues).toContain("summary-only");
        expect(validValues.length).toBe(3);
      });

      it("should maintain backward compatibility with existing fields", () => {
        // Test that adding new fields didn't break existing validation
        const options = {
          serverName: "test-server",
          verbose: true,
          jsonOnly: true,
          format: "json",
          // Include new fields
          outputFormat: "tiered",
          autoTier: true,
        };

        const result = safeParseAssessmentOptions(options);

        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data.verbose).toBe(true);
          expect(result.data.jsonOnly).toBe(true);
          expect(result.data.format).toBe("json");
          expect(result.data.outputFormat).toBe("tiered");
          expect(result.data.autoTier).toBe(true);
        }
      });
    });
  });

  describe("[TEST-REQ-002] jsonl-events.ts - TieredOutputEvent and emitTieredOutput", () => {
    // Capture console.error output for testing
    let consoleSpy: any;
    let errorOutput: string[] = [];

    beforeEach(() => {
      errorOutput = [];
      // Spy on console.error to capture JSONL output
      consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation((msg: any) => {
          errorOutput.push(msg);
        });
    });

    afterEach(() => {
      // Restore original console.error
      if (consoleSpy) {
        consoleSpy.mockRestore();
      }
    });

    describe("emitTieredOutput function", () => {
      it("should emit valid JSONL with correct event type", () => {
        const tiers: TieredOutputEvent["tiers"] = {
          executiveSummary: {
            path: "/tmp/output/executive-summary.json",
            estimatedTokens: 500,
          },
          toolSummaries: {
            path: "/tmp/output/tool-summaries.json",
            estimatedTokens: 1500,
            toolCount: 10,
          },
        };

        emitTieredOutput("/tmp/output", "summary-only", tiers);

        expect(errorOutput.length).toBe(1);
        const parsed = JSON.parse(errorOutput[0]);

        expect(parsed.event).toBe("tiered_output_generated");
        expect(parsed.outputDir).toBe("/tmp/output");
        expect(parsed.outputFormat).toBe("summary-only");
        expect(parsed.tiers).toEqual(tiers);
      });

      it("should include version and schemaVersion fields", () => {
        const tiers: TieredOutputEvent["tiers"] = {
          executiveSummary: {
            path: "/tmp/output/executive-summary.json",
            estimatedTokens: 500,
          },
          toolSummaries: {
            path: "/tmp/output/tool-summaries.json",
            estimatedTokens: 1500,
            toolCount: 10,
          },
        };

        emitTieredOutput("/tmp/output", "tiered", tiers);

        expect(errorOutput.length).toBe(1);
        const parsed = JSON.parse(errorOutput[0]);

        expect(parsed.version).toBe(INSPECTOR_VERSION);
        expect(parsed.schemaVersion).toBe(SCHEMA_VERSION);
      });

      it("should include all required tier properties", () => {
        const tiers: TieredOutputEvent["tiers"] = {
          executiveSummary: {
            path: "/tmp/output/executive-summary.json",
            estimatedTokens: 500,
          },
          toolSummaries: {
            path: "/tmp/output/tool-summaries.json",
            estimatedTokens: 1500,
            toolCount: 10,
          },
          toolDetails: {
            directory: "/tmp/output/tools",
            fileCount: 10,
            totalEstimatedTokens: 5000,
          },
        };

        emitTieredOutput("/tmp/output", "tiered", tiers);

        expect(errorOutput.length).toBe(1);
        const parsed = JSON.parse(errorOutput[0]);

        expect(parsed.tiers.executiveSummary).toEqual({
          path: "/tmp/output/executive-summary.json",
          estimatedTokens: 500,
        });
        expect(parsed.tiers.toolSummaries).toEqual({
          path: "/tmp/output/tool-summaries.json",
          estimatedTokens: 1500,
          toolCount: 10,
        });
        expect(parsed.tiers.toolDetails).toEqual({
          directory: "/tmp/output/tools",
          fileCount: 10,
          totalEstimatedTokens: 5000,
        });
      });

      it("should handle missing optional toolDetails tier", () => {
        const tiers: TieredOutputEvent["tiers"] = {
          executiveSummary: {
            path: "/tmp/output/executive-summary.json",
            estimatedTokens: 500,
          },
          toolSummaries: {
            path: "/tmp/output/tool-summaries.json",
            estimatedTokens: 1500,
            toolCount: 10,
          },
          // toolDetails omitted (optional)
        };

        emitTieredOutput("/tmp/output", "summary-only", tiers);

        expect(errorOutput.length).toBe(1);
        const parsed = JSON.parse(errorOutput[0]);

        expect(parsed.tiers.executiveSummary).toBeDefined();
        expect(parsed.tiers.toolSummaries).toBeDefined();
        expect(parsed.tiers.toolDetails).toBeUndefined();
      });

      it("should emit valid JSON that can be parsed", () => {
        const tiers: TieredOutputEvent["tiers"] = {
          executiveSummary: {
            path: "/tmp/output/executive-summary.json",
            estimatedTokens: 500,
          },
          toolSummaries: {
            path: "/tmp/output/tool-summaries.json",
            estimatedTokens: 1500,
            toolCount: 10,
          },
        };

        emitTieredOutput("/tmp/output", "tiered", tiers);

        expect(errorOutput.length).toBe(1);

        // Should not throw when parsing
        expect(() => JSON.parse(errorOutput[0])).not.toThrow();
      });
    });

    describe("TieredOutputEvent type structure", () => {
      it("should enforce correct event type", () => {
        const event: TieredOutputEvent = {
          event: "tiered_output_generated",
          outputDir: "/tmp/output",
          outputFormat: "tiered",
          tiers: {
            executiveSummary: {
              path: "/tmp/output/executive-summary.json",
              estimatedTokens: 500,
            },
            toolSummaries: {
              path: "/tmp/output/tool-summaries.json",
              estimatedTokens: 1500,
              toolCount: 10,
            },
          },
        };

        expect(event.event).toBe("tiered_output_generated");
      });

      it("should support both 'tiered' and 'summary-only' output formats", () => {
        const tieredEvent: TieredOutputEvent = {
          event: "tiered_output_generated",
          outputDir: "/tmp/output",
          outputFormat: "tiered",
          tiers: {
            executiveSummary: { path: "/tmp/exec.json", estimatedTokens: 500 },
            toolSummaries: {
              path: "/tmp/tools.json",
              estimatedTokens: 1500,
              toolCount: 10,
            },
          },
        };

        const summaryOnlyEvent: TieredOutputEvent = {
          event: "tiered_output_generated",
          outputDir: "/tmp/output",
          outputFormat: "summary-only",
          tiers: {
            executiveSummary: { path: "/tmp/exec.json", estimatedTokens: 500 },
            toolSummaries: {
              path: "/tmp/tools.json",
              estimatedTokens: 1500,
              toolCount: 10,
            },
          },
        };

        expect(tieredEvent.outputFormat).toBe("tiered");
        expect(summaryOnlyEvent.outputFormat).toBe("summary-only");
      });

      it("should have correct structure for all tier properties", () => {
        const event: TieredOutputEvent = {
          event: "tiered_output_generated",
          outputDir: "/tmp/output",
          outputFormat: "tiered",
          tiers: {
            executiveSummary: {
              path: "/tmp/output/executive-summary.json",
              estimatedTokens: 500,
            },
            toolSummaries: {
              path: "/tmp/output/tool-summaries.json",
              estimatedTokens: 1500,
              toolCount: 10,
            },
            toolDetails: {
              directory: "/tmp/output/tools",
              fileCount: 10,
              totalEstimatedTokens: 5000,
            },
          },
        };

        // Verify executive summary structure
        expect(event.tiers.executiveSummary).toHaveProperty("path");
        expect(event.tiers.executiveSummary).toHaveProperty("estimatedTokens");
        expect(typeof event.tiers.executiveSummary.path).toBe("string");
        expect(typeof event.tiers.executiveSummary.estimatedTokens).toBe(
          "number",
        );

        // Verify tool summaries structure
        expect(event.tiers.toolSummaries).toHaveProperty("path");
        expect(event.tiers.toolSummaries).toHaveProperty("estimatedTokens");
        expect(event.tiers.toolSummaries).toHaveProperty("toolCount");
        expect(typeof event.tiers.toolSummaries.path).toBe("string");
        expect(typeof event.tiers.toolSummaries.estimatedTokens).toBe("number");
        expect(typeof event.tiers.toolSummaries.toolCount).toBe("number");

        // Verify tool details structure (optional)
        expect(event.tiers.toolDetails).toHaveProperty("directory");
        expect(event.tiers.toolDetails).toHaveProperty("fileCount");
        expect(event.tiers.toolDetails).toHaveProperty("totalEstimatedTokens");
        expect(typeof event.tiers.toolDetails?.directory).toBe("string");
        expect(typeof event.tiers.toolDetails?.fileCount).toBe("number");
        expect(typeof event.tiers.toolDetails?.totalEstimatedTokens).toBe(
          "number",
        );
      });
    });

    describe("JSONL format compliance", () => {
      it("should emit single-line JSON (no newlines within object)", () => {
        const tiers: TieredOutputEvent["tiers"] = {
          executiveSummary: {
            path: "/tmp/output/executive-summary.json",
            estimatedTokens: 500,
          },
          toolSummaries: {
            path: "/tmp/output/tool-summaries.json",
            estimatedTokens: 1500,
            toolCount: 10,
          },
        };

        emitTieredOutput("/tmp/output", "tiered", tiers);

        expect(errorOutput.length).toBe(1);
        const output = errorOutput[0];

        // Should be single line (may have trailing newline from console.error)
        const lines = output.trim().split("\n");
        expect(lines.length).toBe(1);
      });

      it("should emit parseable JSON Lines format", () => {
        const tiers1: TieredOutputEvent["tiers"] = {
          executiveSummary: { path: "/tmp/1/exec.json", estimatedTokens: 500 },
          toolSummaries: {
            path: "/tmp/1/tools.json",
            estimatedTokens: 1500,
            toolCount: 10,
          },
        };

        const tiers2: TieredOutputEvent["tiers"] = {
          executiveSummary: { path: "/tmp/2/exec.json", estimatedTokens: 600 },
          toolSummaries: {
            path: "/tmp/2/tools.json",
            estimatedTokens: 1600,
            toolCount: 12,
          },
        };

        emitTieredOutput("/tmp/output1", "tiered", tiers1);
        emitTieredOutput("/tmp/output2", "summary-only", tiers2);

        expect(errorOutput.length).toBe(2);

        // Each line should be valid JSON
        const parsed1 = JSON.parse(errorOutput[0]);
        const parsed2 = JSON.parse(errorOutput[1]);

        expect(parsed1.outputDir).toBe("/tmp/output1");
        expect(parsed2.outputDir).toBe("/tmp/output2");
      });
    });
  });

  describe("Code duplication documentation", () => {
    it("should have matching TieredOutputEvent interface across files", () => {
      // This test documents the intentional duplication between
      // cli/src/lib/jsonl-events.ts and scripts/lib/jsonl-events.ts
      // as documented in FIX-002 and FIX-003

      // The interface structure is tested above. This test serves as
      // documentation that the duplication is intentional and tracked.

      const expectedEventType = "tiered_output_generated";
      const expectedOutputFormats = ["tiered", "summary-only"];

      expect(expectedEventType).toBe("tiered_output_generated");
      expect(expectedOutputFormats).toEqual(["tiered", "summary-only"]);
    });

    it("should maintain consistency reminder for developers", () => {
      // This test serves as a reminder that TieredOutputEvent and
      // emitTieredOutput are duplicated across two files and must
      // be kept in sync when changes are made.

      const files = [
        "cli/src/lib/jsonl-events.ts",
        "scripts/lib/jsonl-events.ts",
      ];

      // Documentation reminder
      expect(files.length).toBe(2);
      expect(files[0]).toContain("cli/src/lib/jsonl-events.ts");
      expect(files[1]).toContain("scripts/lib/jsonl-events.ts");
    });
  });
});
