/**
 * Tests for DescriptionAnalyzer
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 */

import {
  analyzeDescription,
  hasReadOnlyIndicators,
  hasDestructiveIndicators,
  hasWriteIndicators,
  DESCRIPTION_BEHAVIOR_KEYWORDS,
} from "../modules/annotations/DescriptionAnalyzer";

describe("DescriptionAnalyzer", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("analyzeDescription", () => {
    describe("read-only detection", () => {
      it("should detect 'retrieves' as high-confidence read-only", () => {
        const result = analyzeDescription(
          "Retrieves user data from the database",
        );

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("retrieves")]),
        );
      });

      it("should detect 'returns' as high-confidence read-only", () => {
        const result = analyzeDescription(
          "Returns the current configuration settings",
        );

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
      });

      it("should detect 'lists' as high-confidence read-only", () => {
        const result = analyzeDescription("Lists all available projects");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should detect 'gets' as medium-confidence read-only", () => {
        const result = analyzeDescription("Gets the file contents");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(70);
        expect(result.confidence).toBeLessThan(90);
      });

      it("should detect multiple read-only keywords and accumulate confidence", () => {
        const result = analyzeDescription(
          "Retrieves and displays the list of users",
        );

        expect(result.expectedReadOnly).toBe(true);
        // Should have higher confidence from multiple keywords
        expect(result.confidence).toBeGreaterThan(90);
      });
    });

    describe("destructive detection", () => {
      it("should detect 'deletes' as high-confidence destructive", () => {
        const result = analyzeDescription("Deletes the specified file");

        expect(result.expectedDestructive).toBe(true);
        expect(result.expectedReadOnly).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
      });

      it("should detect 'removes' as high-confidence destructive", () => {
        const result = analyzeDescription("Removes all cached data");

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
      });

      it("should detect 'permanently' as high-confidence destructive", () => {
        const result = analyzeDescription(
          "Permanently erases all user data from the system",
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
      });

      it("should detect 'truncates' as medium-confidence destructive", () => {
        const result = analyzeDescription("Truncates the log table");

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(70);
      });

      it("should prioritize destructive over read-only when both present", () => {
        const result = analyzeDescription(
          "Retrieves and then deletes all expired sessions",
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.expectedReadOnly).toBe(false);
      });
    });

    describe("write detection", () => {
      it("should detect 'creates' as write operation", () => {
        const result = analyzeDescription(
          "Creates a new project with the given name",
        );

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("creates")]),
        );
      });

      it("should detect 'updates' as write operation", () => {
        const result = analyzeDescription("Updates the user profile");

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(70);
      });

      it("should detect 'inserts' as write operation", () => {
        const result = analyzeDescription(
          "Inserts a new record into the table",
        );

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should override read-only when write keywords have higher score", () => {
        const result = analyzeDescription(
          "Creates a new report and gets the file path",
        );

        // 'creates' (high confidence write) should override 'gets' (medium confidence read)
        expect(result.expectedReadOnly).toBe(false);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("override")]),
        );
      });
    });

    describe("negation handling", () => {
      it("should ignore negated destructive keywords", () => {
        const result = analyzeDescription(
          "This operation does not delete any files",
        );

        expect(result.expectedDestructive).toBe(false);
        // Negated keywords are filtered out, so no behavioral keywords are detected
        expect(result.evidence).toEqual(
          expect.arrayContaining([
            expect.stringContaining("No behavioral keywords"),
          ]),
        );
      });

      it("should ignore 'doesn't delete' pattern", () => {
        const result = analyzeDescription(
          "This doesn't delete the original data",
        );

        expect(result.expectedDestructive).toBe(false);
      });

      it("should ignore 'cannot remove' pattern", () => {
        const result = analyzeDescription(
          "You cannot remove system-protected files",
        );

        expect(result.expectedDestructive).toBe(false);
      });

      it("should handle 'never' negation", () => {
        const result = analyzeDescription(
          "This tool never deletes your original data",
        );

        expect(result.expectedDestructive).toBe(false);
      });
    });

    describe("edge cases", () => {
      it("should return zero confidence for empty description", () => {
        const result = analyzeDescription("");

        expect(result.confidence).toBe(0);
        expect(result.evidence).toContain("No description provided");
      });

      it("should return zero confidence for whitespace-only description", () => {
        const result = analyzeDescription("   \n\t  ");

        expect(result.confidence).toBe(0);
      });

      it("should handle description with no behavioral keywords", () => {
        const result = analyzeDescription(
          "A tool for interacting with the API",
        );

        expect(result.confidence).toBe(0);
        expect(result.evidence).toContain(
          "No behavioral keywords detected in description",
        );
      });

      it("should handle case-insensitive matching", () => {
        const result = analyzeDescription("RETRIEVES ALL DATA FROM THE SERVER");

        expect(result.expectedReadOnly).toBe(true);
      });

      it("should match multi-word keywords", () => {
        const result = analyzeDescription("This looks up user information");

        expect(result.expectedReadOnly).toBe(true);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("looks up")]),
        );
      });
    });

    describe("atlas-mcp-server examples (Issue #57)", () => {
      it("should detect atlas_project_create as write operation", () => {
        const result = analyzeDescription(
          "Creates a new project in the Atlas system",
        );

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
      });

      it("should detect atlas_project_list as read-only", () => {
        const result = analyzeDescription(
          "Lists all projects in the Atlas system",
        );

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
      });

      it("should detect atlas_database_clean as destructive", () => {
        const result = analyzeDescription(
          "Removes all data from the database permanently",
        );

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
      });
    });
  });

  describe("hasReadOnlyIndicators", () => {
    it("should return true for description with 'retrieves'", () => {
      expect(hasReadOnlyIndicators("Retrieves data from API")).toBe(true);
    });

    it("should return true for description with 'lists'", () => {
      expect(hasReadOnlyIndicators("Lists all items")).toBe(true);
    });

    it("should return false for description without read-only keywords", () => {
      expect(hasReadOnlyIndicators("A generic tool")).toBe(false);
    });

    it("should return false for empty description", () => {
      expect(hasReadOnlyIndicators("")).toBe(false);
    });

    it("should return false for null/undefined", () => {
      expect(hasReadOnlyIndicators(null as unknown as string)).toBe(false);
      expect(hasReadOnlyIndicators(undefined as unknown as string)).toBe(false);
    });
  });

  describe("hasDestructiveIndicators", () => {
    it("should return true for description with 'deletes'", () => {
      expect(hasDestructiveIndicators("Deletes the file")).toBe(true);
    });

    it("should return true for description with 'removes'", () => {
      expect(hasDestructiveIndicators("Removes cached data")).toBe(true);
    });

    it("should return false for description without destructive keywords", () => {
      expect(hasDestructiveIndicators("Creates new entries")).toBe(false);
    });
  });

  describe("hasWriteIndicators", () => {
    it("should return true for description with 'creates'", () => {
      expect(hasWriteIndicators("Creates a new project")).toBe(true);
    });

    it("should return true for description with 'updates'", () => {
      expect(hasWriteIndicators("Updates the configuration")).toBe(true);
    });

    it("should return false for description without write keywords", () => {
      expect(hasWriteIndicators("Lists all projects")).toBe(false);
    });
  });

  describe("DESCRIPTION_BEHAVIOR_KEYWORDS", () => {
    it("should have high/medium/low categories for readOnly", () => {
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.high).toBeInstanceOf(Array);
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.medium).toBeInstanceOf(
        Array,
      );
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.low).toBeInstanceOf(Array);
    });

    it("should have high/medium/low categories for destructive", () => {
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.high).toBeInstanceOf(
        Array,
      );
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.medium).toBeInstanceOf(
        Array,
      );
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.low).toBeInstanceOf(
        Array,
      );
    });

    it("should have high/medium/low categories for write", () => {
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.write.high).toBeInstanceOf(Array);
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.write.medium).toBeInstanceOf(Array);
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.write.low).toBeInstanceOf(Array);
    });

    it("should have expected high-confidence read-only keywords", () => {
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.high).toContain(
        "retrieves",
      );
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.high).toContain("lists");
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.high).toContain("searches");
    });

    it("should have expected high-confidence destructive keywords", () => {
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.high).toContain(
        "deletes",
      );
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.high).toContain(
        "removes",
      );
      expect(DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.high).toContain(
        "destroys",
      );
    });
  });
});
