/**
 * Config Types Unit Tests
 *
 * Tests for AssessmentConfiguration interface and preset configurations.
 * Validates that all presets include required fields like configVersion.
 *
 * @module lib/__tests__/configTypes.test
 */

import { describe, it, expect } from "@jest/globals";

import {
  DEFAULT_ASSESSMENT_CONFIG,
  REVIEWER_MODE_CONFIG,
  DEVELOPER_MODE_CONFIG,
  AUDIT_MODE_CONFIG,
  CLAUDE_ENHANCED_AUDIT_CONFIG,
  type AssessmentConfiguration,
} from "../assessment/configTypes";

describe("AssessmentConfiguration presets", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("configVersion field (Issue #107)", () => {
    const CURRENT_CONFIG_VERSION = 2;

    it("should have configVersion: 2 in DEFAULT_ASSESSMENT_CONFIG", () => {
      expect(DEFAULT_ASSESSMENT_CONFIG.configVersion).toBe(
        CURRENT_CONFIG_VERSION,
      );
    });

    it("should have configVersion: 2 in REVIEWER_MODE_CONFIG", () => {
      expect(REVIEWER_MODE_CONFIG.configVersion).toBe(CURRENT_CONFIG_VERSION);
    });

    it("should have configVersion: 2 in DEVELOPER_MODE_CONFIG", () => {
      expect(DEVELOPER_MODE_CONFIG.configVersion).toBe(CURRENT_CONFIG_VERSION);
    });

    it("should have configVersion: 2 in AUDIT_MODE_CONFIG", () => {
      expect(AUDIT_MODE_CONFIG.configVersion).toBe(CURRENT_CONFIG_VERSION);
    });

    it("should have configVersion: 2 in CLAUDE_ENHANCED_AUDIT_CONFIG", () => {
      expect(CLAUDE_ENHANCED_AUDIT_CONFIG.configVersion).toBe(
        CURRENT_CONFIG_VERSION,
      );
    });

    it("should have configVersion as first field in all presets (by convention)", () => {
      // This ensures configVersion is consistently placed at the top of each preset
      const presets: AssessmentConfiguration[] = [
        DEFAULT_ASSESSMENT_CONFIG,
        REVIEWER_MODE_CONFIG,
        DEVELOPER_MODE_CONFIG,
        AUDIT_MODE_CONFIG,
        CLAUDE_ENHANCED_AUDIT_CONFIG,
      ];

      for (const preset of presets) {
        const keys = Object.keys(preset);
        expect(keys[0]).toBe("configVersion");
      }
    });
  });

  describe("preset completeness", () => {
    it("all presets should have required base fields", () => {
      const presets: AssessmentConfiguration[] = [
        DEFAULT_ASSESSMENT_CONFIG,
        REVIEWER_MODE_CONFIG,
        DEVELOPER_MODE_CONFIG,
        AUDIT_MODE_CONFIG,
        CLAUDE_ENHANCED_AUDIT_CONFIG,
      ];

      for (const preset of presets) {
        // Required fields
        expect(preset.testTimeout).toBeGreaterThan(0);
        expect(typeof preset.skipBrokenTools).toBe("boolean");
        expect(preset.assessmentCategories).toBeDefined();

        // configVersion must be present
        expect(preset.configVersion).toBeDefined();
        expect(typeof preset.configVersion).toBe("number");
      }
    });
  });
});
