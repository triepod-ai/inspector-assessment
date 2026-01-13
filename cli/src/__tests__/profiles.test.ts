/**
 * Profile Module Unit Tests
 *
 * Tests for profile definitions, module resolution, and legacy config mapping.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { jest, describe, it, expect } from "@jest/globals";
import {
  ASSESSMENT_PROFILES,
  PROFILE_METADATA,
  MODULE_ALIASES,
  DEPRECATED_MODULES,
  TIER_1_CORE_SECURITY,
  TIER_2_COMPLIANCE,
  TIER_3_CAPABILITY,
  TIER_4_EXTENDED,
  ALL_MODULES,
  resolveModuleNames,
  getProfileModules,
  isValidProfileName,
  getProfileHelpText,
  mapLegacyConfigToModules,
  modulesToLegacyConfig,
  type AssessmentProfileName,
} from "../profiles.js";

describe("Profile Definitions", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("Profile Constants", () => {
    it("should have four profiles defined", () => {
      const profiles = Object.keys(ASSESSMENT_PROFILES);
      expect(profiles).toEqual(["quick", "security", "compliance", "full"]);
    });

    it("should have metadata for all profiles", () => {
      const profileNames = Object.keys(ASSESSMENT_PROFILES);
      const metadataNames = Object.keys(PROFILE_METADATA);
      expect(metadataNames).toEqual(profileNames);
    });

    it("should have correct module counts in metadata", () => {
      for (const [name, meta] of Object.entries(PROFILE_METADATA)) {
        const profile = ASSESSMENT_PROFILES[name as AssessmentProfileName];
        expect(meta.moduleCount).toBe(profile.length);
      }
    });
  });

  describe("Tier Definitions", () => {
    it("should have Tier 1 core security modules", () => {
      expect(TIER_1_CORE_SECURITY).toContain("functionality");
      expect(TIER_1_CORE_SECURITY).toContain("security");
      expect(TIER_1_CORE_SECURITY).toContain("temporal");
      expect(TIER_1_CORE_SECURITY).toContain("errorHandling");
      expect(TIER_1_CORE_SECURITY).toContain("protocolCompliance");
      expect(TIER_1_CORE_SECURITY).toContain("aupCompliance");
    });

    it("should have Tier 2 compliance modules", () => {
      expect(TIER_2_COMPLIANCE).toContain("toolAnnotations");
      expect(TIER_2_COMPLIANCE).toContain("prohibitedLibraries");
      expect(TIER_2_COMPLIANCE).toContain("manifestValidation");
      expect(TIER_2_COMPLIANCE).toContain("authentication");
    });

    it("should have Tier 3 capability modules", () => {
      expect(TIER_3_CAPABILITY).toContain("resources");
      expect(TIER_3_CAPABILITY).toContain("prompts");
      expect(TIER_3_CAPABILITY).toContain("crossCapability");
    });

    it("should have Tier 4 extended modules", () => {
      expect(TIER_4_EXTENDED).toContain("developerExperience");
      expect(TIER_4_EXTENDED).toContain("portability");
      expect(TIER_4_EXTENDED).toContain("externalAPIScanner");
    });

    it("should combine all tiers in ALL_MODULES", () => {
      const expectedLength =
        TIER_1_CORE_SECURITY.length +
        TIER_2_COMPLIANCE.length +
        TIER_3_CAPABILITY.length +
        TIER_4_EXTENDED.length;
      expect(ALL_MODULES.length).toBe(expectedLength);
    });
  });

  describe("Profile Compositions", () => {
    it("quick profile should have functionality and security only", () => {
      expect(ASSESSMENT_PROFILES.quick).toEqual(["functionality", "security"]);
    });

    it("security profile should include all Tier 1 modules", () => {
      for (const module of TIER_1_CORE_SECURITY) {
        expect(ASSESSMENT_PROFILES.security).toContain(module);
      }
    });

    it("compliance profile should include Tier 1 and Tier 2", () => {
      for (const module of TIER_1_CORE_SECURITY) {
        expect(ASSESSMENT_PROFILES.compliance).toContain(module);
      }
      for (const module of TIER_2_COMPLIANCE) {
        expect(ASSESSMENT_PROFILES.compliance).toContain(module);
      }
    });

    it("full profile should include all tiers", () => {
      for (const module of ALL_MODULES) {
        expect(ASSESSMENT_PROFILES.full).toContain(module);
      }
    });
  });
});

describe("Module Aliases", () => {
  it("should map deprecated mcpSpecCompliance to protocolCompliance", () => {
    expect(MODULE_ALIASES.mcpSpecCompliance).toBe("protocolCompliance");
  });

  it("should map deprecated protocolConformance to protocolCompliance", () => {
    expect(MODULE_ALIASES.protocolConformance).toBe("protocolCompliance");
  });

  it("should map deprecated documentation to developerExperience", () => {
    expect(MODULE_ALIASES.documentation).toBe("developerExperience");
  });

  it("should map deprecated usability to developerExperience", () => {
    expect(MODULE_ALIASES.usability).toBe("developerExperience");
  });

  it("should have DEPRECATED_MODULES match MODULE_ALIASES keys", () => {
    const aliasKeys = Object.keys(MODULE_ALIASES);
    for (const key of aliasKeys) {
      expect(DEPRECATED_MODULES.has(key)).toBe(true);
    }
    expect(DEPRECATED_MODULES.size).toBe(aliasKeys.length);
  });
});

describe("resolveModuleNames", () => {
  it("should return unchanged names for non-deprecated modules", () => {
    const modules = ["functionality", "security", "temporal"];
    const result = resolveModuleNames(modules, false);
    expect(result).toEqual(modules);
  });

  it("should replace deprecated module names with aliases", () => {
    const modules = ["mcpSpecCompliance", "documentation"];
    const result = resolveModuleNames(modules, false);
    expect(result).toContain("protocolCompliance");
    expect(result).toContain("developerExperience");
    expect(result).not.toContain("mcpSpecCompliance");
    expect(result).not.toContain("documentation");
  });

  it("should deduplicate when deprecated and replacement both specified", () => {
    const modules = ["mcpSpecCompliance", "protocolCompliance"];
    const result = resolveModuleNames(modules, false);
    expect(result.length).toBe(1);
    expect(result).toContain("protocolCompliance");
  });

  it("should emit warnings for deprecated modules when warn=true", () => {
    const consoleSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    try {
      const modules = ["documentation"];
      resolveModuleNames(modules, true);
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("deprecated"),
      );
    } finally {
      consoleSpy.mockRestore();
    }
  });

  it("should not emit warnings when warn=false", () => {
    const consoleSpy = jest.spyOn(console, "warn").mockImplementation(() => {});

    try {
      const modules = ["documentation"];
      resolveModuleNames(modules, false);
      expect(consoleSpy).not.toHaveBeenCalled();
    } finally {
      consoleSpy.mockRestore();
    }
  });
});

describe("getProfileModules", () => {
  it("should return modules for quick profile", () => {
    const modules = getProfileModules("quick");
    expect(modules).toEqual(["functionality", "security"]);
  });

  it("should return modules for security profile", () => {
    const modules = getProfileModules("security");
    expect(modules.length).toBe(TIER_1_CORE_SECURITY.length);
    for (const mod of TIER_1_CORE_SECURITY) {
      expect(modules).toContain(mod);
    }
  });

  it("should exclude temporal when skipTemporal=true", () => {
    const modules = getProfileModules("security", { skipTemporal: true });
    expect(modules).not.toContain("temporal");
  });

  it("should exclude externalAPIScanner when hasSourceCode=false", () => {
    const modules = getProfileModules("full", { hasSourceCode: false });
    expect(modules).not.toContain("externalAPIScanner");
  });

  it("should include externalAPIScanner when hasSourceCode=true", () => {
    const modules = getProfileModules("full", { hasSourceCode: true });
    expect(modules).toContain("externalAPIScanner");
  });

  it("should handle multiple options together", () => {
    const modules = getProfileModules("full", {
      skipTemporal: true,
      hasSourceCode: false,
    });
    expect(modules).not.toContain("temporal");
    expect(modules).not.toContain("externalAPIScanner");
  });
});

describe("isValidProfileName", () => {
  it("should return true for valid profile names", () => {
    expect(isValidProfileName("quick")).toBe(true);
    expect(isValidProfileName("security")).toBe(true);
    expect(isValidProfileName("compliance")).toBe(true);
    expect(isValidProfileName("full")).toBe(true);
  });

  it("should return false for invalid profile names", () => {
    expect(isValidProfileName("invalid")).toBe(false);
    expect(isValidProfileName("")).toBe(false);
    expect(isValidProfileName("QUICK")).toBe(false);
    expect(isValidProfileName("fast")).toBe(false);
  });
});

describe("getProfileHelpText", () => {
  it("should return non-empty string", () => {
    const help = getProfileHelpText();
    expect(help.length).toBeGreaterThan(0);
  });

  it("should contain all profile names", () => {
    const help = getProfileHelpText();
    expect(help).toContain("quick");
    expect(help).toContain("security");
    expect(help).toContain("compliance");
    expect(help).toContain("full");
  });

  it("should contain module counts", () => {
    const help = getProfileHelpText();
    expect(help).toContain("Modules:");
  });

  it("should contain time estimates", () => {
    const help = getProfileHelpText();
    expect(help).toContain("Time:");
  });
});

describe("mapLegacyConfigToModules", () => {
  it("should return empty array for empty config", () => {
    const result = mapLegacyConfigToModules({});
    expect(result).toEqual([]);
  });

  it("should return enabled modules", () => {
    const config = {
      functionality: true,
      security: true,
      temporal: false,
    };
    const result = mapLegacyConfigToModules(config);
    expect(result).toContain("functionality");
    expect(result).toContain("security");
    expect(result).not.toContain("temporal");
  });

  it("should apply aliases for deprecated names", () => {
    const config = {
      documentation: true,
      mcpSpecCompliance: true,
    };
    const result = mapLegacyConfigToModules(config);
    expect(result).toContain("developerExperience");
    expect(result).toContain("protocolCompliance");
    expect(result).not.toContain("documentation");
    expect(result).not.toContain("mcpSpecCompliance");
  });

  it("should deduplicate when both deprecated and new names enabled", () => {
    const config = {
      documentation: true,
      developerExperience: true,
    };
    const result = mapLegacyConfigToModules(config);
    const devExpCount = result.filter(
      (m) => m === "developerExperience",
    ).length;
    expect(devExpCount).toBe(1);
  });
});

describe("modulesToLegacyConfig", () => {
  it("should return config with all modules disabled by default", () => {
    const result = modulesToLegacyConfig([]);
    expect(result.functionality).toBe(false);
    expect(result.security).toBe(false);
  });

  it("should enable specified modules", () => {
    const result = modulesToLegacyConfig(["functionality", "security"]);
    expect(result.functionality).toBe(true);
    expect(result.security).toBe(true);
    expect(result.temporal).toBe(false);
  });

  it("should map protocolCompliance to both old modules", () => {
    const result = modulesToLegacyConfig(["protocolCompliance"]);
    expect(result.mcpSpecCompliance).toBe(true);
    expect(result.protocolConformance).toBe(true);
  });

  it("should map developerExperience to both old modules", () => {
    const result = modulesToLegacyConfig(["developerExperience"]);
    expect(result.documentation).toBe(true);
    expect(result.usability).toBe(true);
  });

  it("should handle full profile modules", () => {
    const modules = getProfileModules("full", { hasSourceCode: true });
    const result = modulesToLegacyConfig(modules);
    expect(result.functionality).toBe(true);
    expect(result.security).toBe(true);
    expect(result.temporal).toBe(true);
    expect(result.toolAnnotations).toBe(true);
  });
});

describe("Profile Metadata", () => {
  it("should have descriptions for all profiles", () => {
    for (const meta of Object.values(PROFILE_METADATA)) {
      expect(meta.description).toBeTruthy();
      expect(typeof meta.description).toBe("string");
    }
  });

  it("should have estimated times for all profiles", () => {
    for (const meta of Object.values(PROFILE_METADATA)) {
      expect(meta.estimatedTime).toBeTruthy();
      expect(meta.estimatedTime).toMatch(/~\d+-?\d*\s*minutes?/);
    }
  });

  it("should have tier information for all profiles", () => {
    for (const meta of Object.values(PROFILE_METADATA)) {
      expect(Array.isArray(meta.tiers)).toBe(true);
      expect(meta.tiers.length).toBeGreaterThan(0);
    }
  });

  it("should have correct tier counts", () => {
    expect(PROFILE_METADATA.quick.tiers.length).toBe(1);
    expect(PROFILE_METADATA.security.tiers.length).toBe(1);
    expect(PROFILE_METADATA.compliance.tiers.length).toBe(2);
    expect(PROFILE_METADATA.full.tiers.length).toBe(4);
  });
});
