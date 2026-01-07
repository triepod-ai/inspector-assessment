/**
 * Assessment Profiles
 *
 * Pre-configured module sets for common assessment scenarios.
 * Profiles map to the 4-tier module organization:
 *
 * Tier 1: Core Security (Always Run)
 *   - functionality, security, temporal, errorHandling, protocolCompliance, aupCompliance
 *
 * Tier 2: Compliance (MCP Directory)
 *   - toolAnnotations, prohibitedLibraries, manifestValidation, authentication
 *
 * Tier 3: Capability-Based (Conditional)
 *   - resources, prompts, crossCapability
 *
 * Tier 4: Extended (Optional)
 *   - developerExperience, portability, externalAPIScanner
 *
 * @module cli/profiles
 */

/**
 * Valid profile names for CLI --profile flag
 */
export type AssessmentProfileName =
  | "quick"
  | "security"
  | "compliance"
  | "full";

/**
 * Module alias mappings for backward compatibility.
 * Maps deprecated module names to their replacements.
 */
export const MODULE_ALIASES: Record<string, string> = {
  // Protocol compliance merge (MCPSpec + ProtocolConformance → ProtocolCompliance)
  mcpSpecCompliance: "protocolCompliance",
  protocolConformance: "protocolCompliance",
  // Developer experience merge (Documentation + Usability → DeveloperExperience)
  documentation: "developerExperience",
  usability: "developerExperience",
};

/**
 * Deprecated module names that trigger a warning when used.
 */
export const DEPRECATED_MODULES = new Set(Object.keys(MODULE_ALIASES));

/**
 * Tier 1: Core Security modules
 * Essential for any MCP server assessment - security-focused
 */
export const TIER_1_CORE_SECURITY = [
  "functionality",
  "security",
  "temporal",
  "errorHandling",
  "protocolCompliance",
  "aupCompliance",
] as const;

/**
 * Tier 2: Compliance modules
 * Required for MCP Directory submission compliance
 */
export const TIER_2_COMPLIANCE = [
  "toolAnnotations",
  "prohibitedLibraries",
  "manifestValidation",
  "authentication",
] as const;

/**
 * Tier 3: Capability-Based modules
 * Only run when server has corresponding capabilities
 */
export const TIER_3_CAPABILITY = [
  "resources",
  "prompts",
  "crossCapability",
] as const;

/**
 * Tier 4: Extended modules
 * Optional assessments for comprehensive audits
 */
export const TIER_4_EXTENDED = [
  "developerExperience",
  "portability",
  "externalAPIScanner",
] as const;

/**
 * All available modules (new naming)
 */
export const ALL_MODULES = [
  ...TIER_1_CORE_SECURITY,
  ...TIER_2_COMPLIANCE,
  ...TIER_3_CAPABILITY,
  ...TIER_4_EXTENDED,
] as const;

/**
 * Assessment profile definitions
 * Each profile includes a specific set of modules optimized for the use case.
 */
export const ASSESSMENT_PROFILES: Record<AssessmentProfileName, string[]> = {
  /**
   * Quick profile: Minimal testing for fast CI/CD checks
   * Use when: Pre-commit hooks, quick validation
   * Time: ~30 seconds
   */
  quick: ["functionality", "security"],

  /**
   * Security profile: Core security modules (Tier 1)
   * Use when: Security-focused audits, vulnerability scanning
   * Time: ~2-3 minutes
   */
  security: [...TIER_1_CORE_SECURITY],

  /**
   * Compliance profile: Security + Directory compliance (Tier 1 + 2)
   * Use when: Pre-submission validation for MCP Directory
   * Time: ~5 minutes
   */
  compliance: [...TIER_1_CORE_SECURITY, ...TIER_2_COMPLIANCE],

  /**
   * Full profile: All modules (Tier 1 + 2 + 3 + 4)
   * Use when: Comprehensive audits, initial server review
   * Time: ~10-15 minutes
   */
  full: [
    ...TIER_1_CORE_SECURITY,
    ...TIER_2_COMPLIANCE,
    ...TIER_3_CAPABILITY,
    ...TIER_4_EXTENDED,
  ],
};

/**
 * Profile metadata for help text and documentation
 */
export interface ProfileMetadata {
  description: string;
  estimatedTime: string;
  moduleCount: number;
  tiers: string[];
}

export const PROFILE_METADATA: Record<AssessmentProfileName, ProfileMetadata> =
  {
    quick: {
      description: "Fast validation (functionality + security only)",
      estimatedTime: "~30 seconds",
      moduleCount: ASSESSMENT_PROFILES.quick.length,
      tiers: ["Tier 1 (partial)"],
    },
    security: {
      description: "Core security modules for vulnerability scanning",
      estimatedTime: "~2-3 minutes",
      moduleCount: ASSESSMENT_PROFILES.security.length,
      tiers: ["Tier 1 (Core Security)"],
    },
    compliance: {
      description: "Security + MCP Directory compliance validation",
      estimatedTime: "~5 minutes",
      moduleCount: ASSESSMENT_PROFILES.compliance.length,
      tiers: ["Tier 1 (Core Security)", "Tier 2 (Compliance)"],
    },
    full: {
      description: "Comprehensive audit with all assessment modules",
      estimatedTime: "~10-15 minutes",
      moduleCount: ASSESSMENT_PROFILES.full.length,
      tiers: [
        "Tier 1 (Core Security)",
        "Tier 2 (Compliance)",
        "Tier 3 (Capability)",
        "Tier 4 (Extended)",
      ],
    },
  };

/**
 * Resolve module names, applying aliases for deprecated names.
 * Emits warnings for deprecated module usage.
 *
 * @param modules - Array of module names (may include deprecated names)
 * @param warn - If true, emit console warnings for deprecated names
 * @returns Array of resolved module names (with aliases applied)
 */
export function resolveModuleNames(
  modules: string[],
  warn: boolean = true,
): string[] {
  const resolved: Set<string> = new Set();

  for (const module of modules) {
    if (DEPRECATED_MODULES.has(module)) {
      const replacement = MODULE_ALIASES[module];
      if (warn) {
        console.warn(
          `Warning: Module '${module}' is deprecated, using '${replacement}' instead`,
        );
      }
      resolved.add(replacement);
    } else {
      resolved.add(module);
    }
  }

  return Array.from(resolved);
}

/**
 * Get modules for a profile, with optional source code awareness.
 *
 * @param profileName - Profile to get modules for
 * @param options.hasSourceCode - If true, includes source-dependent modules
 * @param options.skipTemporal - If true, excludes temporal module
 * @returns Array of module names to run
 */
export function getProfileModules(
  profileName: AssessmentProfileName,
  options: { hasSourceCode?: boolean; skipTemporal?: boolean } = {},
): string[] {
  let modules = [...ASSESSMENT_PROFILES[profileName]];

  // Filter out temporal if requested
  if (options.skipTemporal) {
    modules = modules.filter((m) => m !== "temporal");
  }

  // externalAPIScanner requires source code
  if (!options.hasSourceCode) {
    modules = modules.filter((m) => m !== "externalAPIScanner");
  }

  // prohibitedLibraries is most effective with source code
  // (still runs but with limited capability)

  return modules;
}

/**
 * Validate a profile name.
 *
 * @param name - Profile name to validate
 * @returns True if valid profile name
 */
export function isValidProfileName(
  name: string,
): name is AssessmentProfileName {
  return name in ASSESSMENT_PROFILES;
}

/**
 * Get help text for profiles.
 */
export function getProfileHelpText(): string {
  const lines: string[] = ["Assessment Profiles:", ""];

  for (const [name, metadata] of Object.entries(PROFILE_METADATA)) {
    lines.push(`  ${name.padEnd(12)} ${metadata.description}`);
    lines.push(
      `               Modules: ${metadata.moduleCount}, Time: ${metadata.estimatedTime}`,
    );
    lines.push(`               Tiers: ${metadata.tiers.join(", ")}`);
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Map old module config keys to new profile-based module list.
 * Used for backward compatibility with existing configs.
 *
 * @param oldConfig - Old-style assessmentCategories object
 * @returns Array of enabled module names (new naming)
 */
export function mapLegacyConfigToModules(
  oldConfig: Record<string, boolean>,
): string[] {
  const enabled: string[] = [];

  for (const [key, value] of Object.entries(oldConfig)) {
    if (value === true) {
      // Apply alias resolution for deprecated names
      const resolved = MODULE_ALIASES[key] || key;
      if (!enabled.includes(resolved)) {
        enabled.push(resolved);
      }
    }
  }

  return enabled;
}

/**
 * Convert new module list to old-style config object.
 * Used for backward compatibility with existing orchestrator.
 *
 * @param modules - Array of module names (new naming)
 * @returns Old-style assessmentCategories object
 */
export function modulesToLegacyConfig(
  modules: string[],
): Record<string, boolean> {
  // Start with all modules disabled
  const config: Record<string, boolean> = {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
    mcpSpecCompliance: false,
    aupCompliance: false,
    toolAnnotations: false,
    prohibitedLibraries: false,
    manifestValidation: false,
    portability: false,
    externalAPIScanner: false,
    authentication: false,
    temporal: false,
    resources: false,
    prompts: false,
    crossCapability: false,
    protocolConformance: false,
  };

  // Enable requested modules, mapping new names to old where needed
  for (const module of modules) {
    if (module === "protocolCompliance") {
      // Map to both old modules for backward compat until orchestrator updated
      config.mcpSpecCompliance = true;
      config.protocolConformance = true;
    } else if (module === "developerExperience") {
      // Map to both old modules for backward compat until orchestrator updated
      config.documentation = true;
      config.usability = true;
    } else if (module in config) {
      config[module] = true;
    }
  }

  return config;
}
