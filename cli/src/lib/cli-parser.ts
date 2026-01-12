/**
 * CLI Parser Module
 *
 * Handles command-line argument parsing, validation, and help text for
 * the mcp-assess-full CLI tool.
 *
 * Extracted from assess-full.ts as part of Issue #90 modularization.
 *
 * @module cli/lib/cli-parser
 */

import {
  ASSESSMENT_CATEGORY_METADATA,
  LogLevel,
} from "../../../client/lib/lib/assessmentTypes.js";
import { type ReportFormat } from "../../../client/lib/lib/reportFormatters/index.js";
import {
  ASSESSMENT_PROFILES,
  getProfileHelpText,
  TIER_1_CORE_SECURITY,
  TIER_2_COMPLIANCE,
  TIER_3_CAPABILITY,
  TIER_4_EXTENDED,
  type AssessmentProfileName,
} from "../profiles.js";
import packageJson from "../../package.json" with { type: "json" };
import {
  safeParseModuleNames,
  LogLevelSchema,
  ReportFormatSchema,
  OutputFormatSchema,
  AssessmentProfileNameSchema,
  type OutputFormat,
} from "./cli-parserSchemas.js";

// ============================================================================
// Types
// ============================================================================

/**
 * Server connection configuration
 */
export interface ServerConfig {
  transport?: "stdio" | "http" | "sse";
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  url?: string;
}

/**
 * Assessment options from CLI arguments
 */
export interface AssessmentOptions {
  serverName: string;
  serverConfigPath?: string;
  outputPath?: string;
  sourceCodePath?: string;
  patternConfigPath?: string;
  /** Path to performance configuration JSON (Issue #37) */
  performanceConfigPath?: string;
  claudeEnabled?: boolean;
  /** Enable HTTP transport for Claude Bridge (connects to mcp-auditor proxy) */
  claudeHttp?: boolean;
  /** URL for mcp-auditor Claude proxy (default: http://localhost:8085) */
  mcpAuditorUrl?: string;
  fullAssessment?: boolean;
  verbose?: boolean;
  jsonOnly?: boolean;
  helpRequested?: boolean;
  /** Version requested via --version flag */
  versionRequested?: boolean;
  format?: ReportFormat;
  includePolicy?: boolean;
  preflightOnly?: boolean;
  comparePath?: string;
  diffOnly?: boolean;
  resume?: boolean;
  noResume?: boolean;
  temporalInvocations?: number;
  skipTemporal?: boolean;
  skipModules?: string[];
  onlyModules?: string[];
  /** Assessment profile (quick, security, compliance, full) */
  profile?: AssessmentProfileName;
  /** Log level for diagnostic output */
  logLevel?: LogLevel;
  /** List available modules and exit */
  listModules?: boolean;
  /** Enable official MCP conformance tests (requires HTTP/SSE transport) */
  conformanceEnabled?: boolean;
  /** Output format for tiered output strategy (Issue #136) */
  outputFormat?: OutputFormat;
  /** Auto-enable tiered output when results exceed token threshold */
  autoTier?: boolean;
}

/**
 * Result of argument validation
 */
export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

// ============================================================================
// Constants
// ============================================================================

// Valid module names derived from ASSESSMENT_CATEGORY_METADATA (used for help text)
const VALID_MODULE_NAMES = Object.keys(
  ASSESSMENT_CATEGORY_METADATA,
) as (keyof typeof ASSESSMENT_CATEGORY_METADATA)[];

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Validate module names from CLI input using Zod schema.
 *
 * @param input - Comma-separated module names
 * @param flagName - Flag name for error messages (e.g., "--skip-modules")
 * @returns Array of validated module names, or empty array if invalid
 */
export function validateModuleNames(input: string, flagName: string): string[] {
  const result = safeParseModuleNames(input);

  if (result.invalid.length > 0) {
    console.error(
      `Error: Invalid module name(s) for ${flagName}: ${result.invalid.join(", ")}`,
    );
    console.error(`Valid modules: ${VALID_MODULE_NAMES.join(", ")}`);
    setTimeout(() => process.exit(1), 10);
    return [];
  }
  return result.valid;
}

/**
 * Validate parsed options for consistency and requirements
 *
 * @param options - Partial assessment options to validate
 * @returns Validation result with any errors
 */
export function validateArgs(
  options: Partial<AssessmentOptions>,
): ValidationResult {
  const errors: string[] = [];

  // Server name is required
  if (!options.serverName) {
    errors.push("--server is required");
  }

  // Validate mutual exclusivity of --profile, --skip-modules, and --only-modules
  if (
    options.profile &&
    (options.skipModules?.length || options.onlyModules?.length)
  ) {
    errors.push(
      "--profile cannot be used with --skip-modules or --only-modules",
    );
  }

  if (options.skipModules?.length && options.onlyModules?.length) {
    errors.push("--skip-modules and --only-modules are mutually exclusive");
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

// ============================================================================
// Argument Parsing
// ============================================================================

/**
 * Parse command-line arguments
 *
 * @param argv - Command-line arguments (defaults to process.argv.slice(2))
 * @returns Parsed assessment options
 */
export function parseArgs(argv?: string[]): AssessmentOptions {
  const args = argv ?? process.argv.slice(2);
  const options: Partial<AssessmentOptions> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;

    switch (arg) {
      case "--server":
      case "-s":
        options.serverName = args[++i];
        break;
      case "--config":
      case "-c":
        options.serverConfigPath = args[++i];
        break;
      case "--output":
      case "-o":
        options.outputPath = args[++i];
        break;
      case "--source":
        options.sourceCodePath = args[++i];
        break;
      case "--pattern-config":
      case "-p":
        options.patternConfigPath = args[++i];
        break;
      case "--performance-config":
        options.performanceConfigPath = args[++i];
        break;
      case "--claude-enabled":
        options.claudeEnabled = true;
        break;
      case "--claude-http":
        // Enable Claude Bridge with HTTP transport (connects to mcp-auditor)
        options.claudeEnabled = true;
        options.claudeHttp = true;
        break;
      case "--mcp-auditor-url": {
        const urlValue = args[++i];
        if (!urlValue || urlValue.startsWith("-")) {
          console.error("Error: --mcp-auditor-url requires a URL argument");
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        try {
          new URL(urlValue); // Validate URL format
          options.mcpAuditorUrl = urlValue;
        } catch {
          console.error(
            `Error: Invalid URL for --mcp-auditor-url: ${urlValue}`,
          );
          console.error(
            "  Expected format: http://hostname:port or https://hostname:port",
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        break;
      }
      case "--full":
        options.fullAssessment = true;
        break;
      case "--verbose":
      case "-v":
        options.verbose = true;
        options.logLevel = "debug";
        break;
      case "--silent":
        options.logLevel = "silent";
        break;
      case "--log-level": {
        const levelValue = args[++i];
        const parseResult = LogLevelSchema.safeParse(levelValue);
        if (!parseResult.success) {
          console.error(
            `Invalid log level: ${levelValue}. Valid options: silent, error, warn, info, debug`,
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.logLevel = parseResult.data;
        break;
      }
      case "--json":
        options.jsonOnly = true;
        break;
      case "--format":
      case "-f": {
        const formatValue = args[++i];
        const parseResult = ReportFormatSchema.safeParse(formatValue);
        if (!parseResult.success) {
          console.error(
            `Invalid format: ${formatValue}. Valid options: json, markdown`,
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.format = parseResult.data;
        break;
      }
      case "--include-policy":
        options.includePolicy = true;
        break;
      case "--preflight":
        options.preflightOnly = true;
        break;
      case "--compare":
        options.comparePath = args[++i];
        break;
      case "--diff-only":
        options.diffOnly = true;
        break;
      case "--resume":
        options.resume = true;
        break;
      case "--no-resume":
        options.noResume = true;
        break;
      case "--temporal-invocations":
        options.temporalInvocations = parseInt(args[++i], 10);
        break;
      case "--skip-temporal":
        options.skipTemporal = true;
        break;
      case "--conformance":
        // Enable official MCP conformance tests (requires HTTP/SSE transport with serverUrl)
        options.conformanceEnabled = true;
        break;
      case "--output-format": {
        // Issue #136: Tiered output strategy for large assessments
        const outputFormatValue = args[++i];
        if (!outputFormatValue) {
          console.error("Error: --output-format requires a format");
          console.error("Valid formats: full, tiered, summary-only");
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        const parseResult = OutputFormatSchema.safeParse(outputFormatValue);
        if (!parseResult.success) {
          console.error(`Error: Invalid output format: ${outputFormatValue}`);
          console.error("Valid formats: full, tiered, summary-only");
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.outputFormat = parseResult.data;
        break;
      }
      case "--auto-tier":
        // Issue #136: Auto-enable tiered output when results exceed token threshold
        options.autoTier = true;
        break;
      case "--profile": {
        const profileValue = args[++i];
        if (!profileValue) {
          console.error("Error: --profile requires a profile name");
          console.error(
            `Valid profiles: ${Object.keys(ASSESSMENT_PROFILES).join(", ")}`,
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        const parseResult = AssessmentProfileNameSchema.safeParse(profileValue);
        if (!parseResult.success) {
          console.error(`Error: Invalid profile name: ${profileValue}`);
          console.error(
            `Valid profiles: ${Object.keys(ASSESSMENT_PROFILES).join(", ")}`,
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.profile = parseResult.data;
        break;
      }
      case "--skip-modules": {
        const skipValue = args[++i];
        if (!skipValue) {
          console.error(
            "Error: --skip-modules requires a comma-separated list",
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.skipModules = validateModuleNames(skipValue, "--skip-modules");
        if (options.skipModules.length === 0 && skipValue) {
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        break;
      }
      case "--only-modules": {
        const onlyValue = args[++i];
        if (!onlyValue) {
          console.error(
            "Error: --only-modules requires a comma-separated list",
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.onlyModules = validateModuleNames(onlyValue, "--only-modules");
        if (options.onlyModules.length === 0 && onlyValue) {
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        break;
      }
      case "--list-modules":
        printModules();
        options.listModules = true;
        return options as AssessmentOptions;
      case "--version":
      case "-V":
        printVersion();
        options.versionRequested = true;
        return options as AssessmentOptions;
      case "--help":
      case "-h":
        printHelp();
        options.helpRequested = true;
        return options as AssessmentOptions;
      default:
        if (!arg.startsWith("-")) {
          if (!options.serverName) {
            options.serverName = arg;
          }
        } else {
          console.error(`Unknown argument: ${arg}`);
          printHelp();
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
    }
  }

  // Validate mutual exclusivity of --profile, --skip-modules, and --only-modules
  if (
    options.profile &&
    (options.skipModules?.length || options.onlyModules?.length)
  ) {
    console.error(
      "Error: --profile cannot be used with --skip-modules or --only-modules",
    );
    setTimeout(() => process.exit(1), 10);
    options.helpRequested = true;
    return options as AssessmentOptions;
  }

  if (options.skipModules?.length && options.onlyModules?.length) {
    console.error(
      "Error: --skip-modules and --only-modules are mutually exclusive",
    );
    setTimeout(() => process.exit(1), 10);
    options.helpRequested = true;
    return options as AssessmentOptions;
  }

  if (!options.serverName) {
    console.error("Error: --server is required");
    printHelp();
    setTimeout(() => process.exit(1), 10);
    options.helpRequested = true;
    return options as AssessmentOptions;
  }

  // Environment variable fallbacks (matches run-security-assessment.ts behavior)
  // INSPECTOR_CLAUDE=true enables Claude with HTTP transport
  if (process.env.INSPECTOR_CLAUDE === "true" && !options.claudeEnabled) {
    options.claudeEnabled = true;
    options.claudeHttp = true; // HTTP transport when enabled via env var
  }

  // INSPECTOR_MCP_AUDITOR_URL overrides default URL (only if not set via CLI)
  if (process.env.INSPECTOR_MCP_AUDITOR_URL && !options.mcpAuditorUrl) {
    const envUrl = process.env.INSPECTOR_MCP_AUDITOR_URL;
    try {
      new URL(envUrl);
      options.mcpAuditorUrl = envUrl;
    } catch {
      console.warn(
        `Warning: Invalid INSPECTOR_MCP_AUDITOR_URL: ${envUrl}, using default`,
      );
    }
  }

  return options as AssessmentOptions;
}

// ============================================================================
// Version and Help Text
// ============================================================================

/**
 * Get package version from package.json
 */
function getPackageVersion(): string {
  return packageJson.version;
}

/**
 * Print version to console
 */
export function printVersion(): void {
  console.log(`mcp-assess-full ${getPackageVersion()}`);
}

/**
 * Print help message to console
 */
export function printHelp(): void {
  console.log(`
Usage: mcp-assess-full [options] [server-name]

Run comprehensive MCP server assessment with 16 assessor modules organized in 4 tiers.

Options:
  --server, -s <name>    Server name (required, or pass as first positional arg)
  --config, -c <path>    Path to server config JSON
  --output, -o <path>    Output path (default: /tmp/inspector-full-assessment-<server>.<ext>)
  --source <path>        Source code path for deep analysis (AUP, portability, etc.)
  --pattern-config, -p <path>  Path to custom annotation pattern JSON
  --performance-config <path>  Path to performance tuning JSON (batch sizes, timeouts, etc.)
  --format, -f <type>    Output format: json (default) or markdown
  --include-policy       Include policy compliance mapping in report (30 requirements)
  --preflight            Run quick validation only (tools exist, manifest valid, server responds)
  --compare <path>       Compare current assessment against baseline JSON file
  --diff-only            Output only the comparison diff (requires --compare)
  --resume               Resume from previous interrupted assessment
  --no-resume            Force fresh start, clear any existing state
  --claude-enabled       Enable Claude Code integration (CLI transport: requires 'claude' binary)
  --claude-http          Enable Claude Code via HTTP transport (connects to mcp-auditor proxy)
  --mcp-auditor-url <url>  mcp-auditor URL for HTTP transport (default: http://localhost:8085)
  --full                 Enable all assessment modules (default)
  --profile <name>       Use predefined module profile (quick, security, compliance, full)
  --temporal-invocations <n>  Number of invocations per tool for rug pull detection (default: 25)
  --skip-temporal        Skip temporal/rug pull testing (faster assessment)
  --conformance          Enable official MCP conformance tests (experimental, requires HTTP/SSE transport)
  --output-format <fmt>  Output format: full (default), tiered, summary-only
                         full: Complete JSON output (existing behavior)
                         tiered: Directory with executive-summary.json, tool-summaries.json, tools/
                         summary-only: Executive summary + tool summaries (no per-tool details)
  --auto-tier            Auto-enable tiered output when results exceed 100K tokens
  --skip-modules <list>  Skip specific modules (comma-separated)
  --only-modules <list>  Run only specific modules (comma-separated)
  --json                 Output only JSON path (no console summary)
  --verbose, -v          Enable verbose logging (same as --log-level debug)
  --silent               Suppress all diagnostic logging
  --log-level <level>    Set log level: silent, error, warn, info (default), debug
                         Also supports LOG_LEVEL environment variable
  --version, -V          Show version number
  --help, -h             Show this help message

Environment Variables:
  INSPECTOR_CLAUDE=true         Enable Claude with HTTP transport (same as --claude-http)
  INSPECTOR_MCP_AUDITOR_URL     Override default mcp-auditor URL (default: http://localhost:8085)
  LOG_LEVEL                     Set log level (overridden by --log-level flag)

${getProfileHelpText()}
Module Selection:
  --profile, --skip-modules, and --only-modules are mutually exclusive.
  Use --profile for common assessment scenarios.
  Use --skip-modules for custom runs by disabling expensive modules.
  Use --only-modules to focus on specific areas (e.g., tool annotation PRs).

  Valid module names (new naming):
    functionality, security, errorHandling, protocolCompliance, aupCompliance,
    toolAnnotations, prohibitedLibraries, manifestValidation, authentication,
    temporal, resources, prompts, crossCapability, developerExperience,
    portability, externalAPIScanner

  Legacy module names (deprecated, will map to new names):
    documentation -> developerExperience
    usability -> developerExperience
    mcpSpecCompliance -> protocolCompliance
    protocolConformance -> protocolCompliance

Module Tiers (16 total):
  Tier 1 - Core Security (Always Run):
    • Functionality      - Tests all tools work correctly
    • Security           - Prompt injection & vulnerability testing
    • Error Handling     - Validates error responses
    • Protocol Compliance - MCP protocol + JSON-RPC validation
    • AUP Compliance     - Acceptable Use Policy checks
    • Temporal           - Rug pull/temporal behavior change detection

  Tier 2 - Compliance (MCP Directory):
    • Tool Annotations   - readOnlyHint/destructiveHint validation
    • Prohibited Libs    - Dependency security checks
    • Manifest           - MCPB manifest.json validation
    • Authentication     - OAuth/auth evaluation

  Tier 3 - Capability-Based (Conditional):
    • Resources          - Resource capability assessment
    • Prompts            - Prompt capability assessment
    • Cross-Capability   - Chained vulnerability detection

  Tier 4 - Extended (Optional):
    • Developer Experience - Documentation + usability assessment
    • Portability        - Cross-platform compatibility
    • External API       - External service detection

Examples:
  # Profile-based (recommended):
  mcp-assess-full my-server --profile quick         # CI/CD fast check (~30s)
  mcp-assess-full my-server --profile security      # Security audit (~2-3min)
  mcp-assess-full my-server --profile compliance    # Directory submission (~5min)
  mcp-assess-full my-server --profile full          # Comprehensive audit (~10-15min)

  # Custom module selection:
  mcp-assess-full my-server --skip-modules temporal,resources  # Skip expensive modules
  mcp-assess-full my-server --only-modules functionality,toolAnnotations  # Annotation PR review

  # Advanced options:
  mcp-assess-full --server my-server --source ./my-server --output ./results.json
  mcp-assess-full --server my-server --format markdown --include-policy
  mcp-assess-full --server my-server --compare ./baseline.json --diff-only
  `);
}

/**
 * Module description mappings for printModules output.
 * Uses human-friendly descriptions that may differ from ASSESSMENT_CATEGORY_METADATA.
 */
const MODULE_DESCRIPTIONS: Record<string, string> = {
  functionality: "Tool functionality validation",
  security: "Security vulnerability detection (23 attack patterns)",
  temporal: "Temporal/rug pull detection",
  errorHandling: "Error handling compliance",
  protocolCompliance: "MCP protocol + JSON-RPC validation",
  aupCompliance: "Acceptable use policy compliance",
  toolAnnotations: "Tool annotation validation (readOnlyHint, destructiveHint)",
  prohibitedLibraries: "Prohibited library detection",
  manifestValidation: "MCPB manifest.json validation",
  authentication: "OAuth/auth evaluation",
  resources: "Resource path traversal + sensitive data exposure",
  prompts: "Prompt AUP compliance + injection testing",
  crossCapability: "Cross-capability attack chain detection",
  developerExperience: "Documentation + usability assessment",
  portability: "Cross-platform compatibility",
  externalAPIScanner: "External API detection (requires --source)",
};

/**
 * Print available modules organized by tier
 */
export function printModules(): void {
  const formatModule = (name: string): string => {
    const desc =
      MODULE_DESCRIPTIONS[name] ||
      ASSESSMENT_CATEGORY_METADATA[
        name as keyof typeof ASSESSMENT_CATEGORY_METADATA
      ]?.description ||
      "";
    return `  ${name.padEnd(22)} ${desc}`;
  };

  console.log(`
Available Assessment Modules (16 total):

Tier 1 - Core Security (${TIER_1_CORE_SECURITY.length} modules):
${TIER_1_CORE_SECURITY.map(formatModule).join("\n")}

Tier 2 - Compliance (${TIER_2_COMPLIANCE.length} modules):
${TIER_2_COMPLIANCE.map(formatModule).join("\n")}

Tier 3 - Capability-Based (${TIER_3_CAPABILITY.length} modules):
${TIER_3_CAPABILITY.map(formatModule).join("\n")}

Tier 4 - Extended (${TIER_4_EXTENDED.length} modules):
${TIER_4_EXTENDED.map(formatModule).join("\n")}

Usage:
  --only-modules <list>   Run only specified modules (comma-separated)
  --skip-modules <list>   Skip specified modules (comma-separated)
  --profile <name>        Use predefined profile (quick, security, compliance, full)

Examples:
  mcp-assess-full my-server --only-modules functionality,security
  mcp-assess-full my-server --skip-modules temporal,portability
  mcp-assess-full my-server --profile compliance
`);
}
