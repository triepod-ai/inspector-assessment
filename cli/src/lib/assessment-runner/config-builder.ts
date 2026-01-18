/**
 * Configuration Building
 *
 * Transforms CLI options into AssessmentConfiguration.
 *
 * @module cli/lib/assessment-runner/config-builder
 */

import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  getAllModulesConfig,
  LogLevel,
} from "../../../../client/lib/lib/assessmentTypes.js";
import { FULL_CLAUDE_CODE_CONFIG } from "../../../../client/lib/services/assessment/lib/claudeCodeBridge.js";
import { loadPerformanceConfig } from "../../../../client/lib/services/assessment/config/performanceConfig.js";
import { safeParseAssessmentConfig } from "../../../../client/lib/lib/assessment/configSchemas.js";

import {
  getProfileModules,
  resolveModuleNames,
  modulesToLegacyConfig,
} from "../../profiles.js";

import type { AssessmentOptions } from "../cli-parser.js";

/**
 * Build assessment configuration from CLI options
 *
 * @param options - CLI assessment options
 * @returns Assessment configuration
 */
export function buildConfig(
  options: AssessmentOptions,
): AssessmentConfiguration {
  const config: AssessmentConfiguration = {
    ...DEFAULT_ASSESSMENT_CONFIG,
    enableExtendedAssessment: options.fullAssessment !== false,
    parallelTesting: true,
    testTimeout: 30000,
    enableSourceCodeAnalysis: Boolean(options.sourceCodePath),
  };

  if (options.fullAssessment !== false) {
    // Priority: --profile > --only-modules > --skip-modules > default (all)
    if (options.profile) {
      // Use profile-based module selection
      const profileModules = getProfileModules(options.profile, {
        hasSourceCode: Boolean(options.sourceCodePath),
        skipTemporal: options.skipTemporal,
      });

      // Convert new-style module list to legacy config format
      // (until orchestrator is updated to use new naming)
      config.assessmentCategories = modulesToLegacyConfig(
        profileModules,
      ) as AssessmentConfiguration["assessmentCategories"];
    } else {
      // Issue #190: Deprecation warning for v2.0 default change
      // Only warn if user didn't specify --only-modules or --skip-modules
      if (!options.onlyModules?.length && !options.skipModules?.length) {
        console.warn(
          "⚠️  Warning: Running without --profile will default to --profile security in v2.0.\n" +
            "   To preserve current behavior (all modules), use --profile full or --profile dev.\n" +
            "   See docs/CLI_ASSESSMENT_GUIDE.md for profile details.",
        );
      }

      // Derive module config from ASSESSMENT_CATEGORY_METADATA (single source of truth)
      const allModules = getAllModulesConfig({
        sourceCodePath: Boolean(options.sourceCodePath),
        skipTemporal: options.skipTemporal,
      });

      // Apply --only-modules filter (whitelist mode)
      if (options.onlyModules?.length) {
        // Resolve any deprecated module names
        const resolved = resolveModuleNames(options.onlyModules);
        for (const key of Object.keys(allModules)) {
          // Disable all modules except those in the whitelist
          allModules[key] = resolved.includes(key);
        }
      }

      // Apply --skip-modules filter (blacklist mode)
      if (options.skipModules?.length) {
        // Resolve any deprecated module names
        const resolved = resolveModuleNames(options.skipModules);
        for (const module of resolved) {
          if (module in allModules) {
            allModules[module] = false;
          }
        }
      }

      config.assessmentCategories =
        allModules as AssessmentConfiguration["assessmentCategories"];
    }
  }

  // Temporal/rug pull detection configuration
  if (options.temporalInvocations) {
    config.temporalInvocations = options.temporalInvocations;
  }

  // Official MCP conformance testing (opt-in via --conformance flag)
  // Requires HTTP/SSE transport with serverUrl - STDIO transport will skip gracefully
  if (options.conformanceEnabled) {
    config.assessmentCategories = {
      ...config.assessmentCategories,
      conformance: true,
    };
    console.log("🔍 Official MCP conformance testing enabled");
  }

  if (options.claudeEnabled) {
    // Check for HTTP transport via --claude-http flag or environment variables
    const useHttpTransport =
      options.claudeHttp || process.env.INSPECTOR_CLAUDE === "true";
    const auditorUrl =
      options.mcpAuditorUrl ||
      process.env.INSPECTOR_MCP_AUDITOR_URL ||
      "http://localhost:8085";

    config.claudeCode = {
      enabled: true,
      timeout: FULL_CLAUDE_CODE_CONFIG.timeout || 60000,
      maxRetries: FULL_CLAUDE_CODE_CONFIG.maxRetries || 2,
      // Use HTTP transport when --claude-http flag or INSPECTOR_CLAUDE env is set
      ...(useHttpTransport && {
        transport: "http" as const,
        httpConfig: {
          baseUrl: auditorUrl,
        },
      }),
      features: {
        intelligentTestGeneration: true,
        aupSemanticAnalysis: true,
        annotationInference: true,
        documentationQuality: true,
      },
    };

    if (useHttpTransport) {
      console.log(`🔗 Claude Bridge HTTP transport: ${auditorUrl}`);
    }
  }

  // Pass custom annotation pattern config path
  if (options.patternConfigPath) {
    config.patternConfigPath = options.patternConfigPath;
  }

  // Load custom performance config if provided (Issue #37)
  // Note: Currently, modules use DEFAULT_PERFORMANCE_CONFIG directly.
  // This validates the config file but doesn't override runtime values yet.
  // Future enhancement: Pass performanceConfig through AssessmentContext.
  if (options.performanceConfigPath) {
    try {
      const performanceConfig = loadPerformanceConfig(
        options.performanceConfigPath,
      );
      console.log(
        `📊 Performance config loaded from: ${options.performanceConfigPath}`,
      );
      console.log(
        `   Batch interval: ${performanceConfig.batchFlushIntervalMs}ms, ` +
          `Security batch: ${performanceConfig.securityBatchSize}, ` +
          `Functionality batch: ${performanceConfig.functionalityBatchSize}`,
      );
      // TODO: Wire performanceConfig through AssessmentContext to modules
    } catch (error) {
      console.error(
        `❌ Failed to load performance config: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw error;
    }
  }

  // Logging configuration
  // Precedence: CLI flags > LOG_LEVEL env var > default (info)
  const envLogLevel = process.env.LOG_LEVEL as LogLevel | undefined;
  const logLevel = options.logLevel ?? envLogLevel ?? "info";
  config.logging = { level: logLevel };

  // Config version validation (Issue #107)
  // Warn if config is missing version field - will be required in v2.0.0
  if (!config.configVersion) {
    console.warn(
      "⚠️  Config missing configVersion field. " +
        "This will be required in v2.0.0. " +
        "See docs/DEPRECATION_GUIDE.md for migration info.",
    );
  }

  // Validate built config with Zod schema (Issue #84)
  // Warning only - maintains backward compatibility with existing configs
  const validation = safeParseAssessmentConfig(config);
  if (!validation.success) {
    const issues = validation.error.issues
      .map((i) => `${i.path.join(".")}: ${i.message}`)
      .join(", ");
    console.warn(`⚠️  Config validation warning: ${issues}`);
  }

  return config;
}
