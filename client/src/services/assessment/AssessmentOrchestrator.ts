/**
 * Assessment Orchestrator
 * Coordinates all assessment modules and manages the assessment workflow
 *
 * @public
 * @module AssessmentOrchestrator
 */

import {
  MCPDirectoryAssessment,
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  ManifestJsonSchema,
  ProgressCallback,
  ServerInfo,
  PackageJson,
} from "@/lib/assessmentTypes";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// Note: All assessor module imports now handled by registry/AssessorDefinitions.ts (Issue #91)

// Claude Code integration for intelligent analysis
import {
  ClaudeCodeBridge,
  ClaudeCodeBridgeConfig,
  FULL_CLAUDE_CODE_CONFIG,
} from "./lib/claudeCodeBridge";
import { TestDataGenerator } from "./TestDataGenerator";

// Structured logging
import { Logger, createLogger, DEFAULT_LOGGING_CONFIG } from "./lib/logger";

// Extracted helpers for testability
import {
  determineOverallStatus,
  generateSummary,
  generateRecommendations,
} from "./orchestratorHelpers";

// Registry pattern for assessor management (Issue #91)
import { AssessorRegistry, ASSESSOR_DEFINITIONS } from "./registry";

// Module scoring for dual-key output (Issue #124)
import { calculateModuleScore } from "@/lib/moduleScoring";

// Types for dual-key output
import type { DeveloperExperienceAssessment } from "@/lib/assessment/extendedTypes";

/**
 * MCP Resource interface for assessment context
 * @public
 */
export interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/**
 * MCP Resource Template interface for assessment context
 * @public
 */
export interface MCPResourceTemplate {
  uriTemplate: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/**
 * MCP Prompt interface for assessment context
 * @public
 */
export interface MCPPrompt {
  name: string;
  description?: string;
  arguments?: Array<{
    name: string;
    description?: string;
    required?: boolean;
  }>;
}

/**
 * MCP Server Capabilities interface
 * @public
 */
export interface MCPServerCapabilities {
  tools?: { listChanged?: boolean };
  resources?: { subscribe?: boolean; listChanged?: boolean };
  prompts?: { listChanged?: boolean };
  logging?: Record<string, unknown>;
  experimental?: Record<string, unknown>;
}

/**
 * Assessment context providing all inputs needed for MCP server assessment
 * @public
 */
export interface AssessmentContext {
  serverName: string;
  tools: Tool[];
  callTool: (
    name: string,
    params: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  readmeContent?: string;
  packageJson?: PackageJson;
  packageLock?: unknown;
  privacyPolicy?: unknown;
  config: AssessmentConfiguration;
  serverInfo?: ServerInfo;

  // Enhanced mode: Source code analysis (optional)
  // When provided, enables deeper analysis for AUP, prohibited libraries, portability
  sourceCodePath?: string;
  sourceCodeFiles?: Map<string, string>; // filename -> content

  // MCPB manifest validation (optional)
  manifestJson?: ManifestJsonSchema;
  manifestRaw?: string; // Raw manifest.json content for parsing validation

  // Progress callback for real-time test progress events
  // Called by assessors to emit batched progress during execution
  onProgress?: ProgressCallback;

  // MCP Resources and Prompts (for extended assessments)
  resources?: MCPResource[];
  resourceTemplates?: MCPResourceTemplate[];
  prompts?: MCPPrompt[];
  serverCapabilities?: MCPServerCapabilities;

  // Resource and prompt operations (optional - provided by CLI runner)
  readResource?: (uri: string) => Promise<string>;
  getPrompt?: (
    name: string,
    args: Record<string, string>,
  ) => Promise<{ messages: Array<{ role: string; content: string }> }>;

  // Transport configuration for security assessment
  transportConfig?: {
    type: "stdio" | "sse" | "streamable-http";
    url?: string;
    usesTLS?: boolean;
    oauthEnabled?: boolean;
  };

  // Tool refresh for temporal definition tracking (optional)
  // When provided, enables detection of tool definition mutations (rug pulls)
  listTools?: () => Promise<Tool[]>;
}

/**
 * Main orchestrator class for running MCP server assessments
 *
 * @public
 * @example
 * ```typescript
 * import { AssessmentOrchestrator, AssessmentContext } from '@bryan-thompson/inspector-assessment';
 *
 * const orchestrator = new AssessmentOrchestrator();
 * const result = await orchestrator.runFullAssessment(context);
 * ```
 */
export class AssessmentOrchestrator {
  private config: AssessmentConfiguration;
  private logger: Logger;
  private startTime: number = 0;
  private totalTestsRun: number = 0;

  // Claude Code Bridge for intelligent analysis
  private claudeBridge?: ClaudeCodeBridge;
  private claudeEnabled: boolean = false;

  // Registry for assessor management (Issue #91)
  // Delegates construction, test count aggregation, and Claude bridge wiring
  private registry: AssessorRegistry;

  constructor(config: Partial<AssessmentConfiguration> = {}) {
    this.config = { ...DEFAULT_ASSESSMENT_CONFIG, ...config };

    // Initialize logger
    this.logger = createLogger(
      "AssessmentOrchestrator",
      this.config.logging ?? DEFAULT_LOGGING_CONFIG,
    );

    // Emit deprecation warnings for deprecated config flags
    if (this.config.assessmentCategories?.mcpSpecCompliance !== undefined) {
      this.logger.warn(
        "Config flag 'mcpSpecCompliance' is deprecated. Use 'protocolCompliance' instead. " +
          "This flag will be removed in v2.0.0.",
        { flag: "mcpSpecCompliance", replacement: "protocolCompliance" },
      );
    }
    if (this.config.assessmentCategories?.protocolConformance !== undefined) {
      this.logger.warn(
        "Config flag 'protocolConformance' is deprecated. Use 'protocolCompliance' instead. " +
          "This flag will be removed in v2.0.0.",
        { flag: "protocolConformance", replacement: "protocolCompliance" },
      );
    }

    // Initialize Claude Code Bridge if enabled in config
    if (this.config.claudeCode?.enabled) {
      this.initializeClaudeBridge(this.config.claudeCode);
    }

    // Initialize registry and register all enabled assessors (Issue #91)
    // The registry handles:
    // - Conditional instantiation based on config flags
    // - Deprecated flag OR logic (e.g., protocolCompliance supports 3 flags)
    // - Custom setup (e.g., ToolAnnotationAssessor pattern config)
    // - Claude bridge wiring for supporting assessors
    this.registry = new AssessorRegistry(this.config);
    this.registry.registerAll(ASSESSOR_DEFINITIONS);

    // Wire up Claude bridge to registry (handles all supporting assessors)
    if (this.claudeBridge) {
      this.registry.setClaudeBridge(this.claudeBridge);
      TestDataGenerator.setClaudeBridge(this.claudeBridge);
    }

    // Set logger for TestDataGenerator diagnostic output
    TestDataGenerator.setLogger(this.logger);
  }

  /**
   * Initialize Claude Code Bridge for intelligent analysis
   * This enables semantic AUP violation analysis, behavior inference, and intelligent test generation
   */
  private initializeClaudeBridge(bridgeConfig: ClaudeCodeBridgeConfig): void {
    try {
      this.claudeBridge = new ClaudeCodeBridge(bridgeConfig, this.logger);
      this.claudeEnabled = true;
      this.logger.info("Claude Code Bridge initialized", {
        features: bridgeConfig.features,
      });
    } catch (error) {
      this.logger.warn("Failed to initialize Claude Code Bridge", {
        error: String(error),
      });
      this.claudeEnabled = false;
    }
  }

  /**
   * Enable Claude Code integration programmatically
   * Call this method to enable Claude features after construction
   * @public
   */
  enableClaudeCode(config?: Partial<ClaudeCodeBridgeConfig>): void {
    const bridgeConfig: ClaudeCodeBridgeConfig = {
      ...FULL_CLAUDE_CODE_CONFIG,
      ...config,
      enabled: true,
    };

    this.initializeClaudeBridge(bridgeConfig);

    // Wire up to all supporting assessors via registry
    if (this.claudeBridge) {
      this.registry.setClaudeBridge(this.claudeBridge);
      TestDataGenerator.setClaudeBridge(this.claudeBridge);
    }
  }

  /**
   * Check if Claude Code integration is enabled and available
   * @public
   */
  isClaudeEnabled(): boolean {
    return this.claudeEnabled && this.claudeBridge !== undefined;
  }

  /**
   * Get Claude Code Bridge for external access
   * @public
   */
  getClaudeBridge(): ClaudeCodeBridge | undefined {
    return this.claudeBridge;
  }

  /**
   * Run a complete assessment on an MCP server
   * @public
   */
  async runFullAssessment(
    context: AssessmentContext,
  ): Promise<MCPDirectoryAssessment> {
    this.startTime = Date.now();
    this.totalTestsRun = 0;
    this.registry.resetAllTestCounts();

    // Execute all assessors via registry (Issue #91)
    // Registry handles:
    // - Phase-ordered execution (Phase 0/PRE always runs first and sequentially)
    // - Parallel vs sequential based on config.parallelTesting
    // - JSONL events (module_started, module_progress)
    // - Test count tracking
    const assessmentResults = await this.registry.executeAll(context);

    // Integrate temporal findings into security.vulnerabilities for unified view
    if (
      assessmentResults.temporal?.rugPullsDetected &&
      assessmentResults.temporal.rugPullsDetected > 0 &&
      assessmentResults.security
    ) {
      for (const detail of assessmentResults.temporal.details.filter(
        (d: { vulnerable: boolean }) => d.vulnerable,
      )) {
        assessmentResults.security.vulnerabilities.push(
          `RUG_PULL_TEMPORAL: ${detail.tool} - Tool behavior changed after invocation ${detail.firstDeviationAt}. Requires immediate manual review.`,
        );
      }
    }

    // Issue #124: Dual-key output for v2.0.0 transition
    // Output BOTH old and new keys to maintain backward compatibility
    // Old keys (documentation, usability, mcpSpecCompliance) will be removed in v2.0.0

    // developerExperience (new) = documentation + usability (deprecated)
    if (assessmentResults.documentation && assessmentResults.usability) {
      const docScore =
        calculateModuleScore(assessmentResults.documentation) ?? 50;
      const usabilityScore =
        calculateModuleScore(assessmentResults.usability) ?? 50;
      const combinedStatus = determineOverallStatus({
        documentation: assessmentResults.documentation,
        usability: assessmentResults.usability,
      });
      assessmentResults.developerExperience = {
        documentation: assessmentResults.documentation,
        usability: assessmentResults.usability,
        status: combinedStatus,
        score: Math.round((docScore + usabilityScore) / 2),
      } as DeveloperExperienceAssessment;

      // Emit deprecation warning for old keys
      this.logger.warn(
        "Output keys 'documentation' and 'usability' are deprecated. " +
          "Use 'developerExperience' instead. These keys will be removed in v2.0.0.",
        {
          deprecated: ["documentation", "usability"],
          replacement: "developerExperience",
        },
      );
    }

    // protocolCompliance (new) = mcpSpecCompliance (deprecated)
    if (assessmentResults.mcpSpecCompliance) {
      assessmentResults.protocolCompliance =
        assessmentResults.mcpSpecCompliance;

      // Emit deprecation warning for old key
      this.logger.warn(
        "Output key 'mcpSpecCompliance' is deprecated. " +
          "Use 'protocolCompliance' instead. This key will be removed in v2.0.0.",
        {
          deprecated: ["mcpSpecCompliance"],
          replacement: "protocolCompliance",
        },
      );
    }

    // Collect test counts from all assessors
    this.totalTestsRun = this.collectTotalTestCount();

    // Determine overall status
    const overallStatus = determineOverallStatus(assessmentResults);

    // Generate summary and recommendations
    const summary = generateSummary(assessmentResults);
    const recommendations = generateRecommendations(assessmentResults);

    const executionTime = Date.now() - this.startTime;

    // Type assertion needed because Partial<MCPDirectoryAssessment> has optional required fields
    // When modules are skipped via --skip-modules, not all fields will be present
    return {
      serverName: context.serverName,
      assessmentDate: new Date().toISOString(),
      assessorVersion: "2.0.0",
      ...assessmentResults,
      overallStatus,
      summary,
      recommendations,
      executionTime,
      totalTestsRun: this.totalTestsRun,
      mcpProtocolVersion: this.config.mcpProtocolVersion,
      assessmentMetadata: {
        // Source code is available if we have a path OR loaded source files
        sourceCodeAvailable:
          !!context.sourceCodePath || (context.sourceCodeFiles?.size ?? 0) > 0,
        // Use explicit transport type, or infer from available context
        transportType:
          context.transportConfig?.type ??
          (context.transportConfig?.url ? "streamable-http" : undefined),
      },
    } as MCPDirectoryAssessment;
  }

  /**
   * Legacy assess method for backward compatibility
   * @public
   * @deprecated Use runFullAssessment() with AssessmentContext instead
   */
  async assess(
    serverName: string,
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    serverInfo?: ServerInfo,
    readmeContent?: string,
    packageJson?: PackageJson,
  ): Promise<MCPDirectoryAssessment> {
    const context: AssessmentContext = {
      serverName,
      tools,
      callTool,
      readmeContent,
      packageJson,
      serverInfo,
      config: this.config,
    };

    return this.runFullAssessment(context);
  }

  private collectTotalTestCount(): number {
    // Delegate to registry for centralized test count aggregation (Issue #91)
    const total = this.registry.getTotalTestCount();
    this.logger.debug("Total test count", { total });
    return total;
  }

  /**
   * Get assessment configuration
   * @public
   */
  getConfig(): AssessmentConfiguration {
    return this.config;
  }

  /**
   * Update assessment configuration
   * @public
   */
  updateConfig(config: Partial<AssessmentConfiguration>): void {
    this.config = { ...this.config, ...config };
  }
}
