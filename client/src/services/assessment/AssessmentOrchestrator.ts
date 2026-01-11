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
} from "@/lib/assessmentTypes";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// Core assessment modules
import { FunctionalityAssessor } from "./modules/FunctionalityAssessor";
import { SecurityAssessor } from "./modules/SecurityAssessor";
import { DocumentationAssessor } from "./modules/DocumentationAssessor";
import { ErrorHandlingAssessor } from "./modules/ErrorHandlingAssessor";
import { UsabilityAssessor } from "./modules/UsabilityAssessor";

// Extended assessment modules - unified protocol compliance
import { ProtocolComplianceAssessor } from "./modules/ProtocolComplianceAssessor";

// New MCP Directory Compliance Gap assessors
import { AUPComplianceAssessor } from "./modules/AUPComplianceAssessor";
import { ToolAnnotationAssessor } from "./modules/ToolAnnotationAssessor";
import { ProhibitedLibrariesAssessor } from "./modules/ProhibitedLibrariesAssessor";
import { ManifestValidationAssessor } from "./modules/ManifestValidationAssessor";
import { PortabilityAssessor } from "./modules/PortabilityAssessor";
import { ExternalAPIScannerAssessor } from "./modules/ExternalAPIScannerAssessor";
import { TemporalAssessor } from "./modules/TemporalAssessor";
import { AuthenticationAssessor } from "./modules/AuthenticationAssessor";

// New capability assessors
import { ResourceAssessor } from "./modules/ResourceAssessor";
import { PromptAssessor } from "./modules/PromptAssessor";
import { CrossCapabilitySecurityAssessor } from "./modules/CrossCapabilitySecurityAssessor";

// Code quality assessors
import { FileModularizationAssessor } from "./modules/FileModularizationAssessor";

// Official MCP conformance testing
import { ConformanceAssessor } from "./modules/ConformanceAssessor";

// Note: ProtocolConformanceAssessor merged into ProtocolComplianceAssessor (v1.25.2)

// Pattern configuration for tool annotation assessment now handled by registry (Issue #91)
// See AssessorDefinitions.ts customSetup for ToolAnnotationAssessor

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
  emitModuleStartedEvent,
  emitModuleProgress,
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
  packageJson?: unknown;
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

  // ============================================================================
  // Private getters for backward compatibility with tests
  // Tests access these via type assertions: (orchestrator as any).assessorName
  // These delegate to the registry to maintain a single source of truth
  // ============================================================================

  private get functionalityAssessor(): FunctionalityAssessor | undefined {
    return this.registry.getAssessor<FunctionalityAssessor>("functionality");
  }

  private get securityAssessor(): SecurityAssessor | undefined {
    return this.registry.getAssessor<SecurityAssessor>("security");
  }

  private get documentationAssessor(): DocumentationAssessor | undefined {
    return this.registry.getAssessor<DocumentationAssessor>("documentation");
  }

  private get errorHandlingAssessor(): ErrorHandlingAssessor | undefined {
    return this.registry.getAssessor<ErrorHandlingAssessor>("errorHandling");
  }

  private get usabilityAssessor(): UsabilityAssessor | undefined {
    return this.registry.getAssessor<UsabilityAssessor>("usability");
  }

  private get protocolComplianceAssessor():
    | ProtocolComplianceAssessor
    | undefined {
    return this.registry.getAssessor<ProtocolComplianceAssessor>(
      "protocolCompliance",
    );
  }

  private get aupComplianceAssessor(): AUPComplianceAssessor | undefined {
    return this.registry.getAssessor<AUPComplianceAssessor>("aupCompliance");
  }

  private get toolAnnotationAssessor(): ToolAnnotationAssessor | undefined {
    return this.registry.getAssessor<ToolAnnotationAssessor>("toolAnnotations");
  }

  private get prohibitedLibrariesAssessor():
    | ProhibitedLibrariesAssessor
    | undefined {
    return this.registry.getAssessor<ProhibitedLibrariesAssessor>(
      "prohibitedLibraries",
    );
  }

  private get manifestValidationAssessor():
    | ManifestValidationAssessor
    | undefined {
    return this.registry.getAssessor<ManifestValidationAssessor>(
      "manifestValidation",
    );
  }

  private get portabilityAssessor(): PortabilityAssessor | undefined {
    return this.registry.getAssessor<PortabilityAssessor>("portability");
  }

  private get externalAPIScannerAssessor():
    | ExternalAPIScannerAssessor
    | undefined {
    return this.registry.getAssessor<ExternalAPIScannerAssessor>(
      "externalAPIScanner",
    );
  }

  private get temporalAssessor(): TemporalAssessor | undefined {
    return this.registry.getAssessor<TemporalAssessor>("temporal");
  }

  private get authenticationAssessor(): AuthenticationAssessor | undefined {
    return this.registry.getAssessor<AuthenticationAssessor>("authentication");
  }

  private get resourceAssessor(): ResourceAssessor | undefined {
    return this.registry.getAssessor<ResourceAssessor>("resources");
  }

  private get promptAssessor(): PromptAssessor | undefined {
    return this.registry.getAssessor<PromptAssessor>("prompts");
  }

  private get crossCapabilityAssessor():
    | CrossCapabilitySecurityAssessor
    | undefined {
    return this.registry.getAssessor<CrossCapabilitySecurityAssessor>(
      "crossCapability",
    );
  }

  private get fileModularizationAssessor():
    | FileModularizationAssessor
    | undefined {
    return this.registry.getAssessor<FileModularizationAssessor>(
      "fileModularization",
    );
  }

  private get conformanceAssessor(): ConformanceAssessor | undefined {
    return this.registry.getAssessor<ConformanceAssessor>("conformance");
  }

  // Note: protocolConformanceAssessor merged into protocolComplianceAssessor (v1.25.2)

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
   * Get the count of tools that will actually be tested based on selectedToolsForTesting config.
   * Used for accurate progress estimation in emitModuleStartedEvent calls.
   */
  private getToolCountForTesting(tools: Tool[]): number {
    if (this.config.selectedToolsForTesting !== undefined) {
      const selectedNames = new Set(this.config.selectedToolsForTesting);
      return tools.filter((tool) => selectedNames.has(tool.name)).length;
    }
    return tools.length;
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
   * Reset test counts for all assessors
   */
  private resetAllTestCounts(): void {
    this.functionalityAssessor?.resetTestCount();
    this.securityAssessor?.resetTestCount();
    this.documentationAssessor?.resetTestCount();
    this.errorHandlingAssessor?.resetTestCount();
    this.usabilityAssessor?.resetTestCount();
    if (this.protocolComplianceAssessor) {
      this.protocolComplianceAssessor.resetTestCount();
    }
    // Reset new assessors
    if (this.aupComplianceAssessor) {
      this.aupComplianceAssessor.resetTestCount();
    }
    if (this.toolAnnotationAssessor) {
      this.toolAnnotationAssessor.resetTestCount();
    }
    if (this.prohibitedLibrariesAssessor) {
      this.prohibitedLibrariesAssessor.resetTestCount();
    }
    if (this.manifestValidationAssessor) {
      this.manifestValidationAssessor.resetTestCount();
    }
    if (this.portabilityAssessor) {
      this.portabilityAssessor.resetTestCount();
    }
    if (this.authenticationAssessor) {
      this.authenticationAssessor.resetTestCount();
    }
    // Reset new capability assessors
    if (this.resourceAssessor) {
      this.resourceAssessor.resetTestCount();
    }
    if (this.promptAssessor) {
      this.promptAssessor.resetTestCount();
    }
    if (this.crossCapabilityAssessor) {
      this.crossCapabilityAssessor.resetTestCount();
    }
    if (this.fileModularizationAssessor) {
      this.fileModularizationAssessor.resetTestCount();
    }
    // Reset official conformance assessor
    if (this.conformanceAssessor) {
      this.conformanceAssessor.resetTestCount();
    }
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
    this.resetAllTestCounts();

    // Run assessments in parallel if enabled
    const assessmentPromises: Promise<unknown>[] = [];
    const assessmentResults: Partial<MCPDirectoryAssessment> = {};

    // PHASE 0: Temporal Assessment (ALWAYS runs first, before parallel/sequential phases)
    // This ensures temporal captures clean baseline before other modules trigger rug pulls
    if (this.temporalAssessor) {
      const toolCount = this.getToolCountForTesting(context.tools);
      const invocationsPerTool = this.config.temporalInvocations ?? 25;
      emitModuleStartedEvent(
        "Temporal",
        toolCount * invocationsPerTool,
        toolCount,
      );
      assessmentResults.temporal = await this.temporalAssessor.assess(context);
      emitModuleProgress(
        "Temporal",
        assessmentResults.temporal.status,
        assessmentResults.temporal,
        this.temporalAssessor.getTestCount(),
      );
    }

    if (this.config.parallelTesting) {
      // Calculate estimates for module_started events
      const toolCount = this.getToolCountForTesting(context.tools);
      const securityPatterns = this.config.securityPatternsToTest || 17;

      // Core assessments - only emit and run if not skipped
      if (this.functionalityAssessor) {
        emitModuleStartedEvent("Functionality", toolCount * 10, toolCount);
        assessmentPromises.push(
          this.functionalityAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Functionality",
              r.status,
              r,
              this.functionalityAssessor!.getTestCount(),
            );
            return (assessmentResults.functionality = r);
          }),
        );
      }
      if (this.securityAssessor) {
        emitModuleStartedEvent(
          "Security",
          securityPatterns * toolCount,
          toolCount,
        );
        assessmentPromises.push(
          this.securityAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Security",
              r.status,
              r,
              this.securityAssessor!.getTestCount(),
            );
            return (assessmentResults.security = r);
          }),
        );
      }
      if (this.documentationAssessor) {
        emitModuleStartedEvent("Documentation", 5, toolCount);
        assessmentPromises.push(
          this.documentationAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Documentation",
              r.status,
              r,
              this.documentationAssessor!.getTestCount(),
            );
            return (assessmentResults.documentation = r);
          }),
        );
      }
      if (this.errorHandlingAssessor) {
        emitModuleStartedEvent("Error Handling", toolCount * 5, toolCount);
        assessmentPromises.push(
          this.errorHandlingAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Error Handling",
              r.status,
              r,
              this.errorHandlingAssessor!.getTestCount(),
            );
            return (assessmentResults.errorHandling = r);
          }),
        );
      }
      if (this.usabilityAssessor) {
        emitModuleStartedEvent("Usability", 10, toolCount);
        assessmentPromises.push(
          this.usabilityAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Usability",
              r.status,
              r,
              this.usabilityAssessor!.getTestCount(),
            );
            return (assessmentResults.usability = r);
          }),
        );
      }

      // Extended assessments - unified protocol compliance
      if (this.protocolComplianceAssessor) {
        emitModuleStartedEvent("Protocol Compliance", 10, toolCount);
        assessmentPromises.push(
          this.protocolComplianceAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Protocol Compliance",
              r.status,
              r,
              this.protocolComplianceAssessor!.getTestCount(),
            );
            return (assessmentResults.mcpSpecCompliance = r);
          }),
        );
      }

      // New MCP Directory Compliance Gap assessments
      if (this.aupComplianceAssessor) {
        emitModuleStartedEvent("AUP", 20, toolCount);
        assessmentPromises.push(
          this.aupComplianceAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "AUP",
              r.status,
              r,
              this.aupComplianceAssessor!.getTestCount(),
            );
            return (assessmentResults.aupCompliance = r);
          }),
        );
      }
      if (this.toolAnnotationAssessor) {
        emitModuleStartedEvent("Annotations", toolCount, toolCount);
        assessmentPromises.push(
          this.toolAnnotationAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Annotations",
              r.status,
              r,
              this.toolAnnotationAssessor!.getTestCount(),
            );
            return (assessmentResults.toolAnnotations = r);
          }),
        );
      }
      if (this.prohibitedLibrariesAssessor) {
        emitModuleStartedEvent("Libraries", 5, toolCount);
        assessmentPromises.push(
          this.prohibitedLibrariesAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Libraries",
              r.status,
              r,
              this.prohibitedLibrariesAssessor!.getTestCount(),
            );
            return (assessmentResults.prohibitedLibraries = r);
          }),
        );
      }
      if (this.manifestValidationAssessor) {
        emitModuleStartedEvent("Manifest", 10, toolCount);
        assessmentPromises.push(
          this.manifestValidationAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Manifest",
              r.status,
              r,
              this.manifestValidationAssessor!.getTestCount(),
            );
            return (assessmentResults.manifestValidation = r);
          }),
        );
      }
      if (this.portabilityAssessor) {
        emitModuleStartedEvent("Portability", 10, toolCount);
        assessmentPromises.push(
          this.portabilityAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Portability",
              r.status,
              r,
              this.portabilityAssessor!.getTestCount(),
            );
            return (assessmentResults.portability = r);
          }),
        );
      }
      if (this.externalAPIScannerAssessor) {
        emitModuleStartedEvent("External APIs", 10, toolCount);
        assessmentPromises.push(
          this.externalAPIScannerAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "External APIs",
              r.status,
              r,
              this.externalAPIScannerAssessor!.getTestCount(),
            );
            return (assessmentResults.externalAPIScanner = r);
          }),
        );
      }
      if (this.authenticationAssessor) {
        const sourceFileCount = context.sourceCodeFiles?.size || 0;
        emitModuleStartedEvent(
          "Authentication",
          sourceFileCount,
          sourceFileCount,
        );
        assessmentPromises.push(
          this.authenticationAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Authentication",
              r.status,
              r,
              this.authenticationAssessor!.getTestCount(),
            );
            return (assessmentResults.authentication = r);
          }),
        );
      }
      // NOTE: Temporal runs in PHASE 0 above, not in parallel with other modules

      // New capability assessors
      if (this.resourceAssessor) {
        const resourceCount =
          (context.resources?.length || 0) +
          (context.resourceTemplates?.length || 0);
        emitModuleStartedEvent("Resources", resourceCount * 5, resourceCount);
        assessmentPromises.push(
          this.resourceAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Resources",
              r.status,
              r,
              this.resourceAssessor!.getTestCount(),
            );
            return (assessmentResults.resources = r);
          }),
        );
      }
      if (this.promptAssessor) {
        const promptCount = context.prompts?.length || 0;
        emitModuleStartedEvent("Prompts", promptCount * 10, promptCount);
        assessmentPromises.push(
          this.promptAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Prompts",
              r.status,
              r,
              this.promptAssessor!.getTestCount(),
            );
            return (assessmentResults.prompts = r);
          }),
        );
      }
      if (this.crossCapabilityAssessor) {
        const capabilityCount =
          toolCount +
          (context.resources?.length || 0) +
          (context.prompts?.length || 0);
        emitModuleStartedEvent(
          "Cross-Capability",
          capabilityCount * 3,
          capabilityCount,
        );
        assessmentPromises.push(
          this.crossCapabilityAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Cross-Capability",
              r.status,
              r,
              this.crossCapabilityAssessor!.getTestCount(),
            );
            return (assessmentResults.crossCapability = r);
          }),
        );
      }
      if (this.fileModularizationAssessor) {
        const sourceFileCount = context.sourceCodeFiles?.size || 0;
        emitModuleStartedEvent(
          "File Modularization",
          sourceFileCount,
          sourceFileCount,
        );
        assessmentPromises.push(
          this.fileModularizationAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "File Modularization",
              r.status,
              r,
              this.fileModularizationAssessor!.getTestCount(),
            );
            return (assessmentResults.fileModularization = r);
          }),
        );
      }

      // Official MCP conformance testing (opt-in, requires HTTP/SSE transport)
      if (this.conformanceAssessor) {
        // Conformance tests ~7 server scenarios
        emitModuleStartedEvent("Conformance", 7, toolCount);
        assessmentPromises.push(
          this.conformanceAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Conformance",
              r.status,
              r,
              this.conformanceAssessor!.getTestCount(),
            );
            return (assessmentResults.conformance = r);
          }),
        );
      }

      // Note: Protocol Conformance now handled by unified ProtocolComplianceAssessor above

      await Promise.all(assessmentPromises);
    } else {
      // Sequential execution with module_started events
      const toolCount = this.getToolCountForTesting(context.tools);
      const securityPatterns = this.config.securityPatternsToTest || 17;

      // NOTE: Temporal runs in PHASE 0 above, before sequential/parallel phases

      // Core assessments - only emit and run if not skipped
      if (this.functionalityAssessor) {
        // Functionality: ~10 scenarios per tool
        emitModuleStartedEvent("Functionality", toolCount * 10, toolCount);
        assessmentResults.functionality =
          await this.functionalityAssessor.assess(context);
        emitModuleProgress(
          "Functionality",
          assessmentResults.functionality.status,
          assessmentResults.functionality,
          this.functionalityAssessor.getTestCount(),
        );
      }

      if (this.securityAssessor) {
        // Security: patterns × tools
        emitModuleStartedEvent(
          "Security",
          securityPatterns * toolCount,
          toolCount,
        );
        assessmentResults.security =
          await this.securityAssessor.assess(context);
        emitModuleProgress(
          "Security",
          assessmentResults.security.status,
          assessmentResults.security,
          this.securityAssessor.getTestCount(),
        );
      }

      if (this.documentationAssessor) {
        // Documentation: ~5 static tests
        emitModuleStartedEvent("Documentation", 5, toolCount);
        assessmentResults.documentation =
          await this.documentationAssessor.assess(context);
        emitModuleProgress(
          "Documentation",
          assessmentResults.documentation.status,
          assessmentResults.documentation,
          this.documentationAssessor.getTestCount(),
        );
      }

      if (this.errorHandlingAssessor) {
        // Error Handling: ~5 tests per tool
        emitModuleStartedEvent("Error Handling", toolCount * 5, toolCount);
        assessmentResults.errorHandling =
          await this.errorHandlingAssessor.assess(context);
        emitModuleProgress(
          "Error Handling",
          assessmentResults.errorHandling.status,
          assessmentResults.errorHandling,
          this.errorHandlingAssessor.getTestCount(),
        );
      }

      if (this.usabilityAssessor) {
        // Usability: ~10 static tests
        emitModuleStartedEvent("Usability", 10, toolCount);
        assessmentResults.usability =
          await this.usabilityAssessor.assess(context);
        emitModuleProgress(
          "Usability",
          assessmentResults.usability.status,
          assessmentResults.usability,
          this.usabilityAssessor.getTestCount(),
        );
      }

      if (this.protocolComplianceAssessor) {
        emitModuleStartedEvent("Protocol Compliance", 10, toolCount);
        assessmentResults.mcpSpecCompliance =
          await this.protocolComplianceAssessor.assess(context);
        emitModuleProgress(
          "Protocol Compliance",
          assessmentResults.mcpSpecCompliance.status,
          assessmentResults.mcpSpecCompliance,
          this.protocolComplianceAssessor.getTestCount(),
        );
      }

      // New MCP Directory Compliance Gap assessments (sequential)
      if (this.aupComplianceAssessor) {
        emitModuleStartedEvent("AUP", 20, toolCount);
        assessmentResults.aupCompliance =
          await this.aupComplianceAssessor.assess(context);
        emitModuleProgress(
          "AUP",
          assessmentResults.aupCompliance.status,
          assessmentResults.aupCompliance,
          this.aupComplianceAssessor.getTestCount(),
        );
      }
      if (this.toolAnnotationAssessor) {
        emitModuleStartedEvent("Annotations", toolCount, toolCount);
        assessmentResults.toolAnnotations =
          await this.toolAnnotationAssessor.assess(context);
        emitModuleProgress(
          "Annotations",
          assessmentResults.toolAnnotations.status,
          assessmentResults.toolAnnotations,
          this.toolAnnotationAssessor.getTestCount(),
        );
      }
      if (this.prohibitedLibrariesAssessor) {
        emitModuleStartedEvent("Libraries", 5, toolCount);
        assessmentResults.prohibitedLibraries =
          await this.prohibitedLibrariesAssessor.assess(context);
        emitModuleProgress(
          "Libraries",
          assessmentResults.prohibitedLibraries.status,
          assessmentResults.prohibitedLibraries,
          this.prohibitedLibrariesAssessor.getTestCount(),
        );
      }
      if (this.manifestValidationAssessor) {
        emitModuleStartedEvent("Manifest", 10, toolCount);
        assessmentResults.manifestValidation =
          await this.manifestValidationAssessor.assess(context);
        emitModuleProgress(
          "Manifest",
          assessmentResults.manifestValidation.status,
          assessmentResults.manifestValidation,
          this.manifestValidationAssessor.getTestCount(),
        );
      }
      if (this.portabilityAssessor) {
        emitModuleStartedEvent("Portability", 10, toolCount);
        assessmentResults.portability =
          await this.portabilityAssessor.assess(context);
        emitModuleProgress(
          "Portability",
          assessmentResults.portability.status,
          assessmentResults.portability,
          this.portabilityAssessor.getTestCount(),
        );
      }
      if (this.externalAPIScannerAssessor) {
        emitModuleStartedEvent("External APIs", 10, toolCount);
        assessmentResults.externalAPIScanner =
          await this.externalAPIScannerAssessor.assess(context);
        emitModuleProgress(
          "External APIs",
          assessmentResults.externalAPIScanner.status,
          assessmentResults.externalAPIScanner,
          this.externalAPIScannerAssessor.getTestCount(),
        );
      }
      if (this.authenticationAssessor) {
        const sourceFileCount = context.sourceCodeFiles?.size || 0;
        emitModuleStartedEvent(
          "Authentication",
          sourceFileCount,
          sourceFileCount,
        );
        assessmentResults.authentication =
          await this.authenticationAssessor.assess(context);
        emitModuleProgress(
          "Authentication",
          assessmentResults.authentication.status,
          assessmentResults.authentication,
          this.authenticationAssessor.getTestCount(),
        );
      }

      // New capability assessors (sequential)
      if (this.resourceAssessor) {
        const resourceCount =
          (context.resources?.length || 0) +
          (context.resourceTemplates?.length || 0);
        emitModuleStartedEvent("Resources", resourceCount * 5, resourceCount);
        assessmentResults.resources =
          await this.resourceAssessor.assess(context);
        emitModuleProgress(
          "Resources",
          assessmentResults.resources.status,
          assessmentResults.resources,
          this.resourceAssessor.getTestCount(),
        );
      }
      if (this.promptAssessor) {
        const promptCount = context.prompts?.length || 0;
        emitModuleStartedEvent("Prompts", promptCount * 10, promptCount);
        assessmentResults.prompts = await this.promptAssessor.assess(context);
        emitModuleProgress(
          "Prompts",
          assessmentResults.prompts.status,
          assessmentResults.prompts,
          this.promptAssessor.getTestCount(),
        );
      }
      if (this.crossCapabilityAssessor) {
        const capabilityCount =
          toolCount +
          (context.resources?.length || 0) +
          (context.prompts?.length || 0);
        emitModuleStartedEvent(
          "Cross-Capability",
          capabilityCount * 3,
          capabilityCount,
        );
        assessmentResults.crossCapability =
          await this.crossCapabilityAssessor.assess(context);
        emitModuleProgress(
          "Cross-Capability",
          assessmentResults.crossCapability.status,
          assessmentResults.crossCapability,
          this.crossCapabilityAssessor.getTestCount(),
        );
      }
      if (this.fileModularizationAssessor) {
        const sourceFileCount = context.sourceCodeFiles?.size || 0;
        emitModuleStartedEvent(
          "File Modularization",
          sourceFileCount,
          sourceFileCount,
        );
        assessmentResults.fileModularization =
          await this.fileModularizationAssessor.assess(context);
        emitModuleProgress(
          "File Modularization",
          assessmentResults.fileModularization.status,
          assessmentResults.fileModularization,
          this.fileModularizationAssessor.getTestCount(),
        );
      }

      // Official MCP conformance testing (sequential, opt-in)
      if (this.conformanceAssessor) {
        emitModuleStartedEvent("Conformance", 7, toolCount);
        assessmentResults.conformance =
          await this.conformanceAssessor.assess(context);
        emitModuleProgress(
          "Conformance",
          assessmentResults.conformance.status,
          assessmentResults.conformance,
          this.conformanceAssessor.getTestCount(),
        );
      }

      // Note: Protocol Conformance now handled by unified ProtocolComplianceAssessor above
    }

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
    packageJson?: Record<string, unknown>,
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
    let total = 0;

    // Get actual test counts from assessors (optional for --skip-modules support)
    const functionalityCount = this.functionalityAssessor?.getTestCount() || 0;
    const securityCount = this.securityAssessor?.getTestCount() || 0;
    const documentationCount = this.documentationAssessor?.getTestCount() || 0;
    const errorHandlingCount = this.errorHandlingAssessor?.getTestCount() || 0;
    const usabilityCount = this.usabilityAssessor?.getTestCount() || 0;
    const mcpSpecCount = this.protocolComplianceAssessor?.getTestCount() || 0;

    // New assessor counts
    const aupCount = this.aupComplianceAssessor?.getTestCount() || 0;
    const annotationCount = this.toolAnnotationAssessor?.getTestCount() || 0;
    const librariesCount =
      this.prohibitedLibrariesAssessor?.getTestCount() || 0;
    const manifestCount = this.manifestValidationAssessor?.getTestCount() || 0;
    const portabilityCount = this.portabilityAssessor?.getTestCount() || 0;
    const authenticationCount =
      this.authenticationAssessor?.getTestCount() || 0;
    const externalAPICount =
      this.externalAPIScannerAssessor?.getTestCount() || 0;
    const temporalCount = this.temporalAssessor?.getTestCount() || 0;

    // New capability assessor counts
    const resourcesCount = this.resourceAssessor?.getTestCount() || 0;
    const promptsCount = this.promptAssessor?.getTestCount() || 0;
    const crossCapabilityCount =
      this.crossCapabilityAssessor?.getTestCount() || 0;

    // Code quality assessor counts
    const fileModularizationCount =
      this.fileModularizationAssessor?.getTestCount() || 0;

    // Official MCP conformance test count
    const conformanceCount = this.conformanceAssessor?.getTestCount() || 0;

    // Note: Protocol conformance now included in mcpSpecCount (unified ProtocolComplianceAssessor)

    this.logger.debug("Test counts by assessor", {
      functionality: functionalityCount,
      security: securityCount,
      documentation: documentationCount,
      errorHandling: errorHandlingCount,
      usability: usabilityCount,
      mcpSpec: mcpSpecCount,
      aupCompliance: aupCount,
      toolAnnotations: annotationCount,
      prohibitedLibraries: librariesCount,
      manifestValidation: manifestCount,
      portability: portabilityCount,
      authentication: authenticationCount,
      externalAPIScanner: externalAPICount,
      temporal: temporalCount,
      resources: resourcesCount,
      prompts: promptsCount,
      crossCapability: crossCapabilityCount,
      fileModularization: fileModularizationCount,
      conformance: conformanceCount,
      // Note: protocolConformance now included in mcpSpec (unified)
    });

    total =
      functionalityCount +
      securityCount +
      documentationCount +
      errorHandlingCount +
      usabilityCount +
      mcpSpecCount +
      aupCount +
      annotationCount +
      librariesCount +
      manifestCount +
      portabilityCount +
      authenticationCount +
      externalAPICount +
      temporalCount +
      resourcesCount +
      promptsCount +
      crossCapabilityCount +
      fileModularizationCount +
      conformanceCount;
    // Note: protocolConformance now included in mcpSpecCount (unified)

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
