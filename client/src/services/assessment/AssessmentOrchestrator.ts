/**
 * Assessment Orchestrator
 * Coordinates all assessment modules and manages the assessment workflow
 */

import {
  MCPDirectoryAssessment,
  AssessmentConfiguration,
  AssessmentStatus,
  DEFAULT_ASSESSMENT_CONFIG,
  ManifestJsonSchema,
  ProgressCallback,
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

// Extended assessment modules
import { MCPSpecComplianceAssessor } from "./modules/MCPSpecComplianceAssessor";

// New MCP Directory Compliance Gap assessors
import { AUPComplianceAssessor } from "./modules/AUPComplianceAssessor";
import { ToolAnnotationAssessor } from "./modules/ToolAnnotationAssessor";
import { ProhibitedLibrariesAssessor } from "./modules/ProhibitedLibrariesAssessor";
import { ManifestValidationAssessor } from "./modules/ManifestValidationAssessor";
import { PortabilityAssessor } from "./modules/PortabilityAssessor";
import { ExternalAPIScannerAssessor } from "./modules/ExternalAPIScannerAssessor";
import { TemporalAssessor } from "./modules/TemporalAssessor";

// New capability assessors
import { ResourceAssessor } from "./modules/ResourceAssessor";
import { PromptAssessor } from "./modules/PromptAssessor";
import { CrossCapabilitySecurityAssessor } from "./modules/CrossCapabilitySecurityAssessor";

// Pattern configuration for tool annotation assessment
import {
  loadPatternConfig,
  compilePatterns,
} from "./config/annotationPatterns";

// Claude Code integration for intelligent analysis
import {
  ClaudeCodeBridge,
  ClaudeCodeBridgeConfig,
  FULL_CLAUDE_CODE_CONFIG,
} from "./lib/claudeCodeBridge";
import { TestDataGenerator } from "./TestDataGenerator";

// Import score calculation helpers from shared module
import {
  calculateModuleScore,
  normalizeModuleKey,
  INSPECTOR_VERSION,
} from "@/lib/moduleScoring";

// Track module start times for duration calculation
const moduleStartTimes: Map<string, number> = new Map();

/**
 * Emit module_started event and track start time for duration calculation.
 * Emits JSONL to stderr with version field for consistent event structure.
 */
function emitModuleStartedEvent(
  moduleName: string,
  estimatedTests: number,
  toolCount: number,
): void {
  const moduleKey = normalizeModuleKey(moduleName);
  moduleStartTimes.set(moduleKey, Date.now());

  // Emit JSONL to stderr with version field
  console.error(
    JSON.stringify({
      event: "module_started",
      module: moduleKey,
      estimatedTests,
      toolCount,
      version: INSPECTOR_VERSION,
    }),
  );
}

/**
 * Emit module_complete event with score and duration.
 * Uses shared score calculator for consistent scoring logic.
 * For AUP module, includes enriched violation data for Claude analysis.
 */

function emitModuleProgress(
  moduleName: string,
  status: string,
  result: any,
  testsRun: number = 0,
): void {
  const moduleKey = normalizeModuleKey(moduleName);

  // Calculate score using shared helper
  const score = calculateModuleScore(result);

  // Calculate duration from module start time
  const startTime = moduleStartTimes.get(moduleKey);
  const duration = startTime ? Date.now() - startTime : 0;
  moduleStartTimes.delete(moduleKey);

  // Build base event
  const event: Record<string, unknown> = {
    event: "module_complete",
    module: moduleKey,
    status,
    score,
    testsRun,
    duration,
    version: INSPECTOR_VERSION,
  };

  // Add AUP enrichment when module is AUP
  if (moduleKey === "aup" && result) {
    const aupEnrichment = buildAUPEnrichment(result);
    Object.assign(event, aupEnrichment);
  }

  // Emit JSONL to stderr with version field
  console.error(JSON.stringify(event));
}

/**
 * Build AUP enrichment data from an AUP compliance assessment result.
 * Samples violations prioritizing by severity (CRITICAL > HIGH > MEDIUM).
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildAUPEnrichment(aupResult: any, maxSamples: number = 10) {
  const violations = aupResult.violations || [];

  // Calculate metrics
  const metrics = {
    total: violations.length,
    critical: violations.filter(
      (v: { severity: string }) => v.severity === "CRITICAL",
    ).length,
    high: violations.filter((v: { severity: string }) => v.severity === "HIGH")
      .length,
    medium: violations.filter(
      (v: { severity: string }) => v.severity === "MEDIUM",
    ).length,
    byCategory: {} as Record<string, number>,
  };

  // Count by category
  for (const v of violations) {
    metrics.byCategory[v.category] = (metrics.byCategory[v.category] || 0) + 1;
  }

  // Sample violations prioritizing by severity
  const sampled: Array<{
    category: string;
    categoryName: string;
    severity: string;
    matchedText: string;
    location: string;
    confidence: string;
  }> = [];
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM"];

  for (const severity of severityOrder) {
    if (sampled.length >= maxSamples) break;
    const bySeverity = violations.filter(
      (v: { severity: string }) => v.severity === severity,
    );
    for (const v of bySeverity) {
      if (sampled.length >= maxSamples) break;
      sampled.push({
        category: v.category,
        categoryName: v.categoryName,
        severity: v.severity,
        matchedText: v.matchedText,
        location: v.location,
        confidence: v.confidence,
      });
    }
  }

  // Build sampling note
  let samplingNote = "";
  if (violations.length === 0) {
    samplingNote = "No violations detected.";
  } else if (violations.length <= maxSamples) {
    samplingNote = `All ${violations.length} violation(s) included.`;
  } else {
    samplingNote = `Sampled ${sampled.length} of ${violations.length} violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).`;
  }

  return {
    violationsSample: sampled,
    samplingNote,
    violationMetrics: metrics,
    scannedLocations: aupResult.scannedLocations || {
      toolNames: false,
      toolDescriptions: false,
      readme: false,
      sourceCode: false,
    },
    highRiskDomains: (aupResult.highRiskDomains || []).slice(0, 10),
  };
}

/**
 * MCP Resource interface for assessment context
 */
export interface MCPResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/**
 * MCP Resource Template interface for assessment context
 */
export interface MCPResourceTemplate {
  uriTemplate: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/**
 * MCP Prompt interface for assessment context
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
 */
export interface MCPServerCapabilities {
  tools?: { listChanged?: boolean };
  resources?: { subscribe?: boolean; listChanged?: boolean };
  prompts?: { listChanged?: boolean };
  logging?: Record<string, unknown>;
  experimental?: Record<string, unknown>;
}

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
  serverInfo?: {
    name: string;
    version?: string;
    metadata?: unknown;
  };

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

export class AssessmentOrchestrator {
  private config: AssessmentConfiguration;
  private startTime: number = 0;
  private totalTestsRun: number = 0;

  // Claude Code Bridge for intelligent analysis
  private claudeBridge?: ClaudeCodeBridge;
  private claudeEnabled: boolean = false;

  // Core assessors
  private functionalityAssessor: FunctionalityAssessor;
  private securityAssessor: SecurityAssessor;
  private documentationAssessor: DocumentationAssessor;
  private errorHandlingAssessor: ErrorHandlingAssessor;
  private usabilityAssessor: UsabilityAssessor;

  // Extended assessors
  private mcpSpecAssessor?: MCPSpecComplianceAssessor;

  // New MCP Directory Compliance Gap assessors
  private aupComplianceAssessor?: AUPComplianceAssessor;
  private toolAnnotationAssessor?: ToolAnnotationAssessor;
  private prohibitedLibrariesAssessor?: ProhibitedLibrariesAssessor;
  private manifestValidationAssessor?: ManifestValidationAssessor;
  private portabilityAssessor?: PortabilityAssessor;
  private externalAPIScannerAssessor?: ExternalAPIScannerAssessor;
  private temporalAssessor?: TemporalAssessor;

  // New capability assessors
  private resourceAssessor?: ResourceAssessor;
  private promptAssessor?: PromptAssessor;
  private crossCapabilityAssessor?: CrossCapabilitySecurityAssessor;

  constructor(config: Partial<AssessmentConfiguration> = {}) {
    this.config = { ...DEFAULT_ASSESSMENT_CONFIG, ...config };

    // Initialize Claude Code Bridge if enabled in config
    if (this.config.claudeCode?.enabled) {
      this.initializeClaudeBridge(this.config.claudeCode);
    }

    // Initialize core assessors
    this.functionalityAssessor = new FunctionalityAssessor(this.config);
    this.securityAssessor = new SecurityAssessor(this.config);
    this.documentationAssessor = new DocumentationAssessor(this.config);
    this.errorHandlingAssessor = new ErrorHandlingAssessor(this.config);
    this.usabilityAssessor = new UsabilityAssessor(this.config);

    // Initialize extended assessors if enabled
    if (this.config.enableExtendedAssessment) {
      if (this.config.assessmentCategories?.mcpSpecCompliance) {
        this.mcpSpecAssessor = new MCPSpecComplianceAssessor(this.config);
      }

      // Initialize new MCP Directory Compliance Gap assessors
      if (this.config.assessmentCategories?.aupCompliance) {
        this.aupComplianceAssessor = new AUPComplianceAssessor(this.config);
        // Wire up Claude bridge for semantic analysis
        if (this.claudeBridge) {
          this.aupComplianceAssessor.setClaudeBridge(this.claudeBridge);
        }
      }
      if (this.config.assessmentCategories?.toolAnnotations) {
        this.toolAnnotationAssessor = new ToolAnnotationAssessor(this.config);
        // Wire up Claude bridge for behavior inference
        if (this.claudeBridge) {
          this.toolAnnotationAssessor.setClaudeBridge(this.claudeBridge);
        }
        // Load custom pattern configuration if provided
        if (this.config.patternConfigPath) {
          const patternConfig = loadPatternConfig(
            this.config.patternConfigPath,
          );
          const compiledPatterns = compilePatterns(patternConfig);
          this.toolAnnotationAssessor.setPatterns(compiledPatterns);
        }
      }
      if (this.config.assessmentCategories?.prohibitedLibraries) {
        this.prohibitedLibrariesAssessor = new ProhibitedLibrariesAssessor(
          this.config,
        );
      }
      if (this.config.assessmentCategories?.manifestValidation) {
        this.manifestValidationAssessor = new ManifestValidationAssessor(
          this.config,
        );
      }
      if (this.config.assessmentCategories?.portability) {
        this.portabilityAssessor = new PortabilityAssessor(this.config);
      }
      if (this.config.assessmentCategories?.externalAPIScanner) {
        this.externalAPIScannerAssessor = new ExternalAPIScannerAssessor(
          this.config,
        );
      }
      if (this.config.assessmentCategories?.temporal) {
        this.temporalAssessor = new TemporalAssessor(this.config);
      }

      // Initialize new capability assessors
      if (this.config.assessmentCategories?.resources) {
        this.resourceAssessor = new ResourceAssessor(this.config);
      }
      if (this.config.assessmentCategories?.prompts) {
        this.promptAssessor = new PromptAssessor(this.config);
      }
      if (this.config.assessmentCategories?.crossCapability) {
        this.crossCapabilityAssessor = new CrossCapabilitySecurityAssessor(
          this.config,
        );
      }
    }

    // Wire up Claude bridge to TestDataGenerator for intelligent test generation
    if (this.claudeBridge) {
      TestDataGenerator.setClaudeBridge(this.claudeBridge);
    }
  }

  /**
   * Initialize Claude Code Bridge for intelligent analysis
   * This enables semantic AUP violation analysis, behavior inference, and intelligent test generation
   */
  private initializeClaudeBridge(bridgeConfig: ClaudeCodeBridgeConfig): void {
    try {
      this.claudeBridge = new ClaudeCodeBridge(bridgeConfig);
      this.claudeEnabled = true;
      console.log(
        "[AssessmentOrchestrator] Claude Code Bridge initialized with features:",
        bridgeConfig.features,
      );
    } catch (error) {
      console.warn(
        "[AssessmentOrchestrator] Failed to initialize Claude Code Bridge:",
        error,
      );
      this.claudeEnabled = false;
    }
  }

  /**
   * Enable Claude Code integration programmatically
   * Call this method to enable Claude features after construction
   */
  enableClaudeCode(config?: Partial<ClaudeCodeBridgeConfig>): void {
    const bridgeConfig: ClaudeCodeBridgeConfig = {
      ...FULL_CLAUDE_CODE_CONFIG,
      ...config,
      enabled: true,
    };

    this.initializeClaudeBridge(bridgeConfig);

    // Wire up to existing assessors
    if (this.claudeBridge) {
      if (this.aupComplianceAssessor) {
        this.aupComplianceAssessor.setClaudeBridge(this.claudeBridge);
      }
      if (this.toolAnnotationAssessor) {
        this.toolAnnotationAssessor.setClaudeBridge(this.claudeBridge);
      }
      TestDataGenerator.setClaudeBridge(this.claudeBridge);
    }
  }

  /**
   * Check if Claude Code integration is enabled and available
   */
  isClaudeEnabled(): boolean {
    return this.claudeEnabled && this.claudeBridge !== undefined;
  }

  /**
   * Get Claude Code Bridge for external access
   */
  getClaudeBridge(): ClaudeCodeBridge | undefined {
    return this.claudeBridge;
  }

  /**
   * Reset test counts for all assessors
   */
  private resetAllTestCounts(): void {
    this.functionalityAssessor.resetTestCount();
    this.securityAssessor.resetTestCount();
    this.documentationAssessor.resetTestCount();
    this.errorHandlingAssessor.resetTestCount();
    this.usabilityAssessor.resetTestCount();
    if (this.mcpSpecAssessor) {
      this.mcpSpecAssessor.resetTestCount();
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
  }

  /**
   * Run a complete assessment on an MCP server
   */
  async runFullAssessment(
    context: AssessmentContext,
  ): Promise<MCPDirectoryAssessment> {
    this.startTime = Date.now();
    this.totalTestsRun = 0;
    this.resetAllTestCounts();

    // Run assessments in parallel if enabled
    const assessmentPromises: Promise<any>[] = [];
    const assessmentResults: any = {};

    if (this.config.parallelTesting) {
      // Calculate estimates for module_started events
      const toolCount = context.tools.length;
      const securityPatterns = this.config.securityPatternsToTest || 17;

      // Emit all module_started events before launching parallel assessments
      emitModuleStartedEvent("Functionality", toolCount * 10, toolCount);
      emitModuleStartedEvent(
        "Security",
        securityPatterns * toolCount,
        toolCount,
      );
      emitModuleStartedEvent("Documentation", 5, toolCount);
      emitModuleStartedEvent("Error Handling", toolCount * 5, toolCount);
      emitModuleStartedEvent("Usability", 10, toolCount);

      // Core assessments
      assessmentPromises.push(
        this.functionalityAssessor.assess(context).then((r) => {
          emitModuleProgress(
            "Functionality",
            r.status,
            r,
            this.functionalityAssessor.getTestCount(),
          );
          return (assessmentResults.functionality = r);
        }),
        this.securityAssessor.assess(context).then((r) => {
          emitModuleProgress(
            "Security",
            r.status,
            r,
            this.securityAssessor.getTestCount(),
          );
          return (assessmentResults.security = r);
        }),
        this.documentationAssessor.assess(context).then((r) => {
          emitModuleProgress(
            "Documentation",
            r.status,
            r,
            this.documentationAssessor.getTestCount(),
          );
          return (assessmentResults.documentation = r);
        }),
        this.errorHandlingAssessor.assess(context).then((r) => {
          emitModuleProgress(
            "Error Handling",
            r.status,
            r,
            this.errorHandlingAssessor.getTestCount(),
          );
          return (assessmentResults.errorHandling = r);
        }),
        this.usabilityAssessor.assess(context).then((r) => {
          emitModuleProgress(
            "Usability",
            r.status,
            r,
            this.usabilityAssessor.getTestCount(),
          );
          return (assessmentResults.usability = r);
        }),
      );

      // Extended assessments
      if (this.mcpSpecAssessor) {
        emitModuleStartedEvent("MCP Spec", 10, toolCount);
        assessmentPromises.push(
          this.mcpSpecAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "MCP Spec",
              r.status,
              r,
              this.mcpSpecAssessor!.getTestCount(),
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
      if (this.temporalAssessor) {
        const invocationsPerTool = this.config.temporalInvocations ?? 25;
        emitModuleStartedEvent(
          "Temporal",
          toolCount * invocationsPerTool,
          toolCount,
        );
        assessmentPromises.push(
          this.temporalAssessor.assess(context).then((r) => {
            emitModuleProgress(
              "Temporal",
              r.status,
              r,
              this.temporalAssessor!.getTestCount(),
            );
            return (assessmentResults.temporal = r);
          }),
        );
      }

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

      await Promise.all(assessmentPromises);
    } else {
      // Sequential execution with module_started events
      const toolCount = context.tools.length;
      const securityPatterns = this.config.securityPatternsToTest || 17;

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

      // Security: patterns × tools
      emitModuleStartedEvent(
        "Security",
        securityPatterns * toolCount,
        toolCount,
      );
      assessmentResults.security = await this.securityAssessor.assess(context);
      emitModuleProgress(
        "Security",
        assessmentResults.security.status,
        assessmentResults.security,
        this.securityAssessor.getTestCount(),
      );

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

      if (this.mcpSpecAssessor) {
        emitModuleStartedEvent("MCP Spec", 10, toolCount);
        assessmentResults.mcpSpecCompliance =
          await this.mcpSpecAssessor.assess(context);
        emitModuleProgress(
          "MCP Spec",
          assessmentResults.mcpSpecCompliance.status,
          assessmentResults.mcpSpecCompliance,
          this.mcpSpecAssessor.getTestCount(),
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
      if (this.temporalAssessor) {
        const invocationsPerTool = this.config.temporalInvocations ?? 25;
        emitModuleStartedEvent(
          "Temporal",
          toolCount * invocationsPerTool,
          toolCount,
        );
        assessmentResults.temporal =
          await this.temporalAssessor.assess(context);
        emitModuleProgress(
          "Temporal",
          assessmentResults.temporal.status,
          assessmentResults.temporal,
          this.temporalAssessor.getTestCount(),
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

    // Collect test counts from all assessors
    this.totalTestsRun = this.collectTotalTestCount();

    // Determine overall status
    const overallStatus = this.determineOverallStatus(assessmentResults);

    // Generate summary and recommendations
    const summary = this.generateSummary(assessmentResults);
    const recommendations = this.generateRecommendations(assessmentResults);

    const executionTime = Date.now() - this.startTime;

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
    };
  }

  /**
   * Legacy assess method for backward compatibility
   */
  async assess(
    serverName: string,
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    serverInfo?: any,
    readmeContent?: string,
    packageJson?: any,
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

    // Get actual test counts from assessors
    const functionalityCount = this.functionalityAssessor.getTestCount();
    const securityCount = this.securityAssessor.getTestCount();
    const documentationCount = this.documentationAssessor.getTestCount();
    const errorHandlingCount = this.errorHandlingAssessor.getTestCount();
    const usabilityCount = this.usabilityAssessor.getTestCount();
    const mcpSpecCount = this.mcpSpecAssessor?.getTestCount() || 0;

    // New assessor counts
    const aupCount = this.aupComplianceAssessor?.getTestCount() || 0;
    const annotationCount = this.toolAnnotationAssessor?.getTestCount() || 0;
    const librariesCount =
      this.prohibitedLibrariesAssessor?.getTestCount() || 0;
    const manifestCount = this.manifestValidationAssessor?.getTestCount() || 0;
    const portabilityCount = this.portabilityAssessor?.getTestCount() || 0;
    const externalAPICount =
      this.externalAPIScannerAssessor?.getTestCount() || 0;
    const temporalCount = this.temporalAssessor?.getTestCount() || 0;

    // New capability assessor counts
    const resourcesCount = this.resourceAssessor?.getTestCount() || 0;
    const promptsCount = this.promptAssessor?.getTestCount() || 0;
    const crossCapabilityCount =
      this.crossCapabilityAssessor?.getTestCount() || 0;

    console.log("[AssessmentOrchestrator] Test counts by assessor:", {
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
      externalAPIScanner: externalAPICount,
      temporal: temporalCount,
      resources: resourcesCount,
      prompts: promptsCount,
      crossCapability: crossCapabilityCount,
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
      externalAPICount +
      temporalCount +
      resourcesCount +
      promptsCount +
      crossCapabilityCount;

    console.log("[AssessmentOrchestrator] Total test count:", total);

    return total;
  }

  private determineOverallStatus(results: any): AssessmentStatus {
    const statuses: AssessmentStatus[] = [];

    // Collect all statuses
    Object.values(results).forEach((assessment: any) => {
      if (assessment?.status) {
        statuses.push(assessment.status);
      }
    });

    // If any critical category fails, overall fails
    if (statuses.includes("FAIL")) return "FAIL";

    // If any category needs more info, overall needs more info
    if (statuses.includes("NEED_MORE_INFO")) return "NEED_MORE_INFO";

    // All must pass for overall pass
    return "PASS";
  }

  private generateSummary(results: any): string {
    const parts: string[] = [];
    const totalCategories = Object.keys(results).length;
    const passedCategories = Object.values(results).filter(
      (r: any) => r?.status === "PASS",
    ).length;

    parts.push(
      `Assessment complete: ${passedCategories}/${totalCategories} categories passed.`,
    );

    // Add key findings
    if (results.security?.vulnerabilities?.length > 0) {
      parts.push(
        `Found ${results.security.vulnerabilities.length} security vulnerabilities.`,
      );
    }

    if (results.functionality?.brokenTools?.length > 0) {
      parts.push(
        `${results.functionality.brokenTools.length} tools are not functioning correctly.`,
      );
    }

    // New assessor findings
    if (results.aupCompliance?.violations?.length > 0) {
      const criticalCount = results.aupCompliance.violations.filter(
        (v: any) => v.severity === "CRITICAL",
      ).length;
      if (criticalCount > 0) {
        parts.push(`CRITICAL: ${criticalCount} AUP violation(s) detected.`);
      } else {
        parts.push(
          `${results.aupCompliance.violations.length} AUP item(s) flagged for review.`,
        );
      }
    }

    if (results.toolAnnotations?.missingAnnotationsCount > 0) {
      parts.push(
        `${results.toolAnnotations.missingAnnotationsCount} tools missing annotations.`,
      );
    }

    if (results.prohibitedLibraries?.matches?.length > 0) {
      const blockingCount = results.prohibitedLibraries.matches.filter(
        (m: any) => m.severity === "BLOCKING",
      ).length;
      if (blockingCount > 0) {
        parts.push(
          `BLOCKING: ${blockingCount} prohibited library/libraries detected.`,
        );
      }
    }

    if (results.portability?.usesBundleRoot) {
      parts.push("Uses ${BUNDLE_ROOT} anti-pattern.");
    }

    return parts.join(" ");
  }

  private generateRecommendations(results: any): string[] {
    const recommendations: string[] = [];

    // Aggregate recommendations from all assessments
    Object.values(results).forEach((assessment: any) => {
      if (assessment?.recommendations) {
        recommendations.push(...assessment.recommendations);
      }
    });

    // De-duplicate and prioritize
    return [...new Set(recommendations)].slice(0, 10);
  }

  /**
   * Get assessment configuration
   */
  getConfig(): AssessmentConfiguration {
    return this.config;
  }

  /**
   * Update assessment configuration
   */
  updateConfig(config: Partial<AssessmentConfiguration>): void {
    this.config = { ...this.config, ...config };
  }
}
