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

// Claude Code integration for intelligent analysis
import {
  ClaudeCodeBridge,
  ClaudeCodeBridgeConfig,
  FULL_CLAUDE_CODE_CONFIG,
} from "./lib/claudeCodeBridge";
import { TestDataGenerator } from "./TestDataGenerator";

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
      // Core assessments
      assessmentPromises.push(
        this.functionalityAssessor
          .assess(context)
          .then((r) => (assessmentResults.functionality = r)),
        this.securityAssessor
          .assess(context)
          .then((r) => (assessmentResults.security = r)),
        this.documentationAssessor
          .assess(context)
          .then((r) => (assessmentResults.documentation = r)),
        this.errorHandlingAssessor
          .assess(context)
          .then((r) => (assessmentResults.errorHandling = r)),
        this.usabilityAssessor
          .assess(context)
          .then((r) => (assessmentResults.usability = r)),
      );

      // Extended assessments
      if (this.mcpSpecAssessor) {
        assessmentPromises.push(
          this.mcpSpecAssessor
            .assess(context)
            .then((r) => (assessmentResults.mcpSpecCompliance = r)),
        );
      }

      // New MCP Directory Compliance Gap assessments
      if (this.aupComplianceAssessor) {
        assessmentPromises.push(
          this.aupComplianceAssessor
            .assess(context)
            .then((r) => (assessmentResults.aupCompliance = r)),
        );
      }
      if (this.toolAnnotationAssessor) {
        assessmentPromises.push(
          this.toolAnnotationAssessor
            .assess(context)
            .then((r) => (assessmentResults.toolAnnotations = r)),
        );
      }
      if (this.prohibitedLibrariesAssessor) {
        assessmentPromises.push(
          this.prohibitedLibrariesAssessor
            .assess(context)
            .then((r) => (assessmentResults.prohibitedLibraries = r)),
        );
      }
      if (this.manifestValidationAssessor) {
        assessmentPromises.push(
          this.manifestValidationAssessor
            .assess(context)
            .then((r) => (assessmentResults.manifestValidation = r)),
        );
      }
      if (this.portabilityAssessor) {
        assessmentPromises.push(
          this.portabilityAssessor
            .assess(context)
            .then((r) => (assessmentResults.portability = r)),
        );
      }

      await Promise.all(assessmentPromises);
    } else {
      // Sequential execution
      assessmentResults.functionality =
        await this.functionalityAssessor.assess(context);
      assessmentResults.security = await this.securityAssessor.assess(context);
      assessmentResults.documentation =
        await this.documentationAssessor.assess(context);
      assessmentResults.errorHandling =
        await this.errorHandlingAssessor.assess(context);
      assessmentResults.usability =
        await this.usabilityAssessor.assess(context);

      if (this.mcpSpecAssessor) {
        assessmentResults.mcpSpecCompliance =
          await this.mcpSpecAssessor.assess(context);
      }

      // New MCP Directory Compliance Gap assessments (sequential)
      if (this.aupComplianceAssessor) {
        assessmentResults.aupCompliance =
          await this.aupComplianceAssessor.assess(context);
      }
      if (this.toolAnnotationAssessor) {
        assessmentResults.toolAnnotations =
          await this.toolAnnotationAssessor.assess(context);
      }
      if (this.prohibitedLibrariesAssessor) {
        assessmentResults.prohibitedLibraries =
          await this.prohibitedLibrariesAssessor.assess(context);
      }
      if (this.manifestValidationAssessor) {
        assessmentResults.manifestValidation =
          await this.manifestValidationAssessor.assess(context);
      }
      if (this.portabilityAssessor) {
        assessmentResults.portability =
          await this.portabilityAssessor.assess(context);
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
      portabilityCount;

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
