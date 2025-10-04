/**
 * Assessment Orchestrator
 * Coordinates all assessment modules and manages the assessment workflow
 */

import {
  MCPDirectoryAssessment,
  AssessmentConfiguration,
  AssessmentStatus,
  DEFAULT_ASSESSMENT_CONFIG,
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
import { PrivacyComplianceAssessor } from "./modules/PrivacyComplianceAssessor";
import { HumanInLoopAssessor } from "./modules/HumanInLoopAssessor";

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
    privacyPolicy?: unknown;
    dataRetention?: unknown;
    encryption?: unknown;
    dataTransfer?: unknown;
    consent?: unknown;
    coppaCompliance?: unknown;
    dataSubjectRights?: unknown;
    jurisdiction?: unknown;
    dataLocalization?: unknown;
  };
}

export class AssessmentOrchestrator {
  private config: AssessmentConfiguration;
  private startTime: number = 0;
  private totalTestsRun: number = 0;

  // Core assessors
  private functionalityAssessor: FunctionalityAssessor;
  private securityAssessor: SecurityAssessor;
  private documentationAssessor: DocumentationAssessor;
  private errorHandlingAssessor: ErrorHandlingAssessor;
  private usabilityAssessor: UsabilityAssessor;

  // Extended assessors
  private mcpSpecAssessor?: MCPSpecComplianceAssessor;
  private privacyAssessor?: PrivacyComplianceAssessor;
  private humanInLoopAssessor?: HumanInLoopAssessor;

  constructor(config: Partial<AssessmentConfiguration> = {}) {
    this.config = { ...DEFAULT_ASSESSMENT_CONFIG, ...config };

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
      if (this.config.assessmentCategories?.privacy) {
        this.privacyAssessor = new PrivacyComplianceAssessor(this.config);
      }
      if (this.config.assessmentCategories?.humanInLoop) {
        this.humanInLoopAssessor = new HumanInLoopAssessor(this.config);
      }
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
      if (this.privacyAssessor) {
        assessmentPromises.push(
          this.privacyAssessor
            .assess(context)
            .then((r) => (assessmentResults.privacy = r)),
        );
      }
      if (this.humanInLoopAssessor) {
        assessmentPromises.push(
          this.humanInLoopAssessor
            .assess(context)
            .then((r) => (assessmentResults.humanInLoop = r)),
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
      if (this.privacyAssessor) {
        assessmentResults.privacy = await this.privacyAssessor.assess(context);
      }
      if (this.humanInLoopAssessor) {
        assessmentResults.humanInLoop =
          await this.humanInLoopAssessor.assess(context);
      }
    }

    // Collect test counts from all assessors
    this.totalTestsRun = this.collectTotalTestCount(assessmentResults);

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

  private collectTotalTestCount(results: any): number {
    let total = 0;

    // Core assessments
    if (results.functionality?.toolResults) {
      total += results.functionality.toolResults.length;
    }
    if (results.security?.promptInjectionTests) {
      total += results.security.promptInjectionTests.length;
    }
    if (results.errorHandling?.metrics?.testDetails) {
      total += results.errorHandling.metrics.testDetails.length;
    }

    // Extended assessments

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
