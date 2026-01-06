/**
 * MCP Directory Assessment Service
 * Handles systematic testing of MCP servers for directory review
 */

import {
  MCPDirectoryAssessment,
  FunctionalityAssessment,
  SecurityAssessment,
  DocumentationAssessment,
  ErrorHandlingAssessment,
  UsabilityAssessment,
  UsabilityMetrics,
  AssessmentStatus,
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  CodeExample,
  MCPSpecComplianceAssessment,
  // PrivacyComplianceAssessment, // Removed - out of scope
} from "@/lib/assessmentTypes";
import { MCPSpecComplianceAssessor } from "./assessment/modules/MCPSpecComplianceAssessor";
import { ErrorHandlingAssessor } from "./assessment/modules/ErrorHandlingAssessor";
import { FunctionalityAssessor } from "./assessment/modules/FunctionalityAssessor";
import { SecurityAssessor } from "./assessment/modules/SecurityAssessor";
// import { SupplyChainAssessor } from "./assessment/modules/SupplyChainAssessor";
// import { PrivacyComplianceAssessor } from "./assessment/modules/PrivacyComplianceAssessor";
import { AssessmentContext } from "./assessment/AssessmentOrchestrator";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

export class MCPAssessmentService {
  private config: AssessmentConfiguration;
  private startTime: number = 0;
  private totalTestsRun: number = 0;

  constructor(config: Partial<AssessmentConfiguration> = {}) {
    this.config = { ...DEFAULT_ASSESSMENT_CONFIG, ...config };
  }

  /**
   * Run a complete assessment on an MCP server
   */
  async runFullAssessment(
    serverName: string,
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    readmeContent?: string,
  ): Promise<MCPDirectoryAssessment> {
    this.startTime = Date.now();
    this.totalTestsRun = 0;

    // Create a context for assessors
    const context: AssessmentContext = {
      serverName,
      tools,
      callTool,
      readmeContent,
      config: this.config,
      // Note: serverInfo is not available in this legacy service
      // The new AssessmentOrchestrator should be used for proper protocol version detection
      serverInfo: undefined,
      packageJson: undefined,
      packageLock: undefined,
      privacyPolicy: undefined,
    };

    // Run assessment categories based on config (default: all enabled)
    const categories = this.config.assessmentCategories;

    // Functionality assessment (always run unless explicitly disabled)
    const functionalityAssessor = new FunctionalityAssessor(this.config);
    const functionality =
      categories?.functionality !== false
        ? await functionalityAssessor.assess(context)
        : this.createEmptyFunctionalityResult();

    // Security assessment (skip if disabled for performance)
    const securityAssessor = new SecurityAssessor(this.config);
    const security =
      categories?.security !== false
        ? await securityAssessor.assess(context)
        : this.createEmptySecurityResult();

    // Documentation assessment
    const documentation =
      categories?.documentation !== false
        ? this.assessDocumentation(readmeContent || "", tools)
        : this.createEmptyDocumentationResult();

    // Error handling assessment (skip if disabled for performance)
    const errorHandlingAssessor = new ErrorHandlingAssessor(this.config);
    const errorHandling =
      categories?.errorHandling !== false
        ? await errorHandlingAssessor.assess(context)
        : this.createEmptyErrorHandlingResult();

    // Usability assessment
    const usability =
      categories?.usability !== false
        ? this.assessUsability(tools)
        : this.createEmptyUsabilityResult();

    // Run extended assessment if enabled
    let mcpSpecCompliance: MCPSpecComplianceAssessment | undefined;
    let mcpAssessor: MCPSpecComplianceAssessor | undefined;
    // let privacy: PrivacyComplianceAssessment | undefined; // Removed - out of scope

    if (this.config.enableExtendedAssessment) {
      // Run MCP Spec Compliance assessment
      mcpAssessor = new MCPSpecComplianceAssessor(this.config);
      mcpSpecCompliance = await mcpAssessor.assess(context);

      // TODO: Fix SupplyChainAssessor to return proper types
      // For now, leave them undefined to prevent blank screen issues
      // const supplyChainAssessor = new SupplyChainAssessor(this.config);
      // supplyChain = await supplyChainAssessor.assess(context);

      // Privacy compliance assessment removed - out of scope
    }

    // Determine overall status
    const overallStatus = this.determineOverallStatus(
      functionality.status,
      security.status,
      documentation.status,
      errorHandling.status,
      usability.status,
    );

    // Generate summary and recommendations
    const summary = this.generateSummary(
      functionality,
      security,
      documentation,
      errorHandling,
      usability,
    );

    const recommendations = this.generateRecommendations(
      functionality,
      security,
      documentation,
      errorHandling,
      usability,
    );

    const executionTime = Date.now() - this.startTime;

    // Collect test counts from all assessors
    this.totalTestsRun =
      functionalityAssessor.getTestCount() +
      securityAssessor.getTestCount() +
      errorHandlingAssessor.getTestCount() +
      (mcpSpecCompliance ? mcpAssessor?.getTestCount() || 0 : 0);

    console.log("[MCPAssessmentService] Test counts:", {
      functionality: functionalityAssessor.getTestCount(),
      security: securityAssessor.getTestCount(),
      errorHandling: errorHandlingAssessor.getTestCount(),
      mcpSpec: mcpSpecCompliance ? mcpAssessor?.getTestCount() || 0 : 0,
      total: this.totalTestsRun,
    });

    return {
      serverName,
      assessmentDate: new Date().toISOString(),
      assessorVersion: "1.0.0",
      functionality,
      security,
      documentation,
      errorHandling,
      usability,
      mcpSpecCompliance,
      // privacy, // Removed - out of scope
      overallStatus,
      summary,
      recommendations,
      executionTime,
      totalTestsRun: this.totalTestsRun,
    };
  }

  // Removed deprecated methods:
  // - generateTestParameters() - replaced by TestDataGenerator
  // - generateInvalidTestParameters() - no longer needed
  // - generateMultipleInvalidTestCases() - no longer needed
  // - generateStandardErrorCodeTestCases() - no longer needed

  /**
   * Assess documentation quality
   */
  private assessDocumentation(
    readmeContent: string,
    tools?: Tool[],
  ): DocumentationAssessment {
    // Extract code examples
    const extractedExamples = this.extractCodeExamples(readmeContent);

    // Extract installation instructions
    const installInstructions = this.extractSection(readmeContent, [
      "install",
      "setup",
      "getting started",
    ]);

    // Extract usage instructions
    const usageInstructions = this.extractSection(readmeContent, [
      "usage",
      "how to",
      "example",
      "quick start",
    ]);

    // Check for outputSchema documentation (MCP 2025-06-18 feature)
    const hasOutputSchemaDocumentation = this.checkOutputSchemaDocumentation(
      readmeContent,
      tools,
    );

    const metrics = {
      hasReadme: readmeContent.length > 0,
      exampleCount: extractedExamples.length,
      requiredExamples: 3,
      missingExamples: [] as string[],
      hasInstallInstructions: !!installInstructions,
      hasUsageGuide: !!usageInstructions,
      hasAPIReference:
        readmeContent.toLowerCase().includes("api") ||
        readmeContent.toLowerCase().includes("reference"),
      extractedExamples: extractedExamples.slice(0, 5), // Limit to first 5 examples
      installInstructions: installInstructions?.substring(0, 500), // Limit length
      usageInstructions: usageInstructions?.substring(0, 500), // Limit length
      // Tool documentation aggregates (always computed)
      toolsWithDescriptions: 0,
      toolsTotal: 0,
      toolDocGaps: [] as import("@/lib/assessmentTypes").ToolDocGap[],
    };

    if (metrics.exampleCount < metrics.requiredExamples) {
      metrics.missingExamples.push(
        `Need more code examples (found ${metrics.exampleCount}, recommend at least ${metrics.requiredExamples})`,
      );
    }
    if (!metrics.hasInstallInstructions) {
      metrics.missingExamples.push(
        "Consider adding installation instructions to README",
      );
    }
    if (!metrics.hasUsageGuide) {
      metrics.missingExamples.push(
        "Consider adding a usage guide or quick start section",
      );
    }

    let status: AssessmentStatus = "PASS";
    if (!metrics.hasReadme || metrics.exampleCount === 0) {
      status = "FAIL";
    } else if (metrics.exampleCount < metrics.requiredExamples) {
      status = "NEED_MORE_INFO";
    }

    // Apply bonus for outputSchema documentation (MCP 2025-06-18)
    let bonusApplied = false;
    if (hasOutputSchemaDocumentation && status !== "FAIL") {
      // Upgrade status if outputSchema is well-documented
      if (status === "NEED_MORE_INFO" && metrics.exampleCount >= 2) {
        status = "PASS";
        bonusApplied = true;
      }
    }

    const explanation = `Documentation has ${metrics.exampleCount}/${metrics.requiredExamples} required examples. ${
      metrics.hasInstallInstructions ? "Has" : "Missing"
    } installation instructions, ${
      metrics.hasUsageGuide ? "has" : "missing"
    } usage guide.${
      hasOutputSchemaDocumentation && status !== "FAIL"
        ? " ✅ Includes structured output documentation (MCP 2025-06-18)."
        : ""
    }${bonusApplied ? " (Bonus applied for outputSchema documentation)" : ""}`;

    const recommendations = [...metrics.missingExamples];
    if (
      !hasOutputSchemaDocumentation &&
      tools?.some((t: any) => t.outputSchema)
    ) {
      recommendations.push(
        "Consider documenting structured output (outputSchema) for tools that support it",
      );
    }

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Extract code examples from documentation
   */
  private extractCodeExamples(content: string): CodeExample[] {
    const examples: CodeExample[] = [];
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
    let match;

    while ((match = codeBlockRegex.exec(content)) !== null) {
      const language = match[1] || "plaintext";
      const code = match[2].trim();

      // Try to find a description before the code block
      const beforeIndex = Math.max(0, match.index - 200);
      const beforeText = content.substring(beforeIndex, match.index);
      const lines = beforeText.split("\n").filter((line) => line.trim());
      const description = lines[lines.length - 1] || undefined;

      examples.push({
        code,
        language,
        description: description?.trim(),
      });
    }

    return examples;
  }

  /**
   * Extract a section from documentation based on keywords
   */
  private extractSection(
    content: string,
    keywords: string[],
  ): string | undefined {
    const lines = content.split("\n");
    let inSection = false;
    let sectionContent: string[] = [];
    let sectionDepth = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lowerLine = line.toLowerCase();

      // Check if this is a section header matching our keywords
      if (line.startsWith("#")) {
        const headerDepth = line.match(/^#+/)?.[0].length || 0;
        const headerMatches = keywords.some((keyword) =>
          lowerLine.includes(keyword.toLowerCase()),
        );

        if (headerMatches) {
          inSection = true;
          sectionDepth = headerDepth;
          sectionContent = [line];
        } else if (inSection && headerDepth <= sectionDepth) {
          // We've reached a new section at the same or higher level
          break;
        }
      } else if (inSection) {
        sectionContent.push(line);
      }
    }

    return sectionContent.length > 0
      ? sectionContent.join("\n").trim()
      : undefined;
  }

  /**
   * Check if documentation includes outputSchema information (MCP 2025-06-18)
   */
  private checkOutputSchemaDocumentation(
    content: string,
    tools?: Tool[],
  ): boolean {
    if (!tools || tools.length === 0) {
      return false;
    }

    // Check if any tools have outputSchema
    const toolsWithOutputSchema = tools.filter((t: any) => t.outputSchema);
    if (toolsWithOutputSchema.length === 0) {
      // No tools with outputSchema, so documentation not needed
      return true;
    }

    const lowerContent = content.toLowerCase();

    // Check for outputSchema keywords
    const hasOutputSchemaKeywords =
      lowerContent.includes("outputschema") ||
      lowerContent.includes("output schema") ||
      lowerContent.includes("structured output") ||
      lowerContent.includes("structuredcontent") ||
      lowerContent.includes("structured content") ||
      lowerContent.includes("typed response") ||
      lowerContent.includes("response schema");

    // Check if examples show structured output usage
    const hasStructuredExamples =
      lowerContent.includes('"structuredcontent"') ||
      lowerContent.includes("structuredContent") ||
      (lowerContent.includes("response") && lowerContent.includes("schema"));

    return hasOutputSchemaKeywords || hasStructuredExamples;
  }
  //
  //   /**
  //    * Count code examples in documentation
  //    */
  //   private countCodeExamples(content: string): number {
  //     // Count markdown code blocks
  //     const codeBlockRegex = /```[\s\S]*?```/g;
  //     const matches = content.match(codeBlockRegex);
  //     return matches ? matches.length : 0;
  //   }

  /**
   * Assess usability of the MCP server
   */
  private assessUsability(tools: Tool[]): UsabilityAssessment {
    // Detailed analysis for each tool
    const toolAnalysis: Array<{
      toolName: string;
      namingPattern: string;
      description?: string;
      descriptionLength: number;
      hasDescription: boolean;
      parameterCount: number;
      hasRequiredParams: boolean;
      hasSchema: boolean;
      schemaQuality: string;
      hasOutputSchema?: boolean; // MCP 2025-06-18 feature
      parameters?: Array<{
        name: string;
        type?: string;
        required: boolean;
        description?: string;
        hasDescription: boolean;
      }>;
    }> = [];

    // Analyze each tool in detail
    for (const tool of tools) {
      const namingPattern = this.detectNamingPattern(tool.name);
      const descriptionLength = tool.description?.length || 0;
      const hasDescription = descriptionLength > 10;

      // Analyze schema and parameters
      const schemaAnalysis = this.analyzeToolSchema(tool);

      // Check for outputSchema (MCP 2025-06-18 feature)
      const hasOutputSchema = !!(tool as any).outputSchema;

      toolAnalysis.push({
        toolName: tool.name,
        namingPattern,
        description: tool.description,
        descriptionLength,
        hasDescription,
        parameterCount: schemaAnalysis.parameterCount,
        hasRequiredParams: schemaAnalysis.hasRequiredParams,
        hasSchema: schemaAnalysis.hasSchema,
        schemaQuality: schemaAnalysis.quality,
        parameters: schemaAnalysis.parameters,
        hasOutputSchema, // Track outputSchema presence
      });
    }

    // Check naming conventions with detailed breakdown
    const namingPatterns = toolAnalysis.map((t) => t.namingPattern);
    const uniquePatterns = new Set(namingPatterns);
    const toolNamingConvention =
      uniquePatterns.size === 1 ? "consistent" : "inconsistent";

    // Detailed naming analysis
    const namingDetails = {
      patterns: Array.from(uniquePatterns),
      breakdown: namingPatterns.reduce(
        (acc, pattern) => {
          acc[pattern] = (acc[pattern] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      ),
      dominant: this.getMostCommonPattern(namingPatterns),
    };

    // Check parameter clarity with detailed metrics
    let clearParams = 0;
    let unclearParams = 0;
    let mixedParams = 0;
    const parameterIssues: string[] = [];

    for (const analysis of toolAnalysis) {
      if (analysis.schemaQuality === "excellent") {
        clearParams++;
      } else if (analysis.schemaQuality === "poor") {
        unclearParams++;
        // Only flag if truly missing descriptions, not just brief ones
        if (analysis.parameters && analysis.parameters.length > 0) {
          const missingDescriptions = analysis.parameters.filter(
            (p) => !p.hasDescription,
          );
          if (missingDescriptions.length > 0) {
            parameterIssues.push(
              `${analysis.toolName}: Missing parameter descriptions for: ${missingDescriptions.map((p) => p.name).join(", ")}`,
            );
          }
        } else if (!analysis.hasSchema) {
          parameterIssues.push(`${analysis.toolName}: No input schema defined`);
        }
      } else {
        mixedParams++;
        if (analysis.descriptionLength < 20) {
          parameterIssues.push(
            `${analysis.toolName}: Tool description too brief (${analysis.descriptionLength} chars) - consider adding more detail`,
          );
        }
      }
    }

    const parameterClarity =
      unclearParams === 0 && mixedParams === 0
        ? "clear"
        : clearParams === 0
          ? "unclear"
          : "mixed";

    // Check description quality with detailed metrics
    const descriptionMetrics = {
      withDescriptions: toolAnalysis.filter((t) => t.hasDescription).length,
      withoutDescriptions: toolAnalysis.filter((t) => !t.hasDescription).length,
      averageLength: Math.round(
        toolAnalysis.reduce((sum, t) => sum + t.descriptionLength, 0) /
          tools.length,
      ),
      tooShort: toolAnalysis.filter(
        (t) => t.descriptionLength > 0 && t.descriptionLength < 20,
      ),
      adequate: toolAnalysis.filter(
        (t) => t.descriptionLength >= 20 && t.descriptionLength < 100,
      ),
      detailed: toolAnalysis.filter((t) => t.descriptionLength >= 100),
    };

    const hasHelpfulDescriptions =
      descriptionMetrics.withoutDescriptions === 0 &&
      descriptionMetrics.averageLength >= 20;

    // Count tools with outputSchema (MCP 2025-06-18 feature)
    const toolsWithOutputSchema = toolAnalysis.filter(
      (t) => t.hasOutputSchema,
    ).length;
    const outputSchemaPercentage =
      tools.length > 0 ? (toolsWithOutputSchema / tools.length) * 100 : 0;

    // Check best practices with detailed scoring
    const bestPracticeScore = {
      naming: this.calculateWeightedNamingScore(namingDetails, tools.length),
      descriptions: hasHelpfulDescriptions
        ? 25
        : descriptionMetrics.withDescriptions > tools.length * 0.8
          ? 15
          : 0,
      schemas:
        toolAnalysis.filter((t) => t.hasSchema).length === tools.length
          ? 25
          : toolAnalysis.filter((t) => t.hasSchema).length > tools.length * 0.8
            ? 15
            : 0,
      clarity:
        parameterClarity === "clear"
          ? 25
          : parameterClarity === "mixed"
            ? 15
            : 0,
      outputSchema:
        outputSchemaPercentage >= 50
          ? 10
          : outputSchemaPercentage >= 20
            ? 5
            : 0, // MCP 2025-06-18 bonus
      total: 0,
    };
    bestPracticeScore.total =
      bestPracticeScore.naming +
      bestPracticeScore.descriptions +
      bestPracticeScore.schemas +
      bestPracticeScore.clarity +
      bestPracticeScore.outputSchema;

    const followsBestPractices = bestPracticeScore.total >= 75;

    // Enhanced metrics with detailed breakdown
    const metrics: UsabilityMetrics = {
      toolNamingConvention: toolNamingConvention as
        | "consistent"
        | "inconsistent",
      parameterClarity: parameterClarity as "clear" | "unclear" | "mixed",
      hasHelpfulDescriptions,
      followsBestPractices,
      // Add detailed metrics for visibility
      detailedAnalysis: {
        tools: toolAnalysis,
        naming: namingDetails,
        descriptions: descriptionMetrics,
        parameterIssues,
        bestPracticeScore,
        overallScore: bestPracticeScore.total,
      },
    };

    // Determine status with clear criteria
    let status: AssessmentStatus = "PASS";
    if (bestPracticeScore.total < 50) {
      status = "FAIL";
    } else if (bestPracticeScore.total < 75) {
      status = "NEED_MORE_INFO";
    }

    // Enhanced explanation with specific details
    const explanation =
      `Usability Score: ${bestPracticeScore.total}/110. ` + // Updated max score with outputSchema bonus
      `Naming: ${toolNamingConvention} (${namingDetails.dominant} pattern used by ${Math.round(((namingDetails.breakdown[namingDetails.dominant] || 0) / tools.length) * 100)}% of tools). ` +
      `Descriptions: ${descriptionMetrics.withDescriptions}/${tools.length} tools have descriptions (avg ${descriptionMetrics.averageLength} chars). ` +
      `Parameter clarity: ${parameterClarity} (${clearParams} clear, ${mixedParams} mixed, ${unclearParams} unclear). ` +
      `Best practices: ${followsBestPractices ? "Yes" : "No"}. ` +
      `${toolsWithOutputSchema > 0 ? `✅ ${toolsWithOutputSchema}/${tools.length} tools use outputSchema (MCP 2025-06-18).` : ""}`;

    // Generate specific recommendations
    const recommendations = [];

    if (toolNamingConvention === "inconsistent") {
      const dominant = namingDetails.dominant;
      const inconsistentTools = toolAnalysis.filter(
        (t) => t.namingPattern !== dominant,
      );
      const dominantPercentage = Math.round(
        ((namingDetails.breakdown[dominant] || 0) / tools.length) * 100,
      );
      recommendations.push(
        `Consider adopting a consistent naming convention (${dominant} is used by ${dominantPercentage}% of tools). MCP doesn't mandate a specific style, but consistency improves usability. Inconsistent tools: ${inconsistentTools.map((t) => t.toolName).join(", ")}`,
      );
    }

    if (!hasHelpfulDescriptions) {
      const needingDescriptions = toolAnalysis.filter((t) => !t.hasDescription);
      if (needingDescriptions.length > 0) {
        recommendations.push(
          `Add descriptions for tools: ${needingDescriptions.map((t) => t.toolName).join(", ")}`,
        );
      }
      if (descriptionMetrics.tooShort.length > 0) {
        recommendations.push(
          `Expand short descriptions: ${descriptionMetrics.tooShort.map((t) => t.toolName).join(", ")}`,
        );
      }
    }

    if (parameterIssues.length > 0) {
      recommendations.push(...parameterIssues.slice(0, 3)); // Limit to top 3 issues
    }

    // Add recommendation for outputSchema if not widely adopted (MCP 2025-06-18)
    if (outputSchemaPercentage < 20 && tools.length > 0) {
      const toolsWithoutOutputSchema = toolAnalysis.filter(
        (t) => !t.hasOutputSchema && t.hasSchema,
      );
      if (toolsWithoutOutputSchema.length > 0) {
        recommendations.push(
          `Consider adding outputSchema to tools for type-safe responses (optional MCP 2025-06-18 feature for structured output). ${toolsWithoutOutputSchema.length} tools could benefit from this.`,
        );
      }
    }

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Detect naming pattern of a tool name
   */
  private detectNamingPattern(name: string): string {
    if (name.includes("_")) return "snake_case";
    if (name.includes("-")) return "kebab-case";
    if (/[A-Z]/.test(name) && /[a-z]/.test(name)) return "camelCase";
    if (name === name.toUpperCase()) return "UPPERCASE";
    if (name === name.toLowerCase()) return "lowercase";
    return "unknown";
  }

  /**
   * Get the most common pattern from an array
   */
  private getMostCommonPattern(patterns: string[]): string {
    const counts = patterns.reduce(
      (acc, pattern) => {
        acc[pattern] = (acc[pattern] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    return Object.entries(counts).reduce(
      (max, [pattern, count]) => (count > (counts[max] || 0) ? pattern : max),
      patterns[0] || "unknown",
    );
  }

  /**
   * Calculate weighted naming score based on dominant pattern percentage
   */
  private calculateWeightedNamingScore(
    namingDetails: {
      patterns: string[];
      breakdown: Record<string, number>;
      dominant: string;
    },
    totalTools: number,
  ): number {
    if (totalTools === 0) return 0;

    // If only one pattern exists, full points
    if (namingDetails.patterns.length === 1) {
      return 25;
    }

    // Calculate percentage of tools using dominant pattern
    const dominantCount = namingDetails.breakdown[namingDetails.dominant] || 0;
    const dominantPercentage = dominantCount / totalTools;

    // Award points proportionally, with bonus for high consistency
    let score = Math.round(dominantPercentage * 25);

    // Bonus points for very high consistency (≥90% = +2, ≥80% = +1)
    if (dominantPercentage >= 0.9) {
      score = Math.min(25, score + 2);
    } else if (dominantPercentage >= 0.8) {
      score = Math.min(25, score + 1);
    }

    return score;
  }

  /**
   * Analyze tool schema quality
   */
  private analyzeToolSchema(tool: Tool): {
    hasSchema: boolean;
    parameterCount: number;
    hasRequiredParams: boolean;
    quality: string;
    parameters?: Array<{
      name: string;
      type?: string;
      required: boolean;
      description?: string;
      hasDescription: boolean;
    }>;
  } {
    if (!tool.inputSchema) {
      return {
        hasSchema: false,
        parameterCount: 0,
        hasRequiredParams: false,
        quality: "poor",
      };
    }

    const schema = tool.inputSchema;
    const properties = schema.properties || {};
    const required = schema.required || [];
    const parameterCount = Object.keys(properties).length;

    // Collect parameter details
    const parameters: Array<{
      name: string;
      type?: string;
      required: boolean;
      description?: string;
      hasDescription: boolean;
    }> = [];

    // Check if parameters have descriptions
    let descriptionsCount = 0;
    let goodDescriptions = 0;

    for (const [name, prop] of Object.entries(properties)) {
      const propSchema = prop as any;
      const hasDesc = !!propSchema.description;

      if (hasDesc) {
        descriptionsCount++;
        if (propSchema.description.length > 20) {
          goodDescriptions++;
        }
      }

      parameters.push({
        name,
        type: propSchema.type || "unknown",
        required: required.includes(name),
        description: propSchema.description,
        hasDescription: hasDesc,
      });
    }

    const descriptionRatio =
      parameterCount > 0 ? descriptionsCount / parameterCount : 0;
    const qualityRatio =
      parameterCount > 0 ? goodDescriptions / parameterCount : 0;

    let quality = "poor";
    if (parameterCount === 0) {
      quality = "excellent"; // No parameters means nothing to critique
    } else if (qualityRatio >= 0.8) {
      quality = "excellent";
    } else if (descriptionRatio >= 0.8) {
      quality = "good";
    } else if (descriptionRatio >= 0.5) {
      quality = "fair";
    }

    return {
      hasSchema: true,
      parameterCount,
      hasRequiredParams: required.length > 0,
      quality,
      parameters,
    };
  }

  /**
   * Determine overall assessment status
   */
  private determineOverallStatus(
    ...statuses: AssessmentStatus[]
  ): AssessmentStatus {
    if (statuses.includes("FAIL")) return "FAIL";
    if (statuses.filter((s) => s === "NEED_MORE_INFO").length >= 2)
      return "FAIL";
    if (statuses.includes("NEED_MORE_INFO")) return "NEED_MORE_INFO";
    return "PASS";
  }

  /**
   * Generate assessment summary
   */
  private generateSummary(
    functionality: FunctionalityAssessment,
    security: SecurityAssessment,
    documentation: DocumentationAssessment,
    errorHandling: ErrorHandlingAssessment,
    usability: UsabilityAssessment,
  ): string {
    const parts = [];

    parts.push(
      `Functionality: ${functionality.status} - ${functionality.coveragePercentage.toFixed(1)}% tools tested, ${functionality.workingTools}/${functionality.totalTools} working`,
    );
    parts.push(
      `Security: ${security.status} - ${security.overallRiskLevel} risk level, ${security.vulnerabilities.length} vulnerabilities found`,
    );
    parts.push(
      `Documentation: ${documentation.status} - ${documentation.metrics.exampleCount}/${documentation.metrics.requiredExamples} examples provided`,
    );
    parts.push(
      `Error Handling: ${errorHandling.status} - ${errorHandling.metrics.errorResponseQuality} quality, ${errorHandling.metrics.mcpComplianceScore.toFixed(1)}% compliance`,
    );
    parts.push(
      `Usability: ${usability.status} - ${usability.metrics.toolNamingConvention} naming, ${usability.metrics.parameterClarity} parameter clarity`,
    );

    return parts.join(". ");
  }

  /**
   * Generate detailed security remediation guidance
   */
  private generateSecurityRecommendations(vulnerabilities: string[]): string[] {
    const recommendations: string[] = [];
    const vulnTypes = new Map<string, number>();

    // Count vulnerability types for prioritization
    vulnerabilities.forEach((vuln) => {
      const [, type] = vuln.split(": ");
      vulnTypes.set(type, (vulnTypes.get(type) || 0) + 1);
    });

    // Generate specific guidance for each vulnerability type
    vulnTypes.forEach((count, type) => {
      const description = this.getVulnerabilityDescription(type);
      const guidance = this.getSecurityGuidance(type);
      if (guidance) {
        recommendations.push(
          `${type} (${count} tools): ${description} → Fix: ${guidance}`,
        );
      }
    });

    return recommendations;
  }

  /**
   * Get user-friendly vulnerability description with context
   */
  private getVulnerabilityDescription(vulnerabilityType: string): string {
    const descriptions: Record<string, string> = {
      "Direct Command Injection":
        "Tool may execute malicious commands from user input",
      "Role Override":
        "Tool accepts instructions to change its behavior or purpose",
      "Data Exfiltration":
        "Tool may leak sensitive information when manipulated",
      "Context Escape": "Tool fails to maintain proper input boundaries",
      "Instruction Confusion":
        "Tool gets confused by conflicting or ambiguous commands",
      "Unicode Bypass": "Tool vulnerable to Unicode character exploitation",
      "Nested Injection":
        "Tool processes malicious payloads in complex data structures",
      "System Command": "Tool may execute unintended system-level operations",
    };

    return (
      descriptions[vulnerabilityType] ||
      "Input validation vulnerability detected"
    );
  }

  /**
   * Get specific security guidance for vulnerability types
   */
  private getSecurityGuidance(vulnerabilityType: string): string {
    const guidelines: Record<string, string> = {
      "Direct Command Injection":
        "Validate and sanitize all string inputs. Never pass user input directly to system commands or eval().",
      "Role Override":
        "Implement strict role validation. Reject inputs that attempt to change system behavior or bypass restrictions.",
      "Data Exfiltration":
        "Add input validation to prevent information disclosure. Avoid reflecting user input in error messages.",
      "Context Escape":
        "Implement proper input boundaries. Reject attempts to break out of expected parameter formats.",
      "Instruction Confusion":
        "Add clear parameter validation. Reject ambiguous or conflicting instructions.",
      "Unicode Bypass":
        "Normalize and validate Unicode input. Use allowlist validation for special characters.",
      "Nested Injection":
        "Validate nested data structures. Implement depth limits and recursive validation.",
      "System Command":
        "Never execute system commands from user input. Use safe alternatives or sandboxed environments.",
    };

    return (
      guidelines[vulnerabilityType] ||
      "Review input validation and implement proper sanitization."
    );
  }

  /**
   * Generate recommendations based on assessment
   */
  private generateRecommendations(
    functionality: FunctionalityAssessment,
    security: SecurityAssessment,
    documentation: DocumentationAssessment,
    errorHandling: ErrorHandlingAssessment,
    usability: UsabilityAssessment,
  ): string[] {
    const recommendations = [];

    // Add section headers to organize recommendations

    // Critical MCP Compliance Issues (highest priority)
    const complianceIssues = [];

    if (functionality.brokenTools.length > 0) {
      complianceIssues.push(
        `Fix broken tools: ${functionality.brokenTools.join(", ")}`,
      );
    }

    // Filter error handling recommendations for compliance issues
    const errorComplianceIssues = errorHandling.recommendations.filter(
      (r) =>
        r.includes("-3260") ||
        r.includes("-3270") ||
        r.includes("error code") ||
        r.includes("MCP standard"),
    );
    complianceIssues.push(...errorComplianceIssues);

    // Filter usability recommendations for compliance issues (schema, parameters)
    const usabilityComplianceIssues = usability.recommendations.filter(
      (r) => r.includes("schema") || r.includes("parameter descriptions for:"),
    );
    complianceIssues.push(...usabilityComplianceIssues);

    if (complianceIssues.length > 0) {
      recommendations.push("=== MCP Compliance Issues ===");
      recommendations.push(...complianceIssues);
    }

    // Security Issues (high priority)
    if (security.vulnerabilities.length > 0) {
      recommendations.push("=== Security Issues ===");
      recommendations.push(
        ...this.generateSecurityRecommendations(security.vulnerabilities),
      );
    }

    // Best Practices (medium priority)
    const bestPractices = [];

    // Filter for best practice recommendations
    const usabilityBestPractices = usability.recommendations.filter(
      (r) =>
        r.includes("naming convention") ||
        r.includes("outputSchema") ||
        (r.includes("consider") && !r.includes("parameter descriptions for:")),
    );
    bestPractices.push(...usabilityBestPractices);

    // Error handling best practices (non-compliance)
    const errorBestPractices = errorHandling.recommendations.filter(
      (r) => !errorComplianceIssues.includes(r) && r.includes("descriptive"),
    );
    bestPractices.push(...errorBestPractices);

    if (bestPractices.length > 0) {
      recommendations.push("=== Best Practices ===");
      recommendations.push(...bestPractices);
    }

    // Documentation Quality (lower priority)
    const docIssues = documentation.recommendations.filter(
      (r) =>
        r.includes("example") ||
        r.includes("installation") ||
        r.includes("usage") ||
        r.includes("guide"),
    );

    if (docIssues.length > 0) {
      recommendations.push("=== Documentation Quality ===");
      recommendations.push(...docIssues);
    }

    return recommendations;
  }

  // Helper methods for creating empty results when assessments are disabled
  private createEmptyFunctionalityResult(): FunctionalityAssessment {
    return {
      totalTools: 0,
      testedTools: 0,
      workingTools: 0,
      brokenTools: [],
      coveragePercentage: 100,
      status: "PASS",
      explanation: "Functionality assessment skipped",
      toolResults: [],
    };
  }

  private createEmptySecurityResult(): SecurityAssessment {
    return {
      promptInjectionTests: [],
      vulnerabilities: [],
      overallRiskLevel: "LOW",
      status: "PASS",
      explanation: "Security assessment skipped",
    };
  }

  private createEmptyDocumentationResult(): DocumentationAssessment {
    return {
      status: "PASS",
      recommendations: [],
      metrics: {
        hasReadme: false,
        exampleCount: 0,
        requiredExamples: 3,
        missingExamples: [],
        hasInstallInstructions: false,
        hasUsageGuide: false,
        hasAPIReference: false,
        toolsWithDescriptions: 0,
        toolsTotal: 0,
        toolDocGaps: [],
      },
      explanation: "Documentation assessment skipped",
    };
  }

  private createEmptyErrorHandlingResult(): ErrorHandlingAssessment {
    return {
      status: "PASS",
      score: 100, // Issue #28: Add score field for downstream consumers
      recommendations: [],
      metrics: {
        mcpComplianceScore: 100,
        errorResponseQuality: "excellent",
        hasProperErrorCodes: true,
        hasDescriptiveMessages: true,
        validatesInputs: true,
      },
      explanation: "Error handling assessment skipped",
    };
  }

  private createEmptyUsabilityResult(): UsabilityAssessment {
    return {
      status: "PASS",
      recommendations: [],
      metrics: {
        toolNamingConvention: "consistent",
        parameterClarity: "clear",
        hasHelpfulDescriptions: true,
        followsBestPractices: true,
      },
      explanation: "Usability assessment skipped",
    };
  }
}
