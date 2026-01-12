/**
 * Developer Experience Assessor Module
 *
 * Unified module for evaluating developer experience aspects of MCP servers.
 * Merges DocumentationAssessor and UsabilityAssessor functionality.
 *
 * Assessment Areas:
 * 1. Documentation Quality - README completeness, examples, guides
 * 2. Usability - Tool naming, parameter clarity, best practices
 *
 * This module is part of Tier 4 (Extended) and is optional for security-focused audits.
 *
 * @module assessment/modules/DeveloperExperienceAssessor
 */

import {
  DocumentationMetrics,
  UsabilityMetrics,
  CodeExample,
  AssessmentStatus,
  ToolDocGap,
  DocumentationQualityChecks,
  DocumentationQualityScore,
  JSONSchema7,
  NamespaceDetectionResult,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Combined Developer Experience Assessment Result
 */
export interface DeveloperExperienceAssessment {
  /** Documentation metrics and analysis */
  documentation: DocumentationMetrics;
  /** Usability metrics and analysis */
  usability: UsabilityMetrics;
  /** Overall status combining both assessments */
  status: AssessmentStatus;
  /** Human-readable explanation */
  explanation: string;
  /** Recommendations for improvement */
  recommendations: string[];
  /** Individual scores for downstream consumers */
  scores: {
    documentation: number;
    usability: number;
    overall: number;
  };
  /** Namespace detection results (Issue #142) */
  namespaceDetection?: NamespaceDetectionResult;
}

export class DeveloperExperienceAssessor extends BaseAssessor<DeveloperExperienceAssessment> {
  async assess(
    context: AssessmentContext,
  ): Promise<DeveloperExperienceAssessment> {
    this.logger.info("Starting developer experience assessment");

    const readmeContent = context.readmeContent || "";

    // Assess documentation
    const documentationMetrics = this.analyzeDocumentation(
      readmeContent,
      context.tools,
      "verbose",
    );

    // Issue #55: Add quality scoring
    const { checks: qualityChecks, score: qualityScore } =
      this.assessDocumentationQuality(readmeContent, context);

    // Add quality data to metrics
    documentationMetrics.qualityChecks = qualityChecks;
    documentationMetrics.qualityScore = qualityScore;
    documentationMetrics.readmeSizeBytes = Buffer.byteLength(
      readmeContent,
      "utf8",
    );

    // Use quality score for documentation scoring (Issue #55)
    const documentationScore = qualityScore.total;

    // Assess usability
    const usabilityMetrics = this.analyzeUsability(context.tools);
    const usabilityScore = this.calculateUsabilityScore(usabilityMetrics);

    // Issue #142: Detect namespace/prefix patterns in tool names
    const namespaceDetection = this.detectNamespace(
      context.tools,
      context.serverInfo?.name,
    );

    // Calculate overall score (weighted average: 60% docs, 40% usability)
    const overallScore = Math.round(
      documentationScore * 0.6 + usabilityScore * 0.4,
    );

    // Determine status using Issue #55 thresholds
    const status = this.determineOverallStatus(overallScore);

    // Generate explanation and recommendations
    const explanation = this.generateExplanation(
      documentationMetrics,
      usabilityMetrics,
      context.tools,
    );
    const recommendations = this.generateRecommendations(
      documentationMetrics,
      usabilityMetrics,
    );

    this.testCount = 16; // Documentation (5) + Quality (6) + Usability (4) + Namespace (1) checks

    return {
      documentation: documentationMetrics,
      usability: usabilityMetrics,
      status,
      explanation,
      recommendations,
      scores: {
        documentation: documentationScore,
        usability: usabilityScore,
        overall: overallScore,
      },
      namespaceDetection,
    };
  }

  // ============================================================================
  // Documentation Analysis (from DocumentationAssessor)
  // ============================================================================

  private analyzeDocumentation(
    content: string,
    tools: Tool[],
    verbosity: "minimal" | "standard" | "verbose" = "standard",
  ): DocumentationMetrics {
    const hasReadme = content.length > 0;
    const functionalExamples = this.extractFunctionalExamples(content);
    const allCodeExamples = this.extractCodeExamples(content);
    const hasInstallInstructions = this.checkInstallInstructions(content);
    const hasUsageGuide = this.checkUsageGuide(content);
    const hasAPIReference = this.checkAPIReference(content);

    const missingExamples: string[] = [];
    let documentedToolsCount = 0;
    const toolDocumentation: DocumentationMetrics["toolDocumentation"] = [];
    const ADEQUATE_DESCRIPTION_LENGTH = 50;
    let toolsWithDescriptions = 0;
    const toolDocGaps: ToolDocGap[] = [];

    if (tools && tools.length > 0) {
      for (const tool of tools) {
        const toolName = tool.name;
        const description = tool.description?.trim() || "";
        const descriptionLength = description.length;
        const hasDescription = descriptionLength > 0;
        const hasAdequateDescription =
          descriptionLength >= ADEQUATE_DESCRIPTION_LENGTH;

        const headingRegex = new RegExp(`^#{1,6}\\s+${toolName}`, "mi");
        const mentionRegex = new RegExp(`\\b${toolName}\\b`, "i");

        const hasHeading = headingRegex.test(content);
        const hasMention = mentionRegex.test(content);
        const documentedInReadme = hasHeading || hasMention;

        if (documentedInReadme) {
          documentedToolsCount++;
        }

        if (!hasDescription && !documentedInReadme) {
          missingExamples.push(toolName);
        }

        if (hasAdequateDescription) {
          toolsWithDescriptions++;
        } else {
          toolDocGaps.push({
            toolName,
            issue: descriptionLength === 0 ? "missing" : "too_short",
            descriptionLength,
            documentedInReadme,
          });
        }

        if (verbosity !== "minimal") {
          toolDocumentation.push({
            name: toolName,
            hasDescription,
            descriptionLength,
            documentedInReadme,
            description: hasDescription ? description.slice(0, 200) : undefined,
          });
        }
      }
    } else {
      if (functionalExamples.length < 1)
        missingExamples.push("Basic usage example");
    }

    const requiredExamples = 3;
    const functionalExampleCount =
      functionalExamples.length +
      (tools && tools.length > 0 ? documentedToolsCount : 0);

    const sectionHeadings =
      verbosity !== "minimal" ? this.extractSectionHeadings(content) : [];

    const baseMetrics: DocumentationMetrics = {
      hasReadme,
      exampleCount: functionalExampleCount,
      requiredExamples,
      missingExamples,
      hasInstallInstructions,
      hasUsageGuide,
      hasAPIReference,
      extractedExamples: allCodeExamples,
      installInstructions: hasInstallInstructions
        ? this.extractSection(content, "install")
        : undefined,
      usageInstructions: hasUsageGuide
        ? this.extractSection(content, "usage")
        : undefined,
      toolsWithDescriptions,
      toolsTotal: tools?.length || 0,
      toolDocGaps,
    };

    if (verbosity !== "minimal") {
      baseMetrics.readmeLength = content.length;
      baseMetrics.readmeWordCount = content
        .split(/\s+/)
        .filter((w) => w.length > 0).length;
      baseMetrics.sectionHeadings = sectionHeadings;
      if (toolDocumentation.length > 0) {
        baseMetrics.toolDocumentation = toolDocumentation;
      }
    }

    if (verbosity === "verbose" && content.length > 0) {
      baseMetrics.readmeContent = content.substring(0, 5000);
    }

    return baseMetrics;
  }

  private extractFunctionalExamples(content: string): CodeExample[] {
    const functionalExamples: CodeExample[] = [];

    const standalonePromptRegex =
      /^[ \t]*([A-Z][^\n]{10,300}?(?:use (?:context7|library|@?[\w-]+\/[\w-]+)|with \S+)[^\n]*?)[ \t]*$/gim;
    let standaloneMatch;

    while ((standaloneMatch = standalonePromptRegex.exec(content)) !== null) {
      const prompt = standaloneMatch[1].trim();
      if (
        !this.isNonFunctionalCodeBlock(prompt) &&
        this.scoreFunctionalExample(prompt)
      ) {
        functionalExamples.push({
          code: prompt,
          language: "prompt",
          description: "Functional example prompt",
          lineNumber: this.getLineNumber(content, standaloneMatch.index),
        });
      }
    }

    const bulletedExampleRegex =
      /^[ \t]*[-*][ \t]+([A-Z][^\n]{10,300}?)[ \t]*$/gim;
    let bulletMatch;

    while ((bulletMatch = bulletedExampleRegex.exec(content)) !== null) {
      const prompt = bulletMatch[1].trim();
      if (
        !this.isNonFunctionalCodeBlock(prompt) &&
        this.scoreFunctionalExample(prompt)
      ) {
        functionalExamples.push({
          code: prompt,
          language: "prompt",
          description: "Bulleted example",
          lineNumber: this.getLineNumber(content, bulletMatch.index),
        });
      }
    }

    return this.deduplicateExamples(functionalExamples);
  }

  private isNonFunctionalCodeBlock(text: string): boolean {
    const excludePatterns = [
      /^\s*{\s*["']mcpServers["']/i,
      /^\s*{\s*["']command["']/i,
      /^\s*(npx|npm|yarn|pnpm|docker|git)\s+/i,
      /^\s*FROM\s+\w+:/i,
      /^\s*import\s+.*\s+from/i,
      /^\s*\[.*\]\s*=\s*["']/i,
      /^\s*<\w+>/i,
      /^\s*(export|const|let|var|function)\s+/i,
      /^\s*\/\//i,
      /^\s*#\s*\w+/i,
    ];

    return excludePatterns.some((pattern) => pattern.test(text));
  }

  private scoreFunctionalExample(text: string): boolean {
    let score = 0;

    if (
      /\b(create|configure|implement|show|generate|build|write|add|get|set|use|run|start)\b/i.test(
        text,
      )
    ) {
      score += 2;
    }

    if (/\b(?:use|with)\s+(?:context7|library|@?\w+\/\w+)\b/i.test(text)) {
      score += 2;
    }

    if (/^[A-Z].{10,}/.test(text)) {
      score += 1;
    }

    if (
      /\b(Next\.js|React|Vue|Angular|PostgreSQL|MySQL|MongoDB|Redis|AWS|Cloudflare|API|HTTP|REST|GraphQL|TypeScript|JavaScript|Python|Docker|Kubernetes|Supabase|Firebase|Auth|JWT|OAuth)\b/i.test(
        text,
      )
    ) {
      score += 1;
    }

    return score >= 4;
  }

  private getLineNumber(content: string, position: number): number {
    const beforeMatch = content.substring(0, position);
    return beforeMatch.split("\n").length;
  }

  private deduplicateExamples(examples: CodeExample[]): CodeExample[] {
    const seen = new Set<string>();
    const unique: CodeExample[] = [];

    for (const example of examples) {
      const normalized = example.code
        .toLowerCase()
        .replace(/[^\w\s]/g, "")
        .replace(/\s+/g, " ")
        .trim();

      if (!seen.has(normalized)) {
        seen.add(normalized);
        unique.push(example);
      }
    }

    return unique;
  }

  private extractCodeExamples(content: string): CodeExample[] {
    const examples: CodeExample[] = [];
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
    let match;

    const lines = content.split("\n");

    while ((match = codeBlockRegex.exec(content)) !== null) {
      const language = match[1] || "plaintext";
      const code = match[2].trim();

      const position = match.index;
      const beforeMatch = content.substring(0, position);
      const lineNumber = beforeMatch.split("\n").length;

      let description = "";
      const lineIndex = lines.findIndex(
        (_, i) => lines.slice(0, i + 1).join("\n").length >= position,
      );

      if (lineIndex > 0) {
        const prevLine = lines[lineIndex - 1].trim();
        if (prevLine && !prevLine.startsWith("#")) {
          description = prevLine;
        }
      }

      examples.push({
        code,
        language,
        description,
        lineNumber,
        lineCount: code.split("\n").length,
        exampleType: this.classifyCodeExample(code, language),
      });
    }

    return examples;
  }

  private checkInstallInstructions(content: string): boolean {
    const installKeywords = [
      "install",
      "npm install",
      "yarn add",
      "pip install",
      "setup",
      "getting started",
    ];
    const contentLower = content.toLowerCase();
    return installKeywords.some((keyword) => contentLower.includes(keyword));
  }

  private checkUsageGuide(content: string): boolean {
    const usageKeywords = [
      "usage",
      "how to use",
      "example",
      "quick start",
      "tutorial",
    ];
    const contentLower = content.toLowerCase();
    return usageKeywords.some((keyword) => contentLower.includes(keyword));
  }

  private checkAPIReference(content: string): boolean {
    const apiKeywords = [
      "api",
      "reference",
      "methods",
      "functions",
      "parameters",
      "returns",
      "endpoints",
    ];
    const contentLower = content.toLowerCase();
    return apiKeywords.some((keyword) => contentLower.includes(keyword));
  }

  private extractSection(content: string, section: string): string {
    const sectionRegex = new RegExp(
      `#+\\s*${section}[\\s\\S]*?(?=\\n#|$)`,
      "gi",
    );
    const match = content.match(sectionRegex);
    return match ? match[0].trim() : "";
  }

  private extractSectionHeadings(content: string): string[] {
    const headingRegex = /^(#{1,6})\s+(.+)$/gm;
    const headings: string[] = [];
    let match;

    while ((match = headingRegex.exec(content)) !== null) {
      headings.push(match[2].trim());
    }

    return headings;
  }

  private classifyCodeExample(
    code: string,
    language?: string,
  ): CodeExample["exampleType"] {
    if (/^\s*(npx|npm|yarn|pnpm|pip|docker|git)\s+/i.test(code)) {
      return "install";
    }
    if (
      /^\s*{\s*["']mcpServers["']/i.test(code) ||
      /^\s*{\s*["']command["']/i.test(code) ||
      language === "json" ||
      language === "toml" ||
      language === "yaml"
    ) {
      return "config";
    }
    if (
      /^\s*(import|export|const|let|var|function|class)\s+/i.test(code) ||
      /^\s*from\s+/i.test(code)
    ) {
      return "implementation";
    }
    return "functional";
  }

  // ============================================================================
  // Issue #55: Documentation Quality Scoring
  // ============================================================================

  /**
   * Assess documentation quality using Issue #55 point-based scoring
   * Max 100 points: README (30), Install (20), Config (20), Examples (20), License (10)
   */
  private assessDocumentationQuality(
    content: string,
    context: AssessmentContext,
  ): { checks: DocumentationQualityChecks; score: DocumentationQualityScore } {
    const checks: DocumentationQualityChecks = {
      hasReadme: content.length > 0,
      readmeQuality: this.determineReadmeQuality(content),
      hasInstallation: this.checkInstallInstructions(content),
      hasConfiguration: this.checkConfigurationSection(content),
      hasExamples: this.checkUsageGuide(content),
      hasLicense: this.detectLicense(context),
      licenseType: this.detectLicenseType(context),
    };

    const score = this.calculateQualityScore(checks, content);
    return { checks, score };
  }

  /**
   * Determine README quality tier based on size
   * - minimal: <5KB
   * - adequate: 5KB-15KB
   * - comprehensive: >15KB
   */
  private determineReadmeQuality(
    content: string,
  ): "minimal" | "adequate" | "comprehensive" {
    const sizeBytes = Buffer.byteLength(content, "utf8");
    const sizeKB = sizeBytes / 1024;

    if (sizeKB > 15) return "comprehensive";
    if (sizeKB > 5) return "adequate";
    return "minimal";
  }

  /**
   * Calculate point-based quality score per Issue #55
   * Max 100 points:
   * - README exists: +10
   * - README >5KB: +10 (adequate)
   * - README >15KB: +10 more (comprehensive = +20 total)
   * - Installation section: +20
   * - Configuration section: +20
   * - Examples present: +20
   * - License file: +10
   */
  private calculateQualityScore(
    checks: DocumentationQualityChecks,
    content: string,
  ): DocumentationQualityScore {
    const sizeBytes = Buffer.byteLength(content, "utf8");
    const sizeKB = sizeBytes / 1024;

    // Calculate README size bonus
    let readmeComprehensive = 0;
    if (checks.hasReadme) {
      if (sizeKB > 15) {
        readmeComprehensive = 20; // comprehensive: +10 + +10
      } else if (sizeKB > 5) {
        readmeComprehensive = 10; // adequate: +10
      }
    }

    const breakdown = {
      readmeExists: checks.hasReadme ? 10 : 0,
      readmeComprehensive,
      installation: checks.hasInstallation ? 20 : 0,
      configuration: checks.hasConfiguration ? 20 : 0,
      examples: checks.hasExamples ? 20 : 0,
      license: checks.hasLicense ? 10 : 0,
    };

    return {
      total: Object.values(breakdown).reduce((sum, v) => sum + v, 0),
      breakdown,
    };
  }

  /**
   * Check for configuration/environment section
   * Looks for: configuration, config, environment, env vars, .env
   */
  private checkConfigurationSection(content: string): boolean {
    const configKeywords = [
      "configuration",
      "config",
      "environment variable",
      "env var",
      ".env",
      "api key",
      "api_key",
      "apikey",
      "setup",
    ];
    const contentLower = content.toLowerCase();
    return configKeywords.some((keyword) => contentLower.includes(keyword));
  }

  /**
   * Detect license presence from context
   * Checks sourceCodeFiles for LICENSE/LICENSE.md or README for license section
   */
  private detectLicense(context: AssessmentContext): boolean {
    // Check source code files if available
    if (context.sourceCodeFiles) {
      const licenseFiles = [
        "LICENSE",
        "LICENSE.md",
        "LICENSE.txt",
        "LICENCE",
        "LICENCE.md",
      ];
      for (const file of licenseFiles) {
        if (context.sourceCodeFiles.has(file)) return true;
      }
    }

    // Fallback: check README for license section
    const content = context.readmeContent || "";
    return /^#+\s*licen[sc]e/im.test(content);
  }

  /**
   * Detect license type (MIT, Apache-2.0, GPL, BSD, etc.)
   */
  private detectLicenseType(context: AssessmentContext): string | undefined {
    if (!context.sourceCodeFiles) return undefined;

    // Try common license file names
    const licenseFiles = [
      "LICENSE",
      "LICENSE.md",
      "LICENSE.txt",
      "LICENCE",
      "LICENCE.md",
    ];
    let licenseContent: string | undefined;

    for (const file of licenseFiles) {
      if (context.sourceCodeFiles.has(file)) {
        licenseContent = context.sourceCodeFiles.get(file);
        break;
      }
    }

    if (!licenseContent) return undefined;

    // Simple license detection patterns
    if (
      licenseContent.includes("MIT License") ||
      licenseContent.includes("Permission is hereby granted, free of charge")
    ) {
      return "MIT";
    }
    if (
      licenseContent.includes("Apache License") &&
      licenseContent.includes("2.0")
    ) {
      return "Apache-2.0";
    }
    if (licenseContent.includes("GNU GENERAL PUBLIC LICENSE")) {
      if (licenseContent.includes("Version 3")) return "GPL-3.0";
      if (licenseContent.includes("Version 2")) return "GPL-2.0";
      return "GPL";
    }
    if (licenseContent.includes("BSD")) {
      if (licenseContent.includes("3-Clause") || licenseContent.includes("New"))
        return "BSD-3-Clause";
      if (
        licenseContent.includes("2-Clause") ||
        licenseContent.includes("Simplified")
      )
        return "BSD-2-Clause";
      return "BSD";
    }
    if (licenseContent.includes("ISC License")) {
      return "ISC";
    }
    if (licenseContent.includes("Mozilla Public License")) {
      return "MPL-2.0";
    }
    if (
      licenseContent.includes("UNLICENSE") ||
      licenseContent.includes("unlicense")
    ) {
      return "Unlicense";
    }

    return "Unknown";
  }

  // ============================================================================
  // Usability Analysis (from UsabilityAssessor)
  // ============================================================================

  private analyzeUsability(tools: Tool[]): UsabilityMetrics {
    const toolNamingConvention = this.analyzeNamingConvention(tools);
    const parameterClarity = this.analyzeParameterClarity(tools);
    const hasHelpfulDescriptions = this.checkDescriptions(tools);
    const followsBestPractices = this.checkBestPractices(tools);

    return {
      toolNamingConvention,
      parameterClarity,
      hasHelpfulDescriptions,
      followsBestPractices,
    };
  }

  private analyzeNamingConvention(
    tools: Tool[],
  ): "consistent" | "inconsistent" {
    if (tools.length === 0) return "consistent";

    const namingPatterns = {
      camelCase: 0,
      snake_case: 0,
      kebab_case: 0,
      PascalCase: 0,
    };

    for (const tool of tools) {
      const name = tool.name;

      if (/^[a-z][a-zA-Z0-9]*$/.test(name)) {
        namingPatterns.camelCase++;
      } else if (/^[a-z]+(_[a-z]+)*$/.test(name)) {
        namingPatterns.snake_case++;
      } else if (/^[a-z]+(-[a-z]+)*$/.test(name)) {
        namingPatterns.kebab_case++;
      } else if (/^[A-Z][a-zA-Z0-9]*$/.test(name)) {
        namingPatterns.PascalCase++;
      }
    }

    const total = tools.length;
    const threshold = total * 0.7;

    for (const count of Object.values(namingPatterns)) {
      if (count >= threshold) {
        return "consistent";
      }
    }

    return "inconsistent";
  }

  private analyzeParameterClarity(
    tools: Tool[],
  ): "clear" | "unclear" | "mixed" {
    if (tools.length === 0) return "clear";

    let clearCount = 0;
    let unclearCount = 0;

    for (const tool of tools) {
      const schema = this.getToolSchema(tool);

      if (!schema?.properties) continue;

      for (const [paramName, paramDef] of Object.entries(
        schema.properties as Record<string, any>,
      )) {
        if (this.isDescriptiveName(paramName)) {
          clearCount++;
        } else {
          unclearCount++;
        }

        if (paramDef.description) {
          clearCount++;
        } else {
          unclearCount++;
        }
      }
    }

    const total = clearCount + unclearCount;
    if (total === 0) return "clear";

    const clarityRatio = clearCount / total;

    if (clarityRatio >= 0.8) return "clear";
    if (clarityRatio <= 0.3) return "unclear";
    return "mixed";
  }

  private checkDescriptions(tools: Tool[]): boolean {
    if (tools.length === 0) return false;

    let toolsWithDescriptions = 0;

    for (const tool of tools) {
      if (tool.description && tool.description.length > 10) {
        toolsWithDescriptions++;
      }
    }

    return toolsWithDescriptions / tools.length >= 0.7;
  }

  private checkBestPractices(tools: Tool[]): boolean {
    const practices = {
      hasVersioning: false,
      hasErrorHandling: false,
      hasValidation: false,
      hasDocumentation: false,
    };

    for (const tool of tools) {
      const schema = this.getToolSchema(tool);

      if (schema?.required && schema.required.length > 0) {
        practices.hasValidation = true;
      }

      if (schema?.properties) {
        for (const prop of Object.values(
          schema.properties as Record<string, any>,
        )) {
          if (
            prop.enum ||
            prop.minimum !== undefined ||
            prop.maximum !== undefined
          ) {
            practices.hasValidation = true;
          }
        }
      }

      if (tool.description) {
        practices.hasDocumentation = true;
      }
    }

    const followedPractices = Object.values(practices).filter((v) => v).length;
    return followedPractices >= 2;
  }

  private isDescriptiveName(name: string): boolean {
    const goodNames = [
      "query",
      "search",
      "input",
      "output",
      "data",
      "content",
      "message",
      "text",
      "file",
      "path",
      "url",
      "name",
      "id",
      "value",
      "result",
      "response",
      "request",
      "params",
    ];

    const nameLower = name.toLowerCase();

    for (const goodName of goodNames) {
      if (nameLower.includes(goodName)) {
        return true;
      }
    }

    return name.length > 3 && !/^[a-z]$/.test(name);
  }

  private getToolSchema(tool: Tool): JSONSchema7 | null {
    if (!tool.inputSchema) return null;

    return typeof tool.inputSchema === "string"
      ? (this.safeJsonParse(tool.inputSchema) as JSONSchema7 | null)
      : (tool.inputSchema as JSONSchema7);
  }

  private calculateUsabilityScore(metrics: UsabilityMetrics): number {
    let score = 0;
    const maxScore = 4;

    if (metrics.toolNamingConvention === "consistent") score++;
    if (metrics.parameterClarity === "clear") score++;
    if (metrics.hasHelpfulDescriptions) score++;
    if (metrics.followsBestPractices) score++;

    return Math.round((score / maxScore) * 100);
  }

  // ============================================================================
  // Namespace Detection (Issue #142)
  // ============================================================================

  /**
   * Detect namespace/prefix patterns in tool names.
   * This helps identify intentional naming conventions like:
   * - calc_add, calc_subtract -> namespace "calc"
   * - fileRead, fileWrite -> namespace "file"
   * - myserver_tool1, myserver_tool2 -> matches server name
   */
  private detectNamespace(
    tools: Tool[],
    serverName?: string,
  ): NamespaceDetectionResult {
    const toolNames = tools.map((t) => t.name);
    const totalTools = toolNames.length;

    // Need at least 2 tools to detect a namespace
    if (totalTools < 2) {
      return {
        detected: false,
        confidence: "low",
        toolsCovered: 0,
        totalTools,
        matchPattern: "none",
      };
    }

    // Try server name prefix first (highest priority)
    if (serverName) {
      const serverNameResult = this.checkServerNamePrefix(
        toolNames,
        serverName,
      );
      if (
        serverNameResult.matches >= 2 &&
        serverNameResult.matches / totalTools >= 0.5
      ) {
        return {
          detected: true,
          namespace: this.normalizeServerName(serverName),
          confidence: "high",
          toolsCovered: serverNameResult.matches,
          totalTools,
          matchPattern: "serverName",
          evidence: serverNameResult.matchedTools.slice(0, 5),
        };
      }
    }

    // Try common prefix detection
    const prefixResult = this.findCommonPrefix(toolNames);
    if (prefixResult) {
      const coverageRatio = prefixResult.count / totalTools;
      const confidence: "high" | "medium" | "low" =
        coverageRatio >= 0.5 ? "high" : coverageRatio >= 0.3 ? "medium" : "low";

      if (prefixResult.count >= 2 && coverageRatio >= 0.3) {
        return {
          detected: true,
          namespace: prefixResult.prefix,
          confidence,
          toolsCovered: prefixResult.count,
          totalTools,
          matchPattern: "prefix",
          evidence: prefixResult.matchedTools.slice(0, 5),
        };
      }
    }

    // No namespace detected
    return {
      detected: false,
      confidence: "low",
      toolsCovered: 0,
      totalTools,
      matchPattern: "none",
    };
  }

  /**
   * Find common prefix among tool names.
   * Handles both snake_case (calc_add) and camelCase (calcAdd) conventions.
   */
  private findCommonPrefix(
    toolNames: string[],
  ): { prefix: string; count: number; matchedTools: string[] } | null {
    if (toolNames.length < 2) return null;

    // Build prefix frequency map
    const prefixCounts = new Map<string, string[]>();

    for (const name of toolNames) {
      // Extract prefix using snake_case separator
      const snakeMatch = name.match(/^([a-z]+)_/);
      if (snakeMatch && snakeMatch[1].length >= 3) {
        const prefix = snakeMatch[1];
        if (!prefixCounts.has(prefix)) {
          prefixCounts.set(prefix, []);
        }
        prefixCounts.get(prefix)!.push(name);
      }

      // Extract prefix using camelCase pattern
      const camelMatch = name.match(/^([a-z]+)[A-Z]/);
      if (camelMatch && camelMatch[1].length >= 3) {
        const prefix = camelMatch[1];
        if (!prefixCounts.has(prefix)) {
          prefixCounts.set(prefix, []);
        }
        // Avoid double-counting if snake_case already found this name
        const existing = prefixCounts.get(prefix)!;
        if (!existing.includes(name)) {
          existing.push(name);
        }
      }
    }

    // Find the prefix with the most matches
    let bestPrefix: string | null = null;
    let bestCount = 0;
    let bestTools: string[] = [];

    for (const [prefix, tools] of prefixCounts) {
      if (tools.length > bestCount) {
        bestPrefix = prefix;
        bestCount = tools.length;
        bestTools = tools;
      }
    }

    if (bestPrefix && bestCount >= 2) {
      return {
        prefix: bestPrefix,
        count: bestCount,
        matchedTools: bestTools,
      };
    }

    return null;
  }

  /**
   * Check if tool names use the server name as a prefix.
   * Normalizes server name to match common patterns.
   */
  private checkServerNamePrefix(
    toolNames: string[],
    serverName: string,
  ): { matches: number; matchedTools: string[] } {
    const normalizedServerName = this.normalizeServerName(serverName);
    const matchedTools: string[] = [];

    for (const name of toolNames) {
      const nameLower = name.toLowerCase();

      // Check snake_case prefix (e.g., myserver_tool)
      if (nameLower.startsWith(normalizedServerName + "_")) {
        matchedTools.push(name);
        continue;
      }

      // Check camelCase prefix (e.g., myserverTool)
      if (
        nameLower.startsWith(normalizedServerName) &&
        name.length > normalizedServerName.length &&
        /[A-Z]/.test(name[normalizedServerName.length])
      ) {
        matchedTools.push(name);
        continue;
      }

      // Check kebab-case prefix (e.g., myserver-tool)
      if (nameLower.startsWith(normalizedServerName + "-")) {
        matchedTools.push(name);
      }
    }

    return {
      matches: matchedTools.length,
      matchedTools,
    };
  }

  /**
   * Normalize server name for prefix matching.
   * Converts "My-Server" -> "myserver", "my_server" -> "myserver"
   */
  private normalizeServerName(serverName: string): string {
    return serverName.toLowerCase().replace(/[-_\s]/g, "");
  }

  // ============================================================================
  // Combined Status, Explanation, and Recommendations
  // ============================================================================

  private determineOverallStatus(overallScore: number): AssessmentStatus {
    if (overallScore >= 80) return "PASS";
    if (overallScore >= 50) return "NEED_MORE_INFO";
    return "FAIL";
  }

  private generateExplanation(
    docMetrics: DocumentationMetrics,
    usabilityMetrics: UsabilityMetrics,
    tools: Tool[],
  ): string {
    const parts: string[] = [];

    // Documentation summary
    if (!docMetrics.hasReadme) {
      parts.push("No README documentation found.");
    } else {
      parts.push(`README contains ${docMetrics.exampleCount} code examples.`);

      const features: string[] = [];
      if (docMetrics.hasInstallInstructions) features.push("installation");
      if (docMetrics.hasUsageGuide) features.push("usage guide");
      if (docMetrics.hasAPIReference) features.push("API reference");

      if (features.length > 0) {
        parts.push(`Documentation includes: ${features.join(", ")}.`);
      }
    }

    // Usability summary
    parts.push(`Analyzed ${tools.length} tools for usability.`);
    parts.push(`Naming convention: ${usabilityMetrics.toolNamingConvention}.`);
    parts.push(`Parameter clarity: ${usabilityMetrics.parameterClarity}.`);

    const usabilityFeatures: string[] = [];
    if (usabilityMetrics.hasHelpfulDescriptions)
      usabilityFeatures.push("helpful descriptions");
    if (usabilityMetrics.followsBestPractices)
      usabilityFeatures.push("follows best practices");

    if (usabilityFeatures.length > 0) {
      parts.push(`Usability: ${usabilityFeatures.join(", ")}.`);
    }

    return parts.join(" ");
  }

  private generateRecommendations(
    docMetrics: DocumentationMetrics,
    usabilityMetrics: UsabilityMetrics,
  ): string[] {
    const recommendations: string[] = [];

    // Documentation recommendations
    if (!docMetrics.hasReadme) {
      recommendations.push("Create a comprehensive README.md file");
    }

    if (!docMetrics.hasInstallInstructions) {
      recommendations.push("Add clear installation instructions");
    }

    if (!docMetrics.hasUsageGuide) {
      recommendations.push("Include a usage guide with examples");
    }

    if (!docMetrics.hasAPIReference) {
      recommendations.push("Document all available tools and parameters");
    }

    if (docMetrics.exampleCount < docMetrics.requiredExamples) {
      recommendations.push(
        `Add ${docMetrics.requiredExamples - docMetrics.exampleCount} more code examples`,
      );
    }

    // Usability recommendations
    if (usabilityMetrics.toolNamingConvention === "inconsistent") {
      recommendations.push(
        "Adopt a consistent naming convention for all tools",
      );
    }

    if (usabilityMetrics.parameterClarity !== "clear") {
      recommendations.push("Use descriptive parameter names");
      recommendations.push("Add descriptions for all parameters");
    }

    if (!usabilityMetrics.hasHelpfulDescriptions) {
      recommendations.push("Provide detailed descriptions for each tool");
    }

    if (!usabilityMetrics.followsBestPractices) {
      recommendations.push("Implement input validation with constraints");
    }

    return recommendations;
  }
}
