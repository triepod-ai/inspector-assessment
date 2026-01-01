/**
 * Documentation Assessor Module
 * Evaluates documentation quality and completeness
 */

import {
  DocumentationAssessment,
  DocumentationMetrics,
  CodeExample,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";

export class DocumentationAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<DocumentationAssessment> {
    this.log("Starting documentation assessment");

    const readmeContent = context.readmeContent || "";
    const validVerbosityLevels = ["minimal", "standard", "verbose"] as const;
    const configVerbosity = this.config.documentationVerbosity;
    // Default to verbose to include readmeContent for Claude analysis
    let verbosity: "minimal" | "standard" | "verbose" = "verbose";

    if (configVerbosity) {
      if (
        validVerbosityLevels.includes(
          configVerbosity as (typeof validVerbosityLevels)[number],
        )
      ) {
        verbosity = configVerbosity as "minimal" | "standard" | "verbose";
      } else {
        this.log(
          `Warning: Invalid documentationVerbosity "${configVerbosity}". ` +
            `Valid options: ${validVerbosityLevels.join(", ")}. Using "verbose".`,
        );
      }
    }
    const metrics = this.analyzeDocumentation(
      readmeContent,
      context.tools,
      verbosity,
    );

    const status = this.determineDocumentationStatus(metrics);
    const explanation = this.generateExplanation(metrics);
    const recommendations = this.generateRecommendations(metrics);

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

  private analyzeDocumentation(
    content: string,
    tools: any[],
    verbosity: "minimal" | "standard" | "verbose" = "standard",
  ): DocumentationMetrics {
    const hasReadme = content.length > 0;
    // Use new functional examples method that filters out configs/installs
    const functionalExamples = this.extractFunctionalExamples(content);
    // Keep old method for backward compatibility (extractedExamples field)
    const allCodeExamples = this.extractCodeExamples(content);
    const hasInstallInstructions = this.checkInstallInstructions(content);
    const hasUsageGuide = this.checkUsageGuide(content);
    const hasAPIReference = this.checkAPIReference(content);

    // Check which tools are documented
    const missingExamples: string[] = [];
    let documentedToolsCount = 0;

    // NEW: Build tool documentation status array for standard+ verbosity
    const toolDocumentation: DocumentationMetrics["toolDocumentation"] = [];

    if (tools && tools.length > 0) {
      // Check each tool for documentation
      for (const tool of tools) {
        const toolName = tool.name;
        const description = tool.description?.trim() || "";
        const hasDescription = description.length > 0;

        // Check if tool is mentioned in headings (any level) or code examples
        const headingRegex = new RegExp(`^#{1,6}\\s+${toolName}`, "mi");
        const mentionRegex = new RegExp(`\\b${toolName}\\b`, "i");

        const hasHeading = headingRegex.test(content);
        const hasMention = mentionRegex.test(content);
        const documentedInReadme = hasHeading || hasMention;

        // Count as documented if mentioned in README
        if (documentedInReadme) {
          documentedToolsCount++;
        }

        // Tool is missing if it has no description AND not documented in README
        if (!hasDescription && !documentedInReadme) {
          missingExamples.push(toolName);
        }

        // Build tool documentation status for standard+ verbosity
        if (verbosity !== "minimal") {
          toolDocumentation.push({
            name: toolName,
            hasDescription,
            descriptionLength: description.length,
            documentedInReadme,
            // Include actual description text (truncated) for Claude analysis
            description: hasDescription ? description.slice(0, 200) : undefined,
          });
        }
      }
    } else {
      // Fallback to generic example checking if no tools provided
      if (functionalExamples.length < 1)
        missingExamples.push("Basic usage example");
      if (
        !functionalExamples.some((e) => e.description?.includes("error")) &&
        !allCodeExamples.some((e) => e.description?.includes("error"))
      ) {
        missingExamples.push("Error handling example");
      }
      if (
        !functionalExamples.some((e) => e.description?.includes("config")) &&
        !allCodeExamples.some((e) => e.description?.includes("config"))
      ) {
        missingExamples.push("Configuration example");
      }
    }

    // Required examples: 3 minimum (Anthropic's standard)
    const requiredExamples = 3;

    // Count functional examples only (not configs/installs)
    // For servers with tools, also count documented tools
    const functionalExampleCount =
      functionalExamples.length +
      (tools && tools.length > 0 ? documentedToolsCount : 0);

    // NEW: Extract section headings for standard+ verbosity
    const sectionHeadings =
      verbosity !== "minimal" ? this.extractSectionHeadings(content) : [];

    // Build base metrics (always included)
    const baseMetrics: DocumentationMetrics = {
      hasReadme,
      exampleCount: functionalExampleCount, // Use functional examples instead of all code blocks
      requiredExamples,
      missingExamples,
      hasInstallInstructions,
      hasUsageGuide,
      hasAPIReference,
      extractedExamples: allCodeExamples, // Keep for backward compatibility
      installInstructions: hasInstallInstructions
        ? this.extractSection(content, "install")
        : undefined,
      usageInstructions: hasUsageGuide
        ? this.extractSection(content, "usage")
        : undefined,
    };

    // Add standard+ verbosity fields
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

    // Add verbose mode fields
    if (verbosity === "verbose" && content.length > 0) {
      baseMetrics.readmeContent = content.substring(0, 5000);
    }

    return baseMetrics;
  }

  /**
   * Extract functional example prompts from documentation.
   * Only counts user-facing examples, not configuration or installation code.
   */
  private extractFunctionalExamples(content: string): CodeExample[] {
    const functionalExamples: CodeExample[] = [];

    // Pattern 1: Look for standalone lines with tool triggers (use context7, use library, with X)
    const standalonePromptRegex =
      /^[ \t]*([A-Z][^\n]{10,300}?(?:use (?:context7|library|@?[\w-]+\/[\w-]+)|with \S+)[^\n]*?)[ \t]*$/gim;
    let standaloneMatch;

    while ((standaloneMatch = standalonePromptRegex.exec(content)) !== null) {
      const prompt = standaloneMatch[1].trim();

      // Filter out non-functional examples
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

    // Pattern 2: Look for bulleted examples
    const bulletedExampleRegex =
      /^[ \t]*[-*][ \t]+([A-Z][^\n]{10,300}?)[ \t]*$/gim;
    let bulletMatch;

    while ((bulletMatch = bulletedExampleRegex.exec(content)) !== null) {
      const prompt = bulletMatch[1].trim();

      // Must have tool trigger or action verb + technical term
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

    // Pattern 3: Look for inline examples with labels
    const inlineExampleRegex =
      /(?:Try|Example|Usage):\s*["`']([^"`']{10,300}?)["`']/gi;
    let inlineMatch;

    while ((inlineMatch = inlineExampleRegex.exec(content)) !== null) {
      const prompt = inlineMatch[1].trim();
      if (
        !this.isNonFunctionalCodeBlock(prompt) &&
        this.scoreFunctionalExample(prompt)
      ) {
        functionalExamples.push({
          code: prompt,
          language: "prompt",
          description: "Inline example",
          lineNumber: this.getLineNumber(content, inlineMatch.index),
        });
      }
    }

    // Remove duplicates based on similar content
    return this.deduplicateExamples(functionalExamples);
  }

  /**
   * Check if a code block is non-functional (config, install, implementation).
   */
  private isNonFunctionalCodeBlock(text: string): boolean {
    const excludePatterns = [
      /^\s*{\s*["']mcpServers["']/i, // JSON config
      /^\s*{\s*["']command["']/i, // MCP config
      /^\s*(npx|npm|yarn|pnpm|docker|git)\s+/i, // Install commands
      /^\s*FROM\s+\w+:/i, // Dockerfile
      /^\s*import\s+.*\s+from/i, // Import statements
      /^\s*\[.*\]\s*=\s*["']/i, // TOML/config assignments
      /^\s*<\w+>/i, // HTML/XML tags
      /^\s*(export|const|let|var|function)\s+/i, // Code declarations
      /^\s*\/\//i, // Code comments
      /^\s*#\s*\w+/i, // Shell comments or headers
    ];

    return excludePatterns.some((pattern) => pattern.test(text));
  }

  /**
   * Score functional example quality (returns true if meets minimum threshold).
   */
  private scoreFunctionalExample(text: string): boolean {
    let score = 0;

    // Has clear action verb (create, configure, implement, show, etc.)
    if (
      /\b(create|configure|implement|show|generate|build|write|add|get|set|use|run|start)\b/i.test(
        text,
      )
    ) {
      score += 2;
    }

    // Includes tool trigger ("use context7", "with library", "use library")
    if (/\b(?:use|with)\s+(?:context7|library|@?\w+\/\w+)\b/i.test(text)) {
      score += 2;
    }

    // Is a complete sentence (starts with capital, ends with punctuation or is substantial)
    if (/^[A-Z].{10,}/.test(text)) {
      score += 1;
    }

    // Has technical context (mentions framework/library/technology)
    if (
      /\b(Next\.js|React|Vue|Angular|PostgreSQL|MySQL|MongoDB|Redis|AWS|Cloudflare|API|HTTP|REST|GraphQL|TypeScript|JavaScript|Python|Docker|Kubernetes|Supabase|Firebase|Auth|JWT|OAuth)\b/i.test(
        text,
      )
    ) {
      score += 1;
    }

    // Minimum score: 4 out of 6 points
    return score >= 4;
  }

  /**
   * Get line number for a position in content.
   */
  private getLineNumber(content: string, position: number): number {
    const beforeMatch = content.substring(0, position);
    return beforeMatch.split("\n").length;
  }

  /**
   * Remove duplicate examples based on similarity.
   */
  private deduplicateExamples(examples: CodeExample[]): CodeExample[] {
    const seen = new Set<string>();
    const unique: CodeExample[] = [];

    for (const example of examples) {
      // Create a normalized version for comparison
      const normalized = example.code
        .toLowerCase()
        .replace(/[^\w\s]/g, "") // Remove punctuation
        .replace(/\s+/g, " ") // Normalize multiple spaces to single space
        .trim();

      if (!seen.has(normalized)) {
        seen.add(normalized);
        unique.push(example);
      }
    }

    return unique;
  }

  /**
   * @deprecated Use extractFunctionalExamples() instead.
   * This method counts ALL code blocks including configs and install commands.
   */
  private extractCodeExamples(content: string): CodeExample[] {
    const examples: CodeExample[] = [];
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
    let match;
    let lineNumber = 0;

    const lines = content.split("\n");

    while ((match = codeBlockRegex.exec(content)) !== null) {
      const language = match[1] || "plaintext";
      const code = match[2].trim();

      // Find line number
      const position = match.index;
      const beforeMatch = content.substring(0, position);
      lineNumber = beforeMatch.split("\n").length;

      // Try to find description from preceding lines
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
        // NEW: Classification fields for downstream analysis
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

  /**
   * Extract all section headings from README content.
   * Returns array of heading text (without # markers).
   */
  private extractSectionHeadings(content: string): string[] {
    const headingRegex = /^(#{1,6})\s+(.+)$/gm;
    const headings: string[] = [];
    let match;

    while ((match = headingRegex.exec(content)) !== null) {
      headings.push(match[2].trim());
    }

    return headings;
  }

  /**
   * Classify a code example by its type.
   * Reuses patterns from isNonFunctionalCodeBlock for consistency.
   */
  private classifyCodeExample(
    code: string,
    language?: string,
  ): CodeExample["exampleType"] {
    // Install commands
    if (/^\s*(npx|npm|yarn|pnpm|pip|docker|git)\s+/i.test(code)) {
      return "install";
    }
    // Configuration blocks
    if (
      /^\s*{\s*["']mcpServers["']/i.test(code) ||
      /^\s*{\s*["']command["']/i.test(code) ||
      language === "json" ||
      language === "toml" ||
      language === "yaml"
    ) {
      return "config";
    }
    // Implementation code (imports, declarations, class definitions)
    if (
      /^\s*(import|export|const|let|var|function|class)\s+/i.test(code) ||
      /^\s*from\s+/i.test(code)
    ) {
      return "implementation";
    }
    return "functional";
  }

  private determineDocumentationStatus(
    metrics: DocumentationMetrics,
  ): AssessmentStatus {
    let score = 0;
    const maxScore = 5;

    if (metrics.hasReadme) score++;
    if (metrics.hasInstallInstructions) score++;
    if (metrics.hasUsageGuide) score++;
    if (metrics.hasAPIReference) score++;
    if (metrics.exampleCount >= metrics.requiredExamples) score++;

    const percentage = (score / maxScore) * 100;

    if (percentage >= 80) return "PASS";
    if (percentage >= 50) return "NEED_MORE_INFO";
    return "FAIL";
  }

  private generateExplanation(metrics: DocumentationMetrics): string {
    const parts: string[] = [];

    if (!metrics.hasReadme) {
      parts.push("No README documentation found.");
    } else {
      parts.push(`README contains ${metrics.exampleCount} code examples.`);

      const features: string[] = [];
      if (metrics.hasInstallInstructions) features.push("installation");
      if (metrics.hasUsageGuide) features.push("usage guide");
      if (metrics.hasAPIReference) features.push("API reference");

      if (features.length > 0) {
        parts.push(`Documentation includes: ${features.join(", ")}.`);
      }

      if (metrics.missingExamples.length > 0) {
        parts.push(`Missing examples: ${metrics.missingExamples.join(", ")}.`);
      }
    }

    return parts.join(" ");
  }

  private generateRecommendations(metrics: DocumentationMetrics): string[] {
    const recommendations: string[] = [];

    if (!metrics.hasReadme) {
      recommendations.push("Create a comprehensive README.md file");
    }

    if (!metrics.hasInstallInstructions) {
      recommendations.push("Add clear installation instructions");
    }

    if (!metrics.hasUsageGuide) {
      recommendations.push("Include a usage guide with examples");
    }

    if (!metrics.hasAPIReference) {
      recommendations.push("Document all available tools and parameters");
    }

    if (metrics.exampleCount < metrics.requiredExamples) {
      recommendations.push(
        `Add ${metrics.requiredExamples - metrics.exampleCount} more code examples`,
      );
    }

    metrics.missingExamples.forEach((missing) => {
      recommendations.push(`Add ${missing}`);
    });

    return recommendations;
  }
}
