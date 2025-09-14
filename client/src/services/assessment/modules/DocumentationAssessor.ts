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
    const metrics = this.analyzeDocumentation(readmeContent);

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

  private analyzeDocumentation(content: string): DocumentationMetrics {
    const hasReadme = content.length > 0;
    const examples = this.extractCodeExamples(content);
    const hasInstallInstructions = this.checkInstallInstructions(content);
    const hasUsageGuide = this.checkUsageGuide(content);
    const hasAPIReference = this.checkAPIReference(content);

    // Determine required vs actual examples
    const requiredExamples = 3; // Minimum recommended
    const missingExamples: string[] = [];

    if (examples.length < 1) missingExamples.push("Basic usage example");
    if (!examples.some((e) => e.description?.includes("error"))) {
      missingExamples.push("Error handling example");
    }
    if (!examples.some((e) => e.description?.includes("config"))) {
      missingExamples.push("Configuration example");
    }

    return {
      hasReadme,
      exampleCount: examples.length,
      requiredExamples,
      missingExamples,
      hasInstallInstructions,
      hasUsageGuide,
      hasAPIReference,
      extractedExamples: examples,
      installInstructions: hasInstallInstructions
        ? this.extractSection(content, "install")
        : undefined,
      usageInstructions: hasUsageGuide
        ? this.extractSection(content, "usage")
        : undefined,
    };
  }

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
