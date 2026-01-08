/**
 * Usability Assessor Module
 * Evaluates tool naming, parameter clarity, and best practices
 */

import {
  UsabilityAssessment,
  UsabilityMetrics,
  AssessmentStatus,
  JSONSchema7,
} from "@/lib/assessmentTypes";
import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";

interface ToolInputSchema {
  type: string;
  properties?: Record<string, JSONSchema7>;
  required?: string[];
}

/**
 * @deprecated Use DeveloperExperienceAssessor instead. Will be removed in v2.0.0.
 */
export class UsabilityAssessor extends BaseAssessor {
  constructor(config: AssessmentConfiguration) {
    super(config);
    this.logger.warn(
      "UsabilityAssessor is deprecated. Use DeveloperExperienceAssessor instead. " +
        "This module will be removed in v2.0.0.",
      {
        module: "UsabilityAssessor",
        replacement: "DeveloperExperienceAssessor",
      },
    );
  }

  async assess(context: AssessmentContext): Promise<UsabilityAssessment> {
    this.log("Starting usability assessment");

    const metrics = this.analyzeUsability(context.tools);
    const status = this.determineUsabilityStatus(metrics);
    const explanation = this.generateExplanation(metrics, context.tools);
    const recommendations = this.generateRecommendations(metrics);

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

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

    // Check if one pattern dominates (>70%)
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
        schema.properties as Record<string, JSONSchema7>,
      )) {
        // Check if parameter name is self-descriptive
        if (this.isDescriptiveName(paramName)) {
          clearCount++;
        } else {
          unclearCount++;
        }

        // Check if parameter has description
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

    // Consider helpful if >70% of tools have descriptions
    return toolsWithDescriptions / tools.length >= 0.7;
  }

  private checkBestPractices(tools: Tool[]): boolean {
    const practices = {
      hasVersioning: false,
      hasErrorHandling: false,
      hasValidation: false,
      hasDocumentation: false,
    };

    // Check various best practices
    for (const tool of tools) {
      const schema = this.getToolSchema(tool);

      // Check for validation (required fields, enums, etc.)
      if (schema?.required && schema.required.length > 0) {
        practices.hasValidation = true;
      }

      // Check for proper parameter constraints
      if (schema?.properties) {
        for (const prop of Object.values(
          schema.properties as Record<string, JSONSchema7>,
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

      // Check for documentation
      if (tool.description) {
        practices.hasDocumentation = true;
      }
    }

    // Count how many practices are followed
    const followedPractices = Object.values(practices).filter((v) => v).length;

    // Consider following best practices if at least 2 are met
    return followedPractices >= 2;
  }

  private isDescriptiveName(name: string): boolean {
    // Check if name is self-descriptive
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

    // Check if name contains any good keywords
    for (const goodName of goodNames) {
      if (nameLower.includes(goodName)) {
        return true;
      }
    }

    // Check if name is not too short or cryptic
    return name.length > 3 && !/^[a-z]$/.test(name);
  }

  private getToolSchema(tool: Tool): ToolInputSchema | null {
    if (!tool.inputSchema) return null;

    return typeof tool.inputSchema === "string"
      ? (this.safeJsonParse(tool.inputSchema) as ToolInputSchema | null)
      : (tool.inputSchema as ToolInputSchema);
  }

  private determineUsabilityStatus(
    metrics: UsabilityMetrics,
  ): AssessmentStatus {
    let score = 0;
    const maxScore = 4;

    if (metrics.toolNamingConvention === "consistent") score++;
    if (metrics.parameterClarity === "clear") score++;
    if (metrics.hasHelpfulDescriptions) score++;
    if (metrics.followsBestPractices) score++;

    const percentage = (score / maxScore) * 100;

    if (percentage >= 75) return "PASS";
    if (percentage >= 50) return "NEED_MORE_INFO";
    return "FAIL";
  }

  private generateExplanation(
    metrics: UsabilityMetrics,
    tools: Tool[],
  ): string {
    const parts: string[] = [];

    parts.push(`Analyzed ${tools.length} tools for usability.`);

    parts.push(`Naming convention: ${metrics.toolNamingConvention}.`);
    parts.push(`Parameter clarity: ${metrics.parameterClarity}.`);

    const features: string[] = [];
    if (metrics.hasHelpfulDescriptions) features.push("helpful descriptions");
    if (metrics.followsBestPractices) features.push("follows best practices");

    if (features.length > 0) {
      parts.push(`Features: ${features.join(", ")}.`);
    } else {
      parts.push("Missing key usability features.");
    }

    return parts.join(" ");
  }

  private generateRecommendations(metrics: UsabilityMetrics): string[] {
    const recommendations: string[] = [];

    if (metrics.toolNamingConvention === "inconsistent") {
      recommendations.push(
        "Adopt a consistent naming convention for all tools",
      );
    }

    if (metrics.parameterClarity !== "clear") {
      recommendations.push("Use descriptive parameter names");
      recommendations.push("Add descriptions for all parameters");
    }

    if (!metrics.hasHelpfulDescriptions) {
      recommendations.push("Provide detailed descriptions for each tool");
    }

    if (!metrics.followsBestPractices) {
      recommendations.push("Implement input validation with constraints");
      recommendations.push("Follow MCP best practices for tool design");
    }

    return recommendations;
  }
}
