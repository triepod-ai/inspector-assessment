/**
 * Tool Classifier
 * Categorizes MCP tools based on name/description to select appropriate security test patterns
 *
 * Validated against broken-mcp server with 16 tools (6 HIGH, 4 MEDIUM, 6 SAFE)
 */

export enum ToolCategory {
  CALCULATOR = "calculator",
  SYSTEM_EXEC = "system_exec",
  DATA_ACCESS = "data_access",
  TOOL_OVERRIDE = "tool_override",
  CONFIG_MODIFIER = "config_modifier",
  URL_FETCHER = "fetcher",
  UNICODE_PROCESSOR = "unicode",
  JSON_PARSER = "parser",
  PACKAGE_INSTALLER = "installer",
  RUG_PULL = "rug_pull",
  SAFE_STORAGE = "safe_storage",
  API_WRAPPER = "api_wrapper",
  GENERIC = "generic",
}

export interface ToolClassification {
  toolName: string;
  categories: ToolCategory[];
  confidence: number; // 0-100
  reasoning: string;
}

/**
 * Classifies MCP tools into vulnerability categories based on naming patterns
 * and descriptions. Uses patterns validated by testing against broken-mcp server.
 */
export class ToolClassifier {
  /**
   * Classify a tool into one or more categories
   * Returns multiple categories if tool matches multiple patterns
   */
  classify(toolName: string, description?: string): ToolClassification {
    const categories: ToolCategory[] = [];
    const confidenceScores: number[] = [];
    const reasons: string[] = [];

    const toolText = `${toolName} ${description || ""}`.toLowerCase();

    // Calculator tools (HIGH RISK)
    // Validated: vulnerable_calculator_tool
    if (
      this.matchesPattern(toolText, [
        /calculator/i,
        /compute/i,
        /math/i,
        /calc/i,
        /eval/i,
        /arithmetic/i,
        /expression/i,
      ])
    ) {
      categories.push(ToolCategory.CALCULATOR);
      confidenceScores.push(90);
      reasons.push("Calculator pattern detected (arithmetic execution risk)");
    }

    // System execution tools (HIGH RISK)
    // Validated: vulnerable_system_exec_tool
    if (
      this.matchesPattern(toolText, [
        /system.*exec/i,
        /exec.*tool/i,
        /command/i,
        /shell/i,
        /\brun\b/i,
        /execute/i,
        /process/i,
      ])
    ) {
      categories.push(ToolCategory.SYSTEM_EXEC);
      confidenceScores.push(95);
      reasons.push(
        "System execution pattern detected (command injection risk)",
      );
    }

    // Data access/leak tools (HIGH RISK)
    // Validated: vulnerable_data_leak_tool
    if (
      this.matchesPattern(toolText, [
        /leak/i,
        /\bdata\b/i,
        /show/i,
        /\bget\b/i,
        /\blist\b/i,
        /display/i,
        /\benv/i,
        /secret/i,
        /\bkey\b/i,
        /credential/i,
        /exfiltrat/i,
      ])
    ) {
      categories.push(ToolCategory.DATA_ACCESS);
      confidenceScores.push(85);
      reasons.push("Data access pattern detected (data exfiltration risk)");
    }

    // Tool override/shadowing (HIGH RISK)
    // Validated: vulnerable_tool_override_tool
    if (
      this.matchesPattern(toolText, [
        /override/i,
        /shadow/i,
        /poison/i,
        /create.*tool/i,
        /register.*tool/i,
        /define.*tool/i,
        /tool.*creator/i,
        /add.*tool/i,
      ])
    ) {
      categories.push(ToolCategory.TOOL_OVERRIDE);
      confidenceScores.push(92);
      reasons.push("Tool override pattern detected (shadowing/poisoning risk)");
    }

    // Config modification tools (HIGH RISK)
    // Validated: vulnerable_config_modifier_tool
    if (
      this.matchesPattern(toolText, [
        /config/i,
        /setting/i,
        /modifier/i,
        /\badmin\b/i,
        /privilege/i,
        /permission/i,
        /configure/i,
        /drift/i,
      ])
    ) {
      categories.push(ToolCategory.CONFIG_MODIFIER);
      confidenceScores.push(88);
      reasons.push(
        "Config modification pattern detected (configuration drift risk)",
      );
    }

    // URL fetching tools (HIGH RISK)
    // Validated: vulnerable_fetcher_tool
    if (
      this.matchesPattern(toolText, [
        /fetch/i,
        /\burl\b/i,
        /http/i,
        /download/i,
        /load/i,
        /retrieve/i,
        /\bget\b.*url/i,
        /external/i,
      ])
    ) {
      categories.push(ToolCategory.URL_FETCHER);
      confidenceScores.push(87);
      reasons.push(
        "URL fetcher pattern detected (indirect prompt injection risk)",
      );
    }

    // Unicode processing tools (MEDIUM RISK)
    // Validated: vulnerable_unicode_processor_tool
    if (
      this.matchesPattern(toolText, [
        /unicode/i,
        /encode/i,
        /decode/i,
        /charset/i,
        /utf/i,
        /hex/i,
        /escape/i,
      ])
    ) {
      categories.push(ToolCategory.UNICODE_PROCESSOR);
      confidenceScores.push(75);
      reasons.push("Unicode processor pattern detected (bypass encoding risk)");
    }

    // JSON/nested parsing tools (MEDIUM RISK)
    // Validated: vulnerable_nested_parser_tool
    if (
      this.matchesPattern(toolText, [
        /parser/i,
        /parse/i,
        /json/i,
        /xml/i,
        /yaml/i,
        /nested/i,
        /deserialize/i,
        /unmarshal/i,
      ])
    ) {
      categories.push(ToolCategory.JSON_PARSER);
      confidenceScores.push(78);
      reasons.push(
        "JSON/nested parser pattern detected (nested injection risk)",
      );
    }

    // Package installation tools (MEDIUM RISK)
    // Validated: vulnerable_package_installer_tool
    if (
      this.matchesPattern(toolText, [
        /install/i,
        /package/i,
        /\bnpm\b/i,
        /\bpip\b/i,
        /dependency/i,
        /module/i,
        /library/i,
        /\bgem\b/i,
      ])
    ) {
      categories.push(ToolCategory.PACKAGE_INSTALLER);
      confidenceScores.push(70);
      reasons.push("Package installer pattern detected (typosquatting risk)");
    }

    // Rug pull (behavioral change over time) (MEDIUM RISK)
    // Validated: vulnerable_rug_pull_tool
    if (
      this.matchesPattern(toolText, [
        /rug.*pull/i,
        /trust/i,
        /behavior.*change/i,
        /malicious.*after/i,
        /invocation.*count/i,
      ])
    ) {
      categories.push(ToolCategory.RUG_PULL);
      confidenceScores.push(80);
      reasons.push("Rug pull pattern detected (behavioral change risk)");
    }

    // API wrapper tools (SAFE - data passing, not code execution)
    // These tools call external APIs and return data as text, not execute it as code
    // Examples: Firecrawl (scrape, crawl, search), HTTP clients, REST/GraphQL clients
    if (
      this.matchesPattern(toolText, [
        /firecrawl/i,
        /\bscrape\b/i,
        /\bcrawl\b/i,
        /web.*scraping/i,
        /api.*wrapper/i,
        /http.*client/i,
        /web.*client/i,
        /rest.*client/i,
        /graphql.*client/i,
        /fetch.*web.*content/i,
      ])
    ) {
      categories.push(ToolCategory.API_WRAPPER);
      confidenceScores.push(95);
      reasons.push(
        "API wrapper pattern detected (safe data passing, not code execution)",
      );
    }

    // Safe storage tools (CONTROL GROUP - should never show vulnerabilities)
    // Validated: safe_storage_tool_mcp, safe_search_tool_mcp, safe_list_tool_mcp,
    //            safe_info_tool_mcp, safe_echo_tool_mcp, safe_validate_tool_mcp
    if (
      this.matchesPattern(toolText, [
        /safe.*storage/i,
        /safe.*search/i,
        /safe.*list/i,
        /safe.*info/i,
        /safe.*echo/i,
        /safe.*validate/i,
        /safe.*tool/i,
      ])
    ) {
      categories.push(ToolCategory.SAFE_STORAGE);
      confidenceScores.push(99);
      reasons.push(
        "Safe tool pattern detected (control group - should be safe)",
      );
    }

    // Default to generic if no specific matches
    if (categories.length === 0) {
      categories.push(ToolCategory.GENERIC);
      confidenceScores.push(50);
      reasons.push("No specific pattern match, using generic tests");
    }

    // Calculate overall confidence (average of matched pattern confidences)
    const avgConfidence =
      confidenceScores.reduce((a, b) => a + b, 0) / confidenceScores.length;

    return {
      toolName,
      categories,
      confidence: Math.round(avgConfidence),
      reasoning: reasons.join("; "),
    };
  }

  /**
   * Check if text matches any of the provided patterns
   */
  private matchesPattern(text: string, patterns: RegExp[]): boolean {
    return patterns.some((pattern) => pattern.test(text));
  }

  /**
   * Get all tool categories (for testing/debugging)
   */
  static getAllCategories(): ToolCategory[] {
    return Object.values(ToolCategory);
  }

  /**
   * Get risk level for a category
   */
  static getRiskLevel(category: ToolCategory): "HIGH" | "MEDIUM" | "LOW" {
    const highRiskCategories = [
      ToolCategory.CALCULATOR,
      ToolCategory.SYSTEM_EXEC,
      ToolCategory.DATA_ACCESS,
      ToolCategory.TOOL_OVERRIDE,
      ToolCategory.CONFIG_MODIFIER,
      ToolCategory.URL_FETCHER,
    ];

    const mediumRiskCategories = [
      ToolCategory.UNICODE_PROCESSOR,
      ToolCategory.JSON_PARSER,
      ToolCategory.PACKAGE_INSTALLER,
      ToolCategory.RUG_PULL,
    ];

    const lowRiskCategories = [
      ToolCategory.API_WRAPPER,
      ToolCategory.SAFE_STORAGE,
      ToolCategory.GENERIC,
    ];

    if (highRiskCategories.includes(category)) return "HIGH";
    if (mediumRiskCategories.includes(category)) return "MEDIUM";
    if (lowRiskCategories.includes(category)) return "LOW";
    return "LOW";
  }

  /**
   * Classify multiple tools at once
   */
  classifyBatch(
    tools: Array<{ name: string; description?: string }>,
  ): ToolClassification[] {
    return tools.map((tool) => this.classify(tool.name, tool.description));
  }
}
