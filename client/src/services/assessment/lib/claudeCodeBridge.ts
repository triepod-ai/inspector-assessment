/**
 * Claude Code Bridge
 *
 * Provides integration with Claude Code CLI for intelligent analysis tasks.
 * Uses shell execution with `claude --print` for stateless reasoning.
 *
 * This bridge enables:
 * - Intelligent test parameter generation
 * - Semantic AUP violation analysis
 * - Tool behavior inference for annotation validation
 * - Documentation quality assessment
 */

import { execFileSync, execSync } from "child_process";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { AUPCategory } from "@/lib/assessmentTypes";

/**
 * Response from Claude Code execution
 */
export interface ClaudeCodeResponse {
  success: boolean;
  output: string;
  error?: string;
  executionTimeMs?: number;
}

/**
 * Configuration for Claude Code Bridge
 */
export interface ClaudeCodeBridgeConfig {
  enabled: boolean;
  timeout?: number; // Timeout in milliseconds (default: 30000)
  maxRetries?: number; // Number of retries on failure (default: 1)
  features: {
    intelligentTestGeneration?: boolean;
    aupSemanticAnalysis?: boolean;
    behaviorInference?: boolean;
    annotationInference?: boolean; // Alias for behaviorInference (used by ToolAnnotationAssessor)
    documentationAssessment?: boolean;
    documentationQuality?: boolean; // Alias for documentationAssessment (used by ClaudeCodeConfig)
  };
}

/**
 * Context for AUP violation analysis
 */
export interface AUPViolationContext {
  toolName: string;
  toolDescription: string;
  category: AUPCategory;
  categoryName: string;
  location: string;
}

/**
 * Result of AUP semantic analysis
 */
export interface AUPSemanticAnalysisResult {
  isViolation: boolean; // Primary property used by consumers
  isConfirmedViolation: boolean; // Alias for backwards compatibility
  confidence: number; // 0-100
  reasoning: string;
  category: AUPCategory;
  suggestedAction: "block" | "flag_for_review" | "allow";
  contextFactors: string[];
}

/**
 * Result of tool behavior inference
 */
export interface BehaviorInferenceResult {
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  confidence: number; // 0-100
  reasoning: string;
  suggestedAnnotations: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    idempotentHint?: boolean;
  };
  misalignmentDetected: boolean;
  misalignmentDetails?: string;
}

/**
 * Result of intelligent test generation
 */
export interface TestGenerationResult {
  scenarios: Array<{
    name: string;
    description: string;
    params: Record<string, unknown>;
    expectedBehavior: string;
    category: "happy_path" | "edge_case" | "boundary" | "error_case";
  }>;
  reasoning: string;
}

/**
 * Default configuration with minimal features
 */
export const DEFAULT_CLAUDE_CODE_CONFIG: ClaudeCodeBridgeConfig = {
  enabled: false,
  timeout: 30000,
  maxRetries: 1,
  features: {
    intelligentTestGeneration: false,
    aupSemanticAnalysis: false,
    behaviorInference: false,
    annotationInference: false,
    documentationAssessment: false,
    documentationQuality: false,
  },
};

/**
 * Full configuration with all features enabled
 */
export const FULL_CLAUDE_CODE_CONFIG: ClaudeCodeBridgeConfig = {
  enabled: true,
  timeout: 60000,
  maxRetries: 2,
  features: {
    intelligentTestGeneration: true,
    aupSemanticAnalysis: true,
    behaviorInference: true,
    annotationInference: true,
    documentationAssessment: true,
    documentationQuality: true,
  },
};

/**
 * Claude Code Bridge
 * Executes Claude CLI for intelligent analysis during MCP assessments
 */
export class ClaudeCodeBridge {
  private config: ClaudeCodeBridgeConfig;
  private isAvailable: boolean = false;

  constructor(config: ClaudeCodeBridgeConfig) {
    this.config = config;
    this.isAvailable = this.checkClaudeAvailability();

    if (!this.isAvailable) {
      console.warn(
        "[ClaudeCodeBridge] Claude CLI not available - features will be disabled",
      );
    }
  }

  /**
   * Check if a specific feature is enabled
   * Note: annotationInference is an alias for behaviorInference
   */
  isFeatureEnabled(feature: keyof ClaudeCodeBridgeConfig["features"]): boolean {
    if (!this.isAvailable || !this.config.enabled) {
      return false;
    }

    // annotationInference is an alias for behaviorInference
    if (feature === "annotationInference") {
      return (
        this.config.features.annotationInference === true ||
        this.config.features.behaviorInference === true
      );
    }

    return this.config.features[feature] === true;
  }

  /**
   * Check if Claude CLI is available on the system
   */
  private checkClaudeAvailability(): boolean {
    try {
      execSync("which claude", { stdio: "pipe", timeout: 5000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Execute Claude CLI with a prompt
   * Uses execFileSync to avoid shell injection vulnerabilities
   */
  private executeClaudeCommand(prompt: string): ClaudeCodeResponse {
    const startTime = Date.now();

    try {
      const timeout = this.config.timeout || 30000;

      // Use execFileSync with argument array to prevent shell injection
      // This avoids spawning a shell and passes arguments directly
      const output = execFileSync("claude", ["--print", prompt], {
        encoding: "utf-8",
        timeout,
        stdio: ["pipe", "pipe", "pipe"],
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      });

      return {
        success: true,
        output: output.trim(),
        executionTimeMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        success: false,
        output: "",
        error: error instanceof Error ? error.message : String(error),
        executionTimeMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Execute with retries
   */
  private async executeWithRetry(prompt: string): Promise<ClaudeCodeResponse> {
    const maxRetries = this.config.maxRetries || 1;
    let lastError: ClaudeCodeResponse | null = null;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const response = this.executeClaudeCommand(prompt);

      if (response.success) {
        return response;
      }

      lastError = response;

      // Wait before retry (exponential backoff)
      if (attempt < maxRetries) {
        await new Promise((resolve) =>
          setTimeout(resolve, 1000 * Math.pow(2, attempt)),
        );
      }
    }

    return lastError!;
  }

  /**
   * Parse JSON from Claude response, handling markdown code blocks
   */
  private parseJsonResponse<T>(response: ClaudeCodeResponse): T | null {
    if (!response.success) {
      return null;
    }

    try {
      let jsonStr = response.output;

      // Handle markdown code blocks
      const jsonMatch = jsonStr.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (jsonMatch) {
        jsonStr = jsonMatch[1].trim();
      }

      return JSON.parse(jsonStr) as T;
    } catch {
      console.warn("[ClaudeCodeBridge] Failed to parse JSON response");
      return null;
    }
  }

  /**
   * Analyze an AUP violation for false positives using semantic analysis
   * @param matchedText - The text that matched the AUP pattern
   * @param context - Context about the violation
   */
  async analyzeAUPViolation(
    matchedText: string,
    context: AUPViolationContext,
  ): Promise<AUPSemanticAnalysisResult | null> {
    if (!this.isFeatureEnabled("aupSemanticAnalysis")) {
      return null;
    }

    const prompt = `You are analyzing a potential AUP (Acceptable Use Policy) violation detected in an MCP server tool.

CONTEXT:
- Flagged text: "${matchedText}"
- Tool name: ${context.toolName}
- Tool description: ${context.toolDescription || "No description"}
- Category: ${context.category} (${context.categoryName})
- Location: ${context.location}

TASK:
Determine if this is a TRUE violation or a FALSE POSITIVE. Consider:
1. Is this a legitimate security/defensive tool?
2. Is there appropriate context (disclaimers, educational purpose)?
3. Does the tool's purpose justify the flagged content?

Respond with JSON only:
{
  "isViolation": boolean,
  "confidence": number (0-100),
  "reasoning": "explanation",
  "category": "${context.category}",
  "suggestedAction": "block" | "flag_for_review" | "allow",
  "contextFactors": ["factor1", "factor2"]
}`;

    const response = await this.executeWithRetry(prompt);
    const result = this.parseJsonResponse<AUPSemanticAnalysisResult>(response);

    // Normalize: ensure both isViolation and isConfirmedViolation are present
    if (result) {
      result.isViolation = result.isViolation ?? result.isConfirmedViolation;
      result.isConfirmedViolation =
        result.isConfirmedViolation ?? result.isViolation;
    }

    return result;
  }

  /**
   * Infer expected tool behavior for annotation validation
   */
  async inferToolBehavior(
    tool: Tool,
    currentAnnotations?: {
      readOnlyHint?: boolean;
      destructiveHint?: boolean;
      idempotentHint?: boolean;
    },
  ): Promise<BehaviorInferenceResult | null> {
    // Check both behaviorInference and annotationInference feature flags
    if (
      !this.isFeatureEnabled("behaviorInference") &&
      !this.isFeatureEnabled("annotationInference")
    ) {
      return null;
    }

    const annotationsStr = currentAnnotations
      ? JSON.stringify(currentAnnotations, null, 2)
      : "No annotations provided";

    const prompt = `You are analyzing an MCP tool to infer its expected behavior and validate annotations.

TOOL:
- Name: ${tool.name}
- Description: ${tool.description || "No description provided"}
- Input Schema: ${JSON.stringify(tool.inputSchema, null, 2)}

CURRENT ANNOTATIONS:
${annotationsStr}

TASK:
Analyze the tool and determine:
1. Is this tool read-only (doesn't modify state)?
2. Is this tool destructive (can delete/destroy data)?
3. Do the current annotations match expected behavior?

Respond with JSON only:
{
  "expectedReadOnly": boolean,
  "expectedDestructive": boolean,
  "confidence": number (0-100),
  "reasoning": "explanation",
  "suggestedAnnotations": {
    "readOnlyHint": boolean,
    "destructiveHint": boolean,
    "idempotentHint": boolean
  },
  "misalignmentDetected": boolean,
  "misalignmentDetails": "details if misaligned, null otherwise"
}`;

    const response = await this.executeWithRetry(prompt);
    return this.parseJsonResponse<BehaviorInferenceResult>(response);
  }

  /**
   * Generate intelligent test scenarios for a tool
   */
  async generateTestScenarios(
    tool: Tool,
    existingScenarios: number,
  ): Promise<TestGenerationResult | null> {
    if (!this.isFeatureEnabled("intelligentTestGeneration")) {
      return null;
    }

    const prompt = `You are generating test scenarios for an MCP tool.

TOOL:
- Name: ${tool.name}
- Description: ${tool.description || "No description provided"}
- Input Schema: ${JSON.stringify(tool.inputSchema, null, 2)}

EXISTING SCENARIOS: ${existingScenarios} already generated via schema analysis

TASK:
Generate 3-5 additional test scenarios that would catch edge cases the schema-based generator might miss. Focus on:
1. Real-world usage patterns
2. Boundary conditions
3. Error conditions
4. Security-relevant inputs

Respond with JSON only:
{
  "scenarios": [
    {
      "name": "scenario_name",
      "description": "what this tests",
      "params": { "param1": "value1" },
      "expectedBehavior": "what should happen",
      "category": "happy_path" | "edge_case" | "boundary" | "error_case"
    }
  ],
  "reasoning": "why these scenarios are valuable"
}`;

    const response = await this.executeWithRetry(prompt);
    return this.parseJsonResponse<TestGenerationResult>(response);
  }

  /**
   * Generate test parameters for a tool
   * This returns just the parameter sets, used by TestDataGenerator
   */
  async generateTestParameters(
    tool: Tool,
  ): Promise<Record<string, unknown>[] | null> {
    if (!this.isFeatureEnabled("intelligentTestGeneration")) {
      return null;
    }

    const prompt = `You are generating test parameters for an MCP tool.

TOOL:
- Name: ${tool.name}
- Description: ${tool.description || "No description provided"}
- Input Schema: ${JSON.stringify(tool.inputSchema, null, 2)}

TASK:
Generate 3-5 sets of valid test parameters that exercise different scenarios:
1. Happy path / typical usage
2. Edge cases (empty strings, zeros, minimum values)
3. Boundary values (max length strings, large numbers)
4. Alternative valid inputs

Return ONLY valid parameter sets (no intentionally invalid inputs).

Respond with JSON only:
{
  "parameters": [
    { "param1": "value1", "param2": 123 },
    { "param1": "", "param2": 0 },
    { "param1": "very long string...", "param2": 999999 }
  ]
}`;

    const response = await this.executeWithRetry(prompt);
    const result = this.parseJsonResponse<{
      parameters: Record<string, unknown>[];
    }>(response);
    return result?.parameters || null;
  }

  /**
   * Assess documentation quality
   */
  async assessDocumentation(
    readmeContent: string,
    toolCount: number,
  ): Promise<{
    score: number;
    issues: string[];
    suggestions: string[];
  } | null> {
    if (!this.isFeatureEnabled("documentationAssessment")) {
      return null;
    }

    // Truncate very long READMEs
    const truncatedReadme =
      readmeContent.length > 10000
        ? readmeContent.substring(0, 10000) + "\n...[truncated]..."
        : readmeContent;

    const prompt = `You are assessing the documentation quality of an MCP server.

README CONTENT:
${truncatedReadme}

SERVER INFO:
- Number of tools: ${toolCount}

TASK:
Assess the documentation quality. Check for:
1. Clear description of what the server does
2. Installation instructions
3. Configuration requirements
4. Tool documentation
5. Examples of usage
6. Security considerations

Respond with JSON only:
{
  "score": number (0-100),
  "issues": ["issue1", "issue2"],
  "suggestions": ["suggestion1", "suggestion2"]
}`;

    const response = await this.executeWithRetry(prompt);
    return this.parseJsonResponse<{
      score: number;
      issues: string[];
      suggestions: string[];
    }>(response);
  }
}
