/**
 * Cross-Capability Security Assessor Module
 * Tests interactions between tools, resources, and prompts for security vulnerabilities
 *
 * Tests include:
 * - Tool->Resource access patterns (can a tool expose unauthorized resources?)
 * - Prompt->Tool interaction (can a prompt trigger dangerous tool calls?)
 * - Resource->Tool data flow (is sensitive resource data passed to tools?)
 * - Privilege escalation across capabilities
 */

import {
  CrossCapabilitySecurityAssessment,
  CrossCapabilityTestResult,
  AssessmentStatus,
  JSONSchema7,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import {
  AssessmentContext,
  MCPResource,
  MCPPrompt,
} from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

// Tool patterns that indicate resource access capability
const RESOURCE_ACCESS_TOOL_PATTERNS = [
  /read[_-]?file/i,
  /get[_-]?file/i,
  /fetch[_-]?resource/i,
  /load[_-]?data/i,
  /access[_-]?resource/i,
  /retrieve/i,
  /download/i,
];

// Tool patterns that indicate dangerous operations
const DANGEROUS_TOOL_PATTERNS = [
  /delete/i,
  /remove/i,
  /drop/i,
  /exec(ute)?/i,
  /run[_-]?command/i,
  /shell/i,
  /system/i,
  /eval/i,
  /write/i,
  /modify/i,
  /update/i,
  /create/i,
  /admin/i,
  /config/i,
];

// Sensitive resource patterns
const SENSITIVE_RESOURCE_PATTERNS = [
  /credential/i,
  /secret/i,
  /password/i,
  /token/i,
  /key/i,
  /config/i,
  /\.env/i,
  /auth/i,
];

// Prompt patterns that could trigger tool execution
const TOOL_TRIGGER_PATTERNS = [
  /execute/i,
  /run/i,
  /call/i,
  /invoke/i,
  /trigger/i,
  /perform/i,
  /do the following/i,
  /carry out/i,
];

export class CrossCapabilitySecurityAssessor extends BaseAssessor {
  async assess(
    context: AssessmentContext,
  ): Promise<CrossCapabilitySecurityAssessment> {
    const results: CrossCapabilityTestResult[] = [];

    // Get all capabilities
    const tools = context.tools || [];
    const resources = context.resources || [];
    const prompts = context.prompts || [];

    this.logger.info(
      `Testing cross-capability security: ${tools.length} tools, ${resources.length} resources, ${prompts.length} prompts`,
    );

    // Test 1: Tool->Resource access patterns
    const toolResourceResults = this.testToolResourceAccess(tools, resources);
    results.push(...toolResourceResults);

    // Test 2: Prompt->Tool interaction security
    const promptToolResults = this.testPromptToolInteraction(prompts, tools);
    results.push(...promptToolResults);

    // Test 3: Resource->Tool data flow
    const dataFlowResults = this.testResourceToolDataFlow(
      resources,
      tools,
      context,
    );
    results.push(...dataFlowResults);

    // Test 4: Privilege escalation paths
    const escalationResults = this.testPrivilegeEscalation(
      tools,
      resources,
      prompts,
    );
    results.push(...escalationResults);

    // Calculate metrics
    const vulnerabilitiesFound = results.filter((r) => r.vulnerable).length;
    const privilegeEscalationRisks = results.filter(
      (r) => r.testType === "privilege_escalation" && r.vulnerable,
    ).length;
    const dataFlowViolations = results.filter(
      (r) =>
        (r.testType === "resource_to_tool" ||
          r.testType === "tool_to_resource") &&
        r.vulnerable,
    ).length;

    // Determine status
    const status = this.determineCrossCapabilityStatus(
      vulnerabilitiesFound,
      privilegeEscalationRisks,
    );

    // Generate explanation and recommendations
    const explanation = this.generateExplanation(results, vulnerabilitiesFound);
    const recommendations = this.generateRecommendations(results);

    return {
      testsRun: results.length,
      vulnerabilitiesFound,
      privilegeEscalationRisks,
      dataFlowViolations,
      results,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Test if tools can access resources in unauthorized ways
   */
  private testToolResourceAccess(
    tools: Tool[],
    resources: MCPResource[],
  ): CrossCapabilityTestResult[] {
    const results: CrossCapabilityTestResult[] = [];

    // Find tools that can access resources
    const resourceAccessTools = tools.filter((tool) =>
      RESOURCE_ACCESS_TOOL_PATTERNS.some(
        (pattern) =>
          pattern.test(tool.name) || pattern.test(tool.description || ""),
      ),
    );

    // Find sensitive resources
    const sensitiveResources = resources.filter((resource) =>
      SENSITIVE_RESOURCE_PATTERNS.some(
        (pattern) =>
          pattern.test(resource.uri) ||
          pattern.test(resource.name || "") ||
          pattern.test(resource.description || ""),
      ),
    );

    this.testCount += resourceAccessTools.length * sensitiveResources.length;

    // Test each combination
    for (const tool of resourceAccessTools) {
      for (const resource of sensitiveResources) {
        const hasPathParameter = this.toolHasPathParameter(tool);

        results.push({
          testType: "tool_to_resource",
          sourceCapability: `tool:${tool.name}`,
          targetCapability: `resource:${resource.uri}`,
          vulnerable: hasPathParameter, // If tool has path param, it could access sensitive resources
          evidence: hasPathParameter
            ? `Tool ${tool.name} has path/file parameter that could access sensitive resource ${resource.uri}`
            : undefined,
          riskLevel: hasPathParameter ? "HIGH" : "LOW",
          description: `Tool ${tool.name} access to resource ${resource.uri}`,
          // NEW: Enrichment fields for Claude analysis (Issue #9)
          confidence: hasPathParameter ? "high" : "low",
          attackChain: hasPathParameter
            ? [`tool:${tool.name}`, `resource:${resource.uri}`]
            : undefined,
        });
      }
    }

    return results;
  }

  /**
   * Test if prompts could trigger dangerous tool calls
   */
  private testPromptToolInteraction(
    prompts: MCPPrompt[],
    tools: Tool[],
  ): CrossCapabilityTestResult[] {
    const results: CrossCapabilityTestResult[] = [];

    // Find dangerous tools
    const dangerousTools = tools.filter((tool) =>
      DANGEROUS_TOOL_PATTERNS.some(
        (pattern) =>
          pattern.test(tool.name) || pattern.test(tool.description || ""),
      ),
    );

    // Find prompts that mention tool execution
    const toolTriggerPrompts = prompts.filter(
      (prompt) =>
        TOOL_TRIGGER_PATTERNS.some(
          (pattern) =>
            pattern.test(prompt.name) || pattern.test(prompt.description || ""),
        ) ||
        prompt.arguments?.some((arg) =>
          TOOL_TRIGGER_PATTERNS.some(
            (pattern) =>
              pattern.test(arg.name) || pattern.test(arg.description || ""),
          ),
        ),
    );

    this.testCount += toolTriggerPrompts.length * dangerousTools.length;

    for (const prompt of toolTriggerPrompts) {
      for (const tool of dangerousTools) {
        // Check if prompt could potentially reference this tool
        const promptText =
          `${prompt.name} ${prompt.description || ""} ${prompt.arguments?.map((a) => a.name).join(" ") || ""}`.toLowerCase();
        const toolName = tool.name.toLowerCase();

        const directReference = promptText.includes(toolName);
        const indirectTrigger = this.promptCouldTriggerTool(prompt, tool);
        const couldTrigger = directReference || indirectTrigger;

        results.push({
          testType: "prompt_to_tool",
          sourceCapability: `prompt:${prompt.name}`,
          targetCapability: `tool:${tool.name}`,
          vulnerable: couldTrigger,
          evidence: couldTrigger
            ? `Prompt ${prompt.name} could trigger dangerous tool ${tool.name}`
            : undefined,
          riskLevel: couldTrigger ? "HIGH" : "LOW",
          description: `Prompt ${prompt.name} interaction with tool ${tool.name}`,
          // NEW: Enrichment fields for Claude analysis (Issue #9)
          confidence: directReference
            ? "high"
            : indirectTrigger
              ? "medium"
              : "low",
          attackChain: couldTrigger
            ? [`prompt:${prompt.name}`, `tool:${tool.name}`]
            : undefined,
        });
      }
    }

    return results;
  }

  /**
   * Test if resource data could be passed to tools in unsafe ways
   */
  private testResourceToolDataFlow(
    resources: MCPResource[],
    tools: Tool[],
    _context: AssessmentContext,
  ): CrossCapabilityTestResult[] {
    const results: CrossCapabilityTestResult[] = [];

    // Find sensitive resources
    const sensitiveResources = resources.filter((resource) =>
      SENSITIVE_RESOURCE_PATTERNS.some(
        (pattern) =>
          pattern.test(resource.uri) ||
          pattern.test(resource.name || "") ||
          pattern.test(resource.description || ""),
      ),
    );

    // Find tools that could exfiltrate data
    const exfiltrationTools = tools.filter(
      (tool) =>
        /send|post|upload|email|notify|webhook|http|request|api/i.test(
          tool.name,
        ) ||
        /send|post|upload|email|notify|webhook|http|request|api/i.test(
          tool.description || "",
        ),
    );

    this.testCount += sensitiveResources.length * exfiltrationTools.length;

    for (const resource of sensitiveResources) {
      for (const tool of exfiltrationTools) {
        // Check if tool has parameters that could accept resource content
        const hasContentParam = this.toolHasContentParameter(tool);

        // Identify sensitive fields from resource URI/name for enrichment
        const sensitiveFields = this.extractSensitiveFields(resource);

        // Determine exfiltration method from tool name/description
        const exfiltrationMethod = this.determineExfiltrationMethod(tool);

        results.push({
          testType: "resource_to_tool",
          sourceCapability: `resource:${resource.uri}`,
          targetCapability: `tool:${tool.name}`,
          vulnerable: hasContentParam,
          evidence: hasContentParam
            ? `Sensitive resource ${resource.uri} content could be exfiltrated via tool ${tool.name}`
            : undefined,
          riskLevel: hasContentParam ? "HIGH" : "MEDIUM",
          description: `Resource ${resource.uri} data flow to tool ${tool.name}`,
          // NEW: Enrichment fields for Claude analysis (Issue #9)
          confidence: hasContentParam ? "high" : "low",
          attackChain: hasContentParam
            ? [`resource:${resource.uri}`, `tool:${tool.name}`]
            : undefined,
          dataExfiltrationRisk: hasContentParam
            ? {
                sensitiveFields,
                exfiltrationMethod,
              }
            : undefined,
        });
      }
    }

    return results;
  }

  /**
   * Extract sensitive field types from resource metadata
   */
  private extractSensitiveFields(resource: MCPResource): string[] {
    const fields: string[] = [];
    const text =
      `${resource.uri} ${resource.name || ""} ${resource.description || ""}`.toLowerCase();

    if (/password|passwd/i.test(text)) fields.push("password");
    if (/token/i.test(text)) fields.push("token");
    if (/key|apikey/i.test(text)) fields.push("api_key");
    if (/secret/i.test(text)) fields.push("secret");
    if (/credential/i.test(text)) fields.push("credentials");
    if (/auth/i.test(text)) fields.push("auth_data");
    if (/config/i.test(text)) fields.push("config");
    if (/\.env/i.test(text)) fields.push("environment_variables");

    return fields.length > 0 ? fields : ["sensitive_data"];
  }

  /**
   * Determine exfiltration method from tool characteristics
   */
  private determineExfiltrationMethod(tool: Tool): string {
    const text = `${tool.name} ${tool.description || ""}`.toLowerCase();

    if (/email/i.test(text)) return "email";
    if (/webhook/i.test(text)) return "webhook";
    if (/http|request|api/i.test(text)) return "http_request";
    if (/upload/i.test(text)) return "file_upload";
    if (/send|post/i.test(text)) return "network_send";
    if (/notify/i.test(text)) return "notification";

    return "unknown";
  }

  /**
   * Test for privilege escalation paths
   */
  private testPrivilegeEscalation(
    tools: Tool[],
    resources: MCPResource[],
    prompts: MCPPrompt[],
  ): CrossCapabilityTestResult[] {
    const results: CrossCapabilityTestResult[] = [];

    // Pattern: Low-privilege prompt -> High-privilege tool
    const readOnlyPrompts = prompts.filter(
      (p) =>
        /read|view|list|get|show|display/i.test(p.name) ||
        /read|view|list|get|show|display/i.test(p.description || ""),
    );

    const writeTools = tools.filter(
      (t) =>
        /write|delete|modify|update|create|drop|exec/i.test(t.name) ||
        /write|delete|modify|update|create|drop|exec/i.test(
          t.description || "",
        ),
    );

    this.testCount += readOnlyPrompts.length;

    for (const prompt of readOnlyPrompts) {
      // Check if prompt arguments could be used to call write tools
      const hasOpenArg = prompt.arguments?.some(
        (arg) =>
          /action|command|operation|tool|function/i.test(arg.name) ||
          /action|command|operation|tool|function/i.test(arg.description || ""),
      );

      if (hasOpenArg && writeTools.length > 0) {
        // Build attack chain for prompt -> tool escalation
        const affectedTools = writeTools.map((t) => t.name).slice(0, 3);

        results.push({
          testType: "privilege_escalation",
          sourceCapability: `prompt:${prompt.name}`,
          targetCapability: `tools:write_operations`,
          vulnerable: true,
          evidence: `Read-only prompt ${prompt.name} has arguments that could specify write operations`,
          riskLevel: "HIGH",
          description: `Privilege escalation path from ${prompt.name} to write tools`,
          // NEW: Enrichment fields for Claude analysis (Issue #9)
          privilegeEscalationVector: "prompt_argument_injection",
          attackChain: [
            `prompt:${prompt.name}`,
            "argument_manipulation",
            ...affectedTools.map((t) => `tool:${t}`),
          ],
          confidence: "high",
        });
      }
    }

    // Pattern: Public resource -> Admin tool
    const publicResources = resources.filter(
      (r) =>
        /public|shared|common/i.test(r.uri) ||
        /public|shared|common/i.test(r.name || ""),
    );

    const adminTools = tools.filter(
      (t) =>
        /admin|config|system|manage|control/i.test(t.name) ||
        /admin|config|system|manage|control/i.test(t.description || ""),
    );

    this.testCount += publicResources.length;

    for (const resource of publicResources) {
      for (const tool of adminTools) {
        // Check if resource content could be used as tool input
        const toolAcceptsData = this.toolHasContentParameter(tool);

        if (toolAcceptsData) {
          results.push({
            testType: "privilege_escalation",
            sourceCapability: `resource:${resource.uri}`,
            targetCapability: `tool:${tool.name}`,
            vulnerable: true,
            evidence: `Public resource ${resource.uri} content could influence admin tool ${tool.name}`,
            riskLevel: "HIGH",
            description: `Privilege escalation path from ${resource.uri} to ${tool.name}`,
            // NEW: Enrichment fields for Claude analysis (Issue #9)
            privilegeEscalationVector: "resource_content_injection",
            attackChain: [
              `resource:${resource.uri}`,
              "content_read",
              "data_flow",
              `tool:${tool.name}`,
            ],
            confidence: "high",
          });
        }
      }
    }

    return results;
  }

  private toolHasPathParameter(tool: Tool): boolean {
    const schema = tool.inputSchema as JSONSchema7 | undefined;
    if (!schema?.properties) return false;

    return Object.entries(schema.properties).some(
      ([name, prop]: [string, JSONSchema7]) =>
        /path|file|uri|url|location|directory|folder/i.test(name) ||
        /path|file|uri|url|location|directory|folder/i.test(
          prop.description || "",
        ),
    );
  }

  private toolHasContentParameter(tool: Tool): boolean {
    const schema = tool.inputSchema as JSONSchema7 | undefined;
    if (!schema?.properties) return false;

    return Object.entries(schema.properties).some(
      ([name, prop]: [string, JSONSchema7]) =>
        /content|data|body|text|message|payload/i.test(name) ||
        /content|data|body|text|message|payload/i.test(prop.description || ""),
    );
  }

  private promptCouldTriggerTool(prompt: MCPPrompt, tool: Tool): boolean {
    // Check if prompt has action/tool arguments
    const hasActionArg = prompt.arguments?.some(
      (arg) =>
        /action|tool|function|command|operation/i.test(arg.name) ||
        /action|tool|function|command|operation/i.test(arg.description || ""),
    );

    // Check if prompt description mentions tool-like operations
    const descMentionsTool = tool.name
      .toLowerCase()
      .split(/[_-]/)
      .some(
        (word) =>
          word.length > 2 &&
          (prompt.description || "").toLowerCase().includes(word),
      );

    return hasActionArg || descMentionsTool;
  }

  private determineCrossCapabilityStatus(
    vulnerabilitiesFound: number,
    privilegeEscalationRisks: number,
  ): AssessmentStatus {
    if (privilegeEscalationRisks > 0) return "FAIL";
    if (vulnerabilitiesFound > 2) return "FAIL";
    if (vulnerabilitiesFound > 0) return "NEED_MORE_INFO";
    return "PASS";
  }

  private generateExplanation(
    results: CrossCapabilityTestResult[],
    vulnerabilitiesFound: number,
  ): string {
    const parts: string[] = [];

    parts.push(`Tested ${results.length} cross-capability interaction(s).`);

    if (vulnerabilitiesFound > 0) {
      parts.push(`Found ${vulnerabilitiesFound} potential vulnerability(ies).`);

      const byType = results.reduce(
        (acc, r) => {
          if (r.vulnerable) {
            acc[r.testType] = (acc[r.testType] || 0) + 1;
          }
          return acc;
        },
        {} as Record<string, number>,
      );

      for (const [type, count] of Object.entries(byType)) {
        parts.push(`${type}: ${count}`);
      }
    } else {
      parts.push("No cross-capability vulnerabilities detected.");
    }

    return parts.join(" ");
  }

  private generateRecommendations(
    results: CrossCapabilityTestResult[],
  ): string[] {
    const recommendations: string[] = [];

    // Tool->Resource recommendations
    const toolResourceVulns = results.filter(
      (r) => r.testType === "tool_to_resource" && r.vulnerable,
    );
    if (toolResourceVulns.length > 0) {
      recommendations.push(
        "Implement resource access controls to prevent tools from accessing sensitive resources. Consider allowlisting accessible resource paths.",
      );
    }

    // Prompt->Tool recommendations
    const promptToolVulns = results.filter(
      (r) => r.testType === "prompt_to_tool" && r.vulnerable,
    );
    if (promptToolVulns.length > 0) {
      recommendations.push(
        "Add confirmation prompts before dangerous tool execution. Implement tool invocation policies in prompts.",
      );
    }

    // Data flow recommendations
    const dataFlowVulns = results.filter(
      (r) => r.testType === "resource_to_tool" && r.vulnerable,
    );
    if (dataFlowVulns.length > 0) {
      recommendations.push(
        "Implement data loss prevention controls. Validate and sanitize resource content before passing to external-facing tools.",
      );
    }

    // Privilege escalation recommendations
    const escalationVulns = results.filter(
      (r) => r.testType === "privilege_escalation" && r.vulnerable,
    );
    if (escalationVulns.length > 0) {
      recommendations.push(
        "CRITICAL: Review and fix privilege escalation paths. Implement capability-based access control and principle of least privilege.",
      );
    }

    return recommendations;
  }
}
