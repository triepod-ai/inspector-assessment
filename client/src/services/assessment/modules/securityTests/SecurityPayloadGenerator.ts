/**
 * Security Payload Generator
 * Creates test parameters for security payload injection
 *
 * Extracted from SecurityAssessor.ts for maintainability.
 * Handles parameter creation, tool classification, and language-aware payloads.
 */

import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { SecurityPayload } from "@/lib/securityPatterns";
import { ToolClassifier, ToolCategory } from "../../ToolClassifier";
import { LanguageAwarePayloadGenerator } from "../../LanguageAwarePayloadGenerator";

/**
 * Creates test parameters for security payload injection
 */
export class SecurityPayloadGenerator {
  private languageGenerator = new LanguageAwarePayloadGenerator();

  /**
   * Check if tool has input parameters
   */
  hasInputParameters(tool: Tool): boolean {
    const schema =
      tool.inputSchema?.type === "object" ? tool.inputSchema : tool.inputSchema;

    return (
      schema?.properties !== undefined &&
      Object.keys(schema.properties).length > 0
    );
  }

  /**
   * Create test parameters using payload
   */
  createTestParameters(
    payload: SecurityPayload,
    tool: Tool,
  ): Record<string, unknown> {
    const schema =
      tool.inputSchema?.type === "object" ? tool.inputSchema : tool.inputSchema;

    if (!schema?.properties) {
      return {};
    }

    const params: Record<string, unknown> = {};
    const targetParamTypes = payload.parameterTypes || [];
    let payloadInjected = false;

    // PRIORITY 1: Handle auth payloads first (Issue #81)
    // These MUST go to token/auth parameters, not language-detected params
    if (!payloadInjected && payload.payloadType === "auth") {
      const authParams = [
        "token",
        "auth_token",
        "authorization",
        "api_key",
        "access_token",
      ];
      for (const [key, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as { type?: string };
        if (propSchema.type === "string") {
          for (const authParam of authParams) {
            if (key.toLowerCase().includes(authParam.toLowerCase())) {
              params[key] = payload.payload;
              payloadInjected = true;
              break;
            }
          }
          if (payloadInjected) break;
        }
      }
    }

    // PRIORITY 2: Handle auth_failure payloads (Issue #79)
    // These MUST go to simulate_failure parameters
    if (!payloadInjected && payload.payloadType === "auth_failure") {
      const authFailureParams = [
        "simulate_failure",
        "failure_mode",
        "failure_type",
      ];
      for (const [key, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as { type?: string };
        if (propSchema.type === "string") {
          for (const failParam of authFailureParams) {
            if (key.toLowerCase().includes(failParam.toLowerCase())) {
              params[key] = payload.payload;
              payloadInjected = true;
              break;
            }
          }
          if (payloadInjected) break;
        }
      }
    }

    // PRIORITY 3: Check for language-specific code execution parameters
    for (const [key, prop] of Object.entries(schema.properties)) {
      const propSchema = prop as { type?: string };
      if (propSchema.type !== "string") continue;

      const detectedLanguage = this.languageGenerator.detectLanguage(
        key,
        tool.name,
        tool.description,
      );

      if (detectedLanguage !== "generic" && !payloadInjected) {
        const languagePayloads =
          this.languageGenerator.getPayloadsForLanguage(detectedLanguage);

        if (languagePayloads.length > 0) {
          const payloadLower = payload.payload.toLowerCase();
          const isCommandTest =
            payloadLower.includes("whoami") ||
            payloadLower.includes("passwd") ||
            payloadLower.includes("id");

          let selectedPayload = languagePayloads[0];
          if (isCommandTest) {
            const cmdPayload = languagePayloads.find(
              (lp) =>
                lp.payload.includes("whoami") ||
                lp.payload.includes("subprocess") ||
                lp.payload.includes("execSync"),
            );
            if (cmdPayload) selectedPayload = cmdPayload;
          }

          params[key] = selectedPayload.payload;
          payloadInjected = true;
          break;
        }
      }
    }

    // Fall back to parameterTypes matching
    if (!payloadInjected && targetParamTypes.length > 0) {
      for (const [key, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as { type?: string };
        const paramNameLower = key.toLowerCase();

        if (
          propSchema.type === "string" &&
          targetParamTypes.some((type) => paramNameLower.includes(type))
        ) {
          params[key] = payload.payload;
          payloadInjected = true;
          break;
        }
      }
    }

    // Fall back to generic payload - inject into first string parameter
    if (!payloadInjected) {
      for (const [key, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as { type?: string };

        if (propSchema.type === "string" && !payloadInjected) {
          params[key] = payload.payload;
          payloadInjected = true;
          break;
        }
      }
    }

    // VERBOSE MODE TESTING (Issue #103, Challenge #9)
    // For secret_leakage payloads, enable verbose mode to detect additional credential exposure
    if (payload.payloadType === "secret_leakage") {
      for (const [key, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as { type?: string };
        if (
          propSchema.type === "boolean" &&
          key.toLowerCase() === "verbose" &&
          !(key in params)
        ) {
          params[key] = true; // Enable verbose mode to test for additional leakage
          break;
        }
      }
    }

    // Fill required parameters with safe defaults
    for (const [key, prop] of Object.entries(schema.properties)) {
      const propSchema = prop as { type?: string };

      if (schema.required?.includes(key) && !(key in params)) {
        if (propSchema.type === "string") {
          params[key] = "test";
        } else if (propSchema.type === "number") {
          params[key] = 1;
        } else if (propSchema.type === "boolean") {
          params[key] = true;
        } else if (propSchema.type === "object") {
          params[key] = {};
        } else if (propSchema.type === "array") {
          params[key] = [];
        }
      }
    }

    return params;
  }

  /**
   * Check if tool is an API wrapper (safe data-passing tool)
   */
  isApiWrapper(tool: Tool): boolean {
    const classifier = new ToolClassifier();
    const classification = classifier.classify(
      tool.name,
      tool.description || "",
    );
    return classification.categories.includes(ToolCategory.API_WRAPPER);
  }

  /**
   * Check if attack is an execution-based test
   * These tests assume the tool executes input as code
   */
  isExecutionTest(attackName: string): boolean {
    const executionTests = [
      "Command Injection",
      "SQL Injection",
      "Path Traversal",
    ];
    return executionTests.includes(attackName);
  }
}
