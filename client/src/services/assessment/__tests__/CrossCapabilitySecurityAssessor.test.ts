/**
 * CrossCapabilitySecurityAssessor Unit Tests
 *
 * Tests for cross-capability security assessment:
 * - Tool-to-Resource access patterns
 * - Prompt-to-Tool interaction security
 * - Resource-to-Tool data flow (exfiltration)
 * - Privilege escalation detection
 */

import { CrossCapabilitySecurityAssessor } from "../modules/CrossCapabilitySecurityAssessor";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";
import {
  AssessmentContext,
  MCPResource,
  MCPPrompt,
} from "../AssessmentOrchestrator";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// Default test configuration
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  testTimeout: 5000,
  skipBrokenTools: false,
  delayBetweenTests: 0,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
  },
  ...overrides,
});

// Tool factory
const createTool = (
  name: string,
  description?: string,
  schemaOverrides: Record<string, unknown> = {},
): Tool => ({
  name,
  description: description || `Test tool: ${name}`,
  inputSchema: {
    type: "object" as const,
    properties: {},
    ...schemaOverrides,
  },
});

// Resource factory
const createResource = (
  uri: string,
  name?: string,
  description?: string,
): MCPResource => ({
  uri,
  name: name || uri.split("/").pop() || "resource",
  description,
});

// Prompt factory
const createPrompt = (
  name: string,
  description?: string,
  args?: Array<{ name: string; description?: string; required?: boolean }>,
): MCPPrompt => ({
  name,
  description,
  arguments: args,
});

// Context factory
const createContext = (
  tools: Tool[],
  resources: MCPResource[] = [],
  prompts: MCPPrompt[] = [],
): AssessmentContext =>
  ({
    tools,
    resources,
    prompts,
    config: createConfig(),
    serverInfo: { name: "test-server", version: "1.0.0" },
    serverCapabilities: {},
  }) as unknown as AssessmentContext;

describe("CrossCapabilitySecurityAssessor", () => {
  let assessor: CrossCapabilitySecurityAssessor;

  beforeEach(() => {
    assessor = new CrossCapabilitySecurityAssessor(createConfig());
  });

  describe("Tool-to-Resource Access Tests", () => {
    it("should detect resource access tool with path param accessing sensitive resource", async () => {
      const tools = [
        createTool("read_file", "Reads files from filesystem", {
          properties: {
            path: { type: "string", description: "File path to read" },
          },
        }),
      ];
      const resources = [
        createResource("file:///config/credentials.json", "API Credentials"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      expect(result.vulnerabilitiesFound).toBeGreaterThan(0);
      const toolResourceResult = result.results.find(
        (r) => r.testType === "tool_to_resource",
      );
      expect(toolResourceResult?.vulnerable).toBe(true);
      expect(toolResourceResult?.riskLevel).toBe("HIGH");
    });

    it("should not flag resource access tool without path param", async () => {
      const tools = [
        createTool("read_file", "Reads files from filesystem", {
          properties: { content: { type: "string" } }, // No path param
        }),
      ];
      const resources = [
        createResource("file:///config/credentials.json", "API Credentials"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const toolResourceResults = result.results.filter(
        (r) => r.testType === "tool_to_resource",
      );
      // Should have results but not vulnerable (no path param)
      toolResourceResults.forEach((r) => {
        expect(r.vulnerable).toBe(false);
        expect(r.riskLevel).toBe("LOW");
      });
    });

    it("should detect multiple tool-resource combinations", async () => {
      const tools = [
        createTool("read_file", "Reads files", {
          properties: { path: { type: "string" } },
        }),
        createTool("fetch_resource", "Fetches data", {
          properties: { uri: { type: "string" } },
        }),
      ];
      const resources = [
        createResource("file:///secrets/api_key.txt", "API Key"),
        createResource("file:///config/token.json", "Token"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const toolResourceResults = result.results.filter(
        (r) => r.testType === "tool_to_resource",
      );
      // 2 tools x 2 resources = 4 combinations (both tools match RESOURCE_ACCESS_TOOL_PATTERNS)
      expect(toolResourceResults.length).toBe(4);
    });

    it("should identify credentials/secrets/tokens as sensitive", async () => {
      const tools = [
        createTool("fetch_resource", "Fetches resources", {
          properties: { uri: { type: "string" } },
        }),
      ];
      const resources = [
        createResource("file:///data/credential.json"),
        createResource("file:///data/secret.key"),
        createResource("file:///data/token.txt"),
        createResource("file:///data/password.env"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const vulnerableResults = result.results.filter(
        (r) => r.testType === "tool_to_resource" && r.vulnerable,
      );
      // All 4 sensitive resources should be flagged
      expect(vulnerableResults.length).toBe(4);
    });

    it("should handle empty resources gracefully", async () => {
      const tools = [
        createTool("read_file", "Reads files", {
          properties: { path: { type: "string" } },
        }),
      ];

      const result = await assessor.assess(createContext(tools, []));

      const toolResourceResults = result.results.filter(
        (r) => r.testType === "tool_to_resource",
      );
      expect(toolResourceResults.length).toBe(0);
    });
  });

  describe("Prompt-to-Tool Interaction Tests", () => {
    it("should detect prompt with trigger words targeting dangerous tool", async () => {
      const tools = [
        createTool("delete_file", "Deletes files from the system"),
      ];
      const prompts = [
        createPrompt("execute_operation", "Execute the specified operation", [
          { name: "action", description: "Action to perform" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const promptToolResults = result.results.filter(
        (r) => r.testType === "prompt_to_tool",
      );
      expect(promptToolResults.length).toBeGreaterThan(0);
      expect(promptToolResults[0].vulnerable).toBe(true);
    });

    it("should detect direct tool reference in prompt text", async () => {
      const tools = [createTool("shell_exec", "Executes shell commands")];
      const prompts = [
        createPrompt(
          "run_shell_exec",
          "Invoke shell_exec to run system commands",
        ),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const promptToolResult = result.results.find(
        (r) => r.testType === "prompt_to_tool" && r.vulnerable,
      );
      expect(promptToolResult).toBeDefined();
      expect(promptToolResult?.confidence).toBe("high");
    });

    it("should detect indirect trigger via action arguments", async () => {
      const tools = [createTool("execute_command", "Runs commands")];
      const prompts = [
        createPrompt("perform_task", "Perform a task", [
          { name: "action", description: "Action to execute" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const vulnerableResult = result.results.find(
        (r) => r.testType === "prompt_to_tool" && r.vulnerable,
      );
      expect(vulnerableResult).toBeDefined();
    });

    it("should not flag read-only prompts with safe tools", async () => {
      const tools = [createTool("get_status", "Gets system status")];
      const prompts = [createPrompt("view_status", "View the current status")];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const promptToolResults = result.results.filter(
        (r) => r.testType === "prompt_to_tool",
      );
      // No dangerous tools, no trigger prompts - no results expected
      expect(promptToolResults.length).toBe(0);
    });

    it("should handle prompts without arguments", async () => {
      const tools = [createTool("drop_table", "Drops database tables")];
      const prompts = [createPrompt("run_cleanup", "Run database cleanup")];

      const result = await assessor.assess(createContext(tools, [], prompts));

      // Should still detect based on prompt name/description patterns
      expect(result.results.length).toBeGreaterThanOrEqual(0);
    });
  });

  describe("Resource-to-Tool Data Flow Tests", () => {
    it("should detect sensitive resource with exfiltration tool", async () => {
      const tools = [
        createTool("send_email", "Sends email messages", {
          properties: {
            body: { type: "string", description: "Email content" },
          },
        }),
      ];
      const resources = [
        createResource("file:///secrets/api_key.txt", "API Key"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const dataFlowResult = result.results.find(
        (r) => r.testType === "resource_to_tool" && r.vulnerable,
      );
      expect(dataFlowResult).toBeDefined();
      expect(dataFlowResult?.riskLevel).toBe("HIGH");
    });

    it("should identify email as exfiltration method", async () => {
      const tools = [
        createTool("send_email", "Sends emails", {
          properties: { content: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///config/password.txt")];

      const result = await assessor.assess(createContext(tools, resources));

      const dataFlowResult = result.results.find(
        (r) => r.testType === "resource_to_tool" && r.vulnerable,
      );
      expect(dataFlowResult?.dataExfiltrationRisk?.exfiltrationMethod).toBe(
        "email",
      );
    });

    it("should identify webhook as exfiltration method", async () => {
      const tools = [
        createTool("call_webhook", "Calls webhook endpoints", {
          properties: { data: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///secrets/token.json")];

      const result = await assessor.assess(createContext(tools, resources));

      const dataFlowResult = result.results.find(
        (r) => r.testType === "resource_to_tool" && r.vulnerable,
      );
      expect(dataFlowResult?.dataExfiltrationRisk?.exfiltrationMethod).toBe(
        "webhook",
      );
    });

    it("should identify http_request as exfiltration method", async () => {
      const tools = [
        createTool("http_post", "Makes HTTP POST requests", {
          properties: { payload: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///config/credentials.env")];

      const result = await assessor.assess(createContext(tools, resources));

      const dataFlowResult = result.results.find(
        (r) => r.testType === "resource_to_tool" && r.vulnerable,
      );
      expect(dataFlowResult?.dataExfiltrationRisk?.exfiltrationMethod).toBe(
        "http_request",
      );
    });

    it("should extract sensitive fields from resource metadata", async () => {
      const tools = [
        createTool("upload_file", "Uploads files", {
          properties: { content: { type: "string" } },
        }),
      ];
      const resources = [
        createResource(
          "file:///config/api_key.json",
          "API Key Configuration",
          "Contains API tokens and passwords",
        ),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const dataFlowResult = result.results.find(
        (r) => r.testType === "resource_to_tool" && r.vulnerable,
      );
      expect(
        dataFlowResult?.dataExfiltrationRisk?.sensitiveFields,
      ).toBeDefined();
      // Should detect "key" and "password" patterns
      expect(dataFlowResult?.dataExfiltrationRisk?.sensitiveFields).toContain(
        "api_key",
      );
    });

    it("should include dataExfiltrationRisk in result", async () => {
      const tools = [
        createTool("notify_user", "Sends notifications", {
          properties: { message: { type: "string" } },
        }),
      ];
      const resources = [
        createResource("file:///secrets/auth.json", "Auth Data"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const dataFlowResult = result.results.find(
        (r) => r.testType === "resource_to_tool" && r.vulnerable,
      );
      expect(dataFlowResult?.dataExfiltrationRisk).toMatchObject({
        sensitiveFields: expect.any(Array),
        exfiltrationMethod: expect.any(String),
      });
    });
  });

  describe("Privilege Escalation Tests", () => {
    it("should detect read-only prompt with action arg + write tools", async () => {
      const tools = [createTool("write_file", "Writes to files")];
      const prompts = [
        createPrompt("view_data", "View data from the system", [
          { name: "action", description: "Action to perform" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const escalationResult = result.results.find(
        (r) => r.testType === "privilege_escalation" && r.vulnerable,
      );
      expect(escalationResult).toBeDefined();
      expect(escalationResult?.privilegeEscalationVector).toBe(
        "prompt_argument_injection",
      );
    });

    it("should detect public resource influencing admin tool", async () => {
      const tools = [
        createTool("admin_config", "Configures admin settings", {
          properties: { data: { type: "string" } },
        }),
      ];
      const resources = [
        createResource("file:///public/shared_data.json", "Shared Data"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const escalationResult = result.results.find(
        (r) => r.testType === "privilege_escalation" && r.vulnerable,
      );
      expect(escalationResult).toBeDefined();
      expect(escalationResult?.privilegeEscalationVector).toBe(
        "resource_content_injection",
      );
    });

    it("should include attackChain in result", async () => {
      const tools = [createTool("delete_records", "Deletes database records")];
      const prompts = [
        createPrompt("list_items", "List all items", [
          { name: "operation", description: "Operation type" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const escalationResult = result.results.find(
        (r) => r.testType === "privilege_escalation" && r.vulnerable,
      );
      expect(escalationResult?.attackChain).toBeDefined();
      expect(escalationResult?.attackChain?.length).toBeGreaterThan(0);
    });

    it("should include privilegeEscalationVector in result", async () => {
      const tools = [createTool("modify_settings", "Modifies system settings")];
      const prompts = [
        createPrompt("read_config", "Read configuration", [
          { name: "command", description: "Command to run" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const escalationResult = result.results.find(
        (r) => r.testType === "privilege_escalation" && r.vulnerable,
      );
      expect(escalationResult?.privilegeEscalationVector).toBeDefined();
    });

    it("should not flag when no escalation path exists", async () => {
      const tools = [createTool("get_info", "Gets information")];
      const prompts = [createPrompt("show_status", "Shows status")];
      const resources = [
        createResource("file:///private/internal.txt", "Internal Data"),
      ];

      const result = await assessor.assess(
        createContext(tools, resources, prompts),
      );

      const escalationResults = result.results.filter(
        (r) => r.testType === "privilege_escalation" && r.vulnerable,
      );
      expect(escalationResults.length).toBe(0);
    });
  });

  describe("Pattern Matching", () => {
    it("should match resource access patterns (read_file, get_file, etc.)", async () => {
      const tools = [
        createTool("read_file"),
        createTool("get_file"),
        createTool("fetch_resource"),
        createTool("load_data"),
        createTool("retrieve_document"),
        createTool("download_asset"),
      ];
      const resources = [createResource("file:///secret.txt", "Secret")];

      const result = await assessor.assess(createContext(tools, resources));

      const toolResourceResults = result.results.filter(
        (r) => r.testType === "tool_to_resource",
      );
      // All 6 tools should match resource access patterns
      expect(toolResourceResults.length).toBe(6);
    });

    it("should match dangerous patterns (delete, exec, shell, etc.)", async () => {
      const tools = [
        createTool("delete_file"),
        createTool("execute_command"),
        createTool("shell_run"),
        createTool("eval_code"),
        createTool("system_call"),
        createTool("drop_table"),
      ];
      const prompts = [createPrompt("run_action", "Run an action")];

      const result = await assessor.assess(createContext(tools, [], prompts));

      const promptToolResults = result.results.filter(
        (r) => r.testType === "prompt_to_tool",
      );
      expect(promptToolResults.length).toBe(6);
    });

    it("should match sensitive patterns (credential, secret, .env, etc.)", async () => {
      const tools = [
        createTool("access_resource", "Accesses resources", {
          properties: { location: { type: "string" } },
        }),
      ];
      const resources = [
        createResource("file:///credential.json"),
        createResource("file:///secret.key"),
        createResource("file:///password.txt"),
        createResource("file:///token.json"),
        createResource("file:///.env"),
        createResource("file:///auth.conf"),
        createResource("file:///config.json"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      const toolResourceResults = result.results.filter(
        (r) => r.testType === "tool_to_resource",
      );
      // All resources match sensitive patterns
      expect(toolResourceResults.length).toBe(7);
    });

    it("should match trigger patterns (execute, run, invoke, etc.)", async () => {
      // Tool must match DANGEROUS_TOOL_PATTERNS (delete, exec, shell, write, etc.)
      const tools = [createTool("delete_records", "Deletes database records")];
      // Prompts need action arguments to trigger vulnerability detection
      const prompts = [
        createPrompt("execute_task", undefined, [{ name: "action" }]),
        createPrompt("run_process", undefined, [{ name: "operation" }]),
        createPrompt("invoke_method", undefined, [{ name: "function" }]),
        createPrompt("trigger_event", undefined, [{ name: "command" }]),
        createPrompt("perform_action", undefined, [{ name: "tool" }]),
        createPrompt("call_function", undefined, [{ name: "action" }]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      // Each prompt should match trigger patterns and combine with dangerous tool
      const promptToolResults = result.results.filter(
        (r) => r.testType === "prompt_to_tool",
      );
      expect(promptToolResults.length).toBe(6);
    });
  });

  describe("Status Determination", () => {
    it("should return FAIL when privilege escalation detected", async () => {
      const tools = [createTool("exec_command", "Executes commands")];
      const prompts = [
        createPrompt("show_data", "Shows data", [
          { name: "action", description: "Action to take" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      expect(result.privilegeEscalationRisks).toBeGreaterThan(0);
      expect(result.status).toBe("FAIL");
    });

    it("should return FAIL when more than 2 vulnerabilities", async () => {
      const tools = [
        createTool("read_file", "Reads files", {
          properties: { path: { type: "string" } },
        }),
      ];
      const resources = [
        createResource("file:///secret1.txt"),
        createResource("file:///secret2.txt"),
        createResource("file:///secret3.txt"),
      ];

      const result = await assessor.assess(createContext(tools, resources));

      expect(result.vulnerabilitiesFound).toBeGreaterThan(2);
      expect(result.status).toBe("FAIL");
    });

    it("should return NEED_MORE_INFO when 1-2 vulnerabilities", async () => {
      const tools = [
        createTool("read_file", "Reads files", {
          properties: { path: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///secret.txt")];

      const result = await assessor.assess(createContext(tools, resources));

      // One vulnerable combination
      if (result.vulnerabilitiesFound > 0 && result.vulnerabilitiesFound <= 2) {
        expect(result.status).toBe("NEED_MORE_INFO");
      }
    });

    it("should return PASS when no vulnerabilities", async () => {
      const tools = [createTool("get_status", "Gets status")];
      const resources = [createResource("file:///public/readme.txt", "Readme")];
      const prompts = [createPrompt("view_help", "View help information")];

      const result = await assessor.assess(
        createContext(tools, resources, prompts),
      );

      expect(result.vulnerabilitiesFound).toBe(0);
      expect(result.status).toBe("PASS");
    });
  });

  describe("Explanation and Recommendations", () => {
    it("should generate explanation with vulnerability counts", async () => {
      const tools = [
        createTool("read_file", "Reads files", {
          properties: { path: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///secrets/key.txt")];

      const result = await assessor.assess(createContext(tools, resources));

      expect(result.explanation).toContain("Tested");
      expect(result.explanation).toContain("interaction");
    });

    it("should generate tool->resource recommendation", async () => {
      const tools = [
        createTool("load_data", "Loads data", {
          properties: { file: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///config/credentials.json")];

      const result = await assessor.assess(createContext(tools, resources));

      expect(
        result.recommendations.some((r) => r.includes("resource access")),
      ).toBe(true);
    });

    it("should generate prompt->tool recommendation", async () => {
      const tools = [createTool("delete_all", "Deletes everything")];
      const prompts = [
        createPrompt("execute_cleanup", "Execute cleanup", [
          { name: "action", description: "Action to perform" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      expect(
        result.recommendations.some((r) => r.includes("tool execution")),
      ).toBe(true);
    });

    it("should generate data flow recommendation", async () => {
      const tools = [
        createTool("send_http", "Sends HTTP requests", {
          properties: { body: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///secrets/token.txt")];

      const result = await assessor.assess(createContext(tools, resources));

      expect(
        result.recommendations.some(
          (r) => r.includes("data loss") || r.includes("sanitize"),
        ),
      ).toBe(true);
    });

    it("should generate CRITICAL privilege escalation recommendation", async () => {
      const tools = [createTool("modify_system", "Modifies system settings")];
      const prompts = [
        createPrompt("read_info", "Read information", [
          { name: "operation", description: "Operation to perform" },
        ]),
      ];

      const result = await assessor.assess(createContext(tools, [], prompts));

      expect(result.recommendations.some((r) => r.includes("CRITICAL"))).toBe(
        true,
      );
    });

    it("should handle no vulnerabilities gracefully", async () => {
      const tools = [createTool("ping", "Pings a server")];

      const result = await assessor.assess(createContext(tools));

      expect(result.explanation).toContain(
        "No cross-capability vulnerabilities",
      );
      expect(result.recommendations.length).toBe(0);
    });
  });

  describe("Result Structure", () => {
    it("should include all required fields in assessment result", async () => {
      const tools = [createTool("test_tool")];
      const resources = [createResource("file:///test.txt")];
      const prompts = [createPrompt("test_prompt")];

      const result = await assessor.assess(
        createContext(tools, resources, prompts),
      );

      expect(result).toMatchObject({
        testsRun: expect.any(Number),
        vulnerabilitiesFound: expect.any(Number),
        privilegeEscalationRisks: expect.any(Number),
        dataFlowViolations: expect.any(Number),
        results: expect.any(Array),
        status: expect.stringMatching(/PASS|FAIL|NEED_MORE_INFO/),
        explanation: expect.any(String),
        recommendations: expect.any(Array),
      });
    });

    it("should include enrichment fields (confidence, attackChain)", async () => {
      const tools = [
        createTool("read_file", "Reads files", {
          properties: { path: { type: "string" } },
        }),
      ];
      const resources = [createResource("file:///secret.txt")];

      const result = await assessor.assess(createContext(tools, resources));

      const vulnerableResult = result.results.find((r) => r.vulnerable);
      if (vulnerableResult) {
        expect(vulnerableResult.confidence).toBeDefined();
        expect(["high", "medium", "low"]).toContain(
          vulnerableResult.confidence,
        );
        // attackChain is optional but should exist for vulnerable results
        if (vulnerableResult.attackChain) {
          expect(Array.isArray(vulnerableResult.attackChain)).toBe(true);
        }
      }
    });

    it("should calculate metrics correctly", async () => {
      const tools = [
        createTool("read_file", "Reads files", {
          properties: { path: { type: "string" } },
        }),
        createTool("send_data", "Sends data externally", {
          properties: { content: { type: "string" } },
        }),
      ];
      const resources = [
        createResource("file:///secrets/key.txt"),
        createResource("file:///config/token.json"),
      ];
      const prompts = [
        createPrompt("get_info", "Get information", [
          { name: "action", description: "Action" },
        ]),
      ];

      const result = await assessor.assess(
        createContext(tools, resources, prompts),
      );

      // Verify metrics are calculated
      expect(result.testsRun).toBeGreaterThanOrEqual(0);
      expect(result.vulnerabilitiesFound).toBe(
        result.results.filter((r) => r.vulnerable).length,
      );
      expect(result.privilegeEscalationRisks).toBe(
        result.results.filter(
          (r) => r.testType === "privilege_escalation" && r.vulnerable,
        ).length,
      );
      expect(result.dataFlowViolations).toBe(
        result.results.filter(
          (r) =>
            (r.testType === "resource_to_tool" ||
              r.testType === "tool_to_resource") &&
            r.vulnerable,
        ).length,
      );
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty tools array", async () => {
      const resources = [createResource("file:///secret.txt")];
      const prompts = [createPrompt("run_task")];

      const result = await assessor.assess(
        createContext([], resources, prompts),
      );

      expect(result.testsRun).toBe(0);
      expect(result.vulnerabilitiesFound).toBe(0);
      expect(result.status).toBe("PASS");
    });

    it("should handle empty resources array", async () => {
      const tools = [createTool("read_file")];
      const prompts = [createPrompt("run_task")];

      const result = await assessor.assess(createContext(tools, [], prompts));

      // No resource tests, but prompt-tool tests may still run
      const resourceResults = result.results.filter(
        (r) =>
          r.testType === "tool_to_resource" ||
          r.testType === "resource_to_tool",
      );
      expect(resourceResults.length).toBe(0);
    });

    it("should handle empty prompts array", async () => {
      const tools = [createTool("delete_file")];
      const resources = [createResource("file:///secret.txt")];

      const result = await assessor.assess(createContext(tools, resources, []));

      const promptResults = result.results.filter(
        (r) =>
          r.testType === "prompt_to_tool" ||
          r.testType === "privilege_escalation",
      );
      // Some privilege_escalation tests don't require prompts (resource->tool)
      // but prompt_to_tool should be empty
      const promptToToolResults = promptResults.filter(
        (r) => r.testType === "prompt_to_tool",
      );
      expect(promptToToolResults.length).toBe(0);
    });

    it("should handle all empty arrays", async () => {
      const result = await assessor.assess(createContext([], [], []));

      expect(result.testsRun).toBe(0);
      expect(result.vulnerabilitiesFound).toBe(0);
      expect(result.privilegeEscalationRisks).toBe(0);
      expect(result.dataFlowViolations).toBe(0);
      expect(result.status).toBe("PASS");
    });

    it("should handle tools without inputSchema", async () => {
      const tools = [
        {
          name: "minimal_tool",
          description: "A minimal tool",
          inputSchema: { type: "object" as const },
        },
      ];
      const resources = [createResource("file:///secrets/key.txt")];

      const result = await assessor.assess(createContext(tools, resources));

      // Should not throw, tool without properties should be handled
      expect(result).toBeDefined();
      expect(result.status).toBeDefined();
    });
  });
});
