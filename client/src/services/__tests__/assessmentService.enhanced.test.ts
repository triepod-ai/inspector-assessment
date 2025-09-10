/**
 * Enhanced Security Assessment Test Generator
 * Tests enhanced vulnerability detection capabilities
 * Fixes gaps discovered in advanced testing
 */

import { MCPAssessmentService } from "../assessmentService";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

// Enhanced Assessment Service with improved security detection
class EnhancedMCPAssessmentService extends MCPAssessmentService {
  /**
   * Enhanced injection detection with broader pattern recognition
   */
  protected checkForInjectionSuccess(
    response: string,
    payload: string,
  ): boolean {
    const lowerResponse = response.toLowerCase();
    const lowerPayload = payload.toLowerCase();

    // Original indicators
    const originalIndicators = [
      "injected",
      "calculator",
      "environment variable",
      "api key",
      "<script>",
      "deleted",
      "command not found",
    ];

    // Enhanced SQL injection indicators
    const sqlIndicators = [
      "table",
      "select",
      "union",
      "drop",
      "insert",
      "delete from",
      "update set",
      "mysql",
      "postgresql",
      "sqlite",
      "syntax error",
      "sql error",
      "query executed",
      "database",
      "column",
    ];

    // Template injection indicators
    const templateIndicators = [
      "template output:",
      "49", // 7*7 result
      "64", // 8*8 result
      "25", // 5*5 result
      "executed",
      "rendered",
      "expression",
    ];

    // XXE indicators
    const xxeIndicators = [
      "root:x:",
      "/etc/passwd",
      "<!doctype",
      "<!entity",
      "system",
      "file://",
      "external entity",
    ];

    // System command indicators
    const commandIndicators = [
      "uid=",
      "gid=",
      "whoami",
      "/bin/bash",
      "/bin/sh",
      "command executed",
      "process",
      "shell",
    ];

    // Data exfiltration indicators
    const dataIndicators = [
      "password=",
      "secret",
      "token",
      "private key",
      "credentials",
      "auth",
      "session",
      "cookie",
      "bearer",
    ];

    // XSS/Script indicators
    const xssIndicators = [
      "alert(",
      "script>",
      "javascript:",
      "onerror",
      "onload",
      "eval(",
      "document.cookie",
      "xss",
    ];

    // Polyglot indicators
    const polyglotIndicators = [
      "jaVasCript:",
      "alert('xss')",
      "alert(//xss//)",
      "svg/onload",
      "script/--!>",
    ];

    // NoSQL injection indicators
    const nosqlIndicators = [
      "$where",
      "$regex",
      "$ne",
      "$gt",
      "$lt",
      "mongodb",
      "collection",
      "documents returned",
    ];

    // Combine all indicators
    const allIndicators = [
      ...originalIndicators,
      ...sqlIndicators,
      ...templateIndicators,
      ...xxeIndicators,
      ...commandIndicators,
      ...dataIndicators,
      ...xssIndicators,
      ...polyglotIndicators,
      ...nosqlIndicators,
    ];

    // Check for any matching indicators
    const hasIndicators = allIndicators.some((indicator) =>
      lowerResponse.includes(indicator),
    );

    // Check for payload reflection (potential injection success)
    const hasPayloadReflection = lowerResponse.includes(
      lowerPayload.substring(0, 20),
    );

    // Check for numeric calculation results (template injection)
    const mathResults = ["49", "64", "25", "36", "16", "9"];
    const hasMathResult = mathResults.some(
      (result) =>
        lowerResponse.includes(result) &&
        (lowerPayload.includes("7*7") ||
          lowerPayload.includes("8*8") ||
          lowerPayload.includes("{{")),
    );

    // Check for error messages that reveal information
    const errorPatterns = [
      "error:",
      "exception:",
      "stack trace",
      "line ",
      "file ",
      "function ",
      "undefined method",
      "null pointer",
    ];
    const hasVerboseErrors = errorPatterns.some((pattern) =>
      lowerResponse.includes(pattern),
    );

    return (
      hasIndicators || hasPayloadReflection || hasMathResult || hasVerboseErrors
    );
  }
}

describe("Enhanced Security Assessment", () => {
  let service: EnhancedMCPAssessmentService;
  let mockCallTool: jest.Mock;

  beforeEach(() => {
    service = new EnhancedMCPAssessmentService();
    mockCallTool = jest.fn();
  });

  describe("Enhanced SQL Injection Detection", () => {
    it("should detect SQL injection with enhanced patterns", async () => {
      const vulnerableResponses = [
        {
          content: [
            {
              type: "text",
              text: "Query executed: SELECT * FROM users WHERE id = 1; DROP TABLE users;",
            },
          ],
        },
        {
          content: [
            { type: "text", text: "MySQL Error: Table 'users' doesn't exist" },
          ],
        },
        {
          content: [
            {
              type: "text",
              text: "Database connection established, executing query",
            },
          ],
        },
      ];

      let callCount = 0;
      mockCallTool.mockImplementation(() => {
        const response =
          vulnerableResponses[callCount % vulnerableResponses.length];
        callCount++;
        return Promise.resolve(response);
      });

      const sqlTool: Tool = {
        name: "query_database",
        description: "Execute database queries",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
            table: { type: "string" },
          },
        },
      };

      const result = await service.runFullAssessment(
        "sql-vulnerable-server",
        [sqlTool],
        mockCallTool,
      );

      // Enhanced detection should catch SQL patterns
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("Enhanced Template Injection Detection", () => {
    it("should detect SSTI with math expression results", async () => {
      mockCallTool.mockImplementation((toolName, params) => {
        const paramStr = JSON.stringify(params);
        if (paramStr.includes("{{7*7}}") || paramStr.includes("${7*7}")) {
          // Simulate template execution
          return Promise.resolve({
            content: [{ type: "text", text: "Template output: 49" }],
          });
        }
        return Promise.resolve({
          content: [{ type: "text", text: "Normal response" }],
        });
      });

      const templateTool: Tool = {
        name: "render_template",
        description: "Render template with data",
        inputSchema: {
          type: "object",
          properties: {
            template: { type: "string" },
            data: { type: "object" },
          },
        },
      };

      const result = await service.runFullAssessment(
        "ssti-server",
        [templateTool],
        mockCallTool,
      );

      // Enhanced detection should catch template patterns
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("Enhanced XXE Detection", () => {
    it("should detect XXE with file content indicators", async () => {
      mockCallTool.mockImplementation((toolName, params) => {
        const paramStr = JSON.stringify(params);
        if (paramStr.includes("<!ENTITY") || paramStr.includes("SYSTEM")) {
          // Simulate XXE vulnerability showing /etc/passwd content
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
              },
            ],
          });
        }
        return Promise.resolve({
          content: [{ type: "text", text: "XML processed" }],
        });
      });

      const xmlTool: Tool = {
        name: "parse_xml",
        description: "Parse XML document",
        inputSchema: {
          type: "object",
          properties: {
            xml: { type: "string" },
          },
        },
      };

      const result = await service.runFullAssessment(
        "xxe-server",
        [xmlTool],
        mockCallTool,
      );

      // Enhanced detection should catch XXE patterns
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("Enhanced Polyglot Detection", () => {
    it("should detect polyglot payloads with enhanced patterns", async () => {
      const polyglotPayload =
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert('XSS') )//";

      mockCallTool.mockImplementation((toolName, params) => {
        const paramStr = JSON.stringify(params);
        if (
          paramStr.includes("jaVasCript") ||
          paramStr.includes("onerror=alert")
        ) {
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: `Processed: jaVasCript:alert('XSS executed')`,
              },
            ],
          });
        }
        return Promise.resolve({
          content: [{ type: "text", text: "Safe response" }],
        });
      });

      const result = await service.runFullAssessment(
        "polyglot-server",
        [
          {
            name: "process_content",
            description: "Process various content types",
            inputSchema: {
              type: "object",
              properties: { content: { type: "string" } },
            },
          },
        ],
        mockCallTool,
      );

      // Enhanced detection should catch polyglot patterns
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("Enhanced NoSQL Injection Detection", () => {
    it("should detect NoSQL injection patterns", async () => {
      mockCallTool.mockImplementation((toolName, params) => {
        const paramStr = JSON.stringify(params);
        if (paramStr.includes("$where") || paramStr.includes("$ne")) {
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: "MongoDB query executed, 1000 documents returned from collection",
              },
            ],
          });
        }
        return Promise.resolve({
          content: [{ type: "text", text: "Normal response" }],
        });
      });

      const nosqlTool: Tool = {
        name: "mongodb_query",
        description: "Query MongoDB collection",
        inputSchema: {
          type: "object",
          properties: {
            filter: { type: "object" },
            collection: { type: "string" },
          },
        },
      };

      const result = await service.runFullAssessment(
        "nosql-server",
        [nosqlTool],
        mockCallTool,
      );

      // Enhanced detection should catch NoSQL patterns
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("Enhanced Command Injection Detection", () => {
    it("should detect command injection with system output", async () => {
      mockCallTool.mockImplementation((toolName, params) => {
        const paramStr = JSON.stringify(params);
        if (
          paramStr.includes("whoami") ||
          paramStr.includes("$(") ||
          paramStr.includes("`")
        ) {
          return Promise.resolve({
            content: [
              { type: "text", text: "uid=0(root) gid=0(root) groups=0(root)" },
            ],
          });
        }
        return Promise.resolve({
          content: [{ type: "text", text: "Normal response" }],
        });
      });

      const cmdTool: Tool = {
        name: "system_command",
        description: "Execute system commands",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string" },
          },
        },
      };

      const result = await service.runFullAssessment(
        "command-injection-server",
        [cmdTool],
        mockCallTool,
      );

      // Enhanced detection should catch command patterns
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("Enhanced Multi-Stage Attack Detection", () => {
    it("should detect sophisticated multi-stage attacks", async () => {
      const attackState = {
        reconnaissance: false,
        exploitation: false,
        persistence: false,
      };

      mockCallTool.mockImplementation((toolName, params) => {
        const paramStr = JSON.stringify(params);

        // Stage 1: Information disclosure
        if (paramStr.includes("/etc/passwd") || paramStr.includes("config")) {
          attackState.reconnaissance = true;
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: "Database credentials: admin:password123, API key: sk-abc123",
              },
            ],
          });
        }

        // Stage 2: Exploitation
        if (
          attackState.reconnaissance &&
          (paramStr.includes("admin:password") || paramStr.includes("sk-abc"))
        ) {
          attackState.exploitation = true;
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: "Authentication successful, shell access granted",
              },
            ],
          });
        }

        // Stage 3: Privilege escalation
        if (attackState.exploitation && paramStr.includes("sudo")) {
          attackState.persistence = true;
          return Promise.resolve({
            content: [
              {
                type: "text",
                text: "root privileges acquired, backdoor installed",
              },
            ],
          });
        }

        return Promise.resolve({
          content: [{ type: "text", text: "Normal response" }],
        });
      });

      const vulnerableTools: Tool[] = [
        {
          name: "get_config",
          description: "Get system configuration",
          inputSchema: {
            type: "object",
            properties: { path: { type: "string" } },
          },
        },
        {
          name: "authenticate",
          description: "Authenticate user",
          inputSchema: {
            type: "object",
            properties: { credentials: { type: "string" } },
          },
        },
        {
          name: "execute_command",
          description: "Execute system command",
          inputSchema: {
            type: "object",
            properties: { command: { type: "string" } },
          },
        },
      ];

      const result = await service.runFullAssessment(
        "multi-stage-attack-server",
        vulnerableTools,
        mockCallTool,
      );

      // Enhanced detection should catch credential exposure and privileged access
      expect(result.security.overallRiskLevel).toBe("HIGH");
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);

      // Verify multi-stage attack indicators detected
      const hasCredentialExposure = result.security.vulnerabilities.some(
        (v) => v.includes("config") || v.includes("authenticate"),
      );
      const hasPrivilegeEscalation = result.security.vulnerabilities.some((v) =>
        v.includes("execute_command"),
      );

      expect(hasCredentialExposure || hasPrivilegeEscalation).toBe(true);
    });
  });

  describe("Payload Reflection Detection", () => {
    it("should detect when malicious payloads are reflected in responses", async () => {
      mockCallTool.mockImplementation((toolName, params) => {
        const paramStr = JSON.stringify(params);
        // Simulate vulnerable server that reflects input
        if (params && typeof params === "object" && "input" in params) {
          const input = params.input as string;
          return Promise.resolve({
            content: [{ type: "text", text: `Processing input: ${input}` }],
          });
        }
        return Promise.resolve({
          content: [{ type: "text", text: "Normal response" }],
        });
      });

      const reflectionTool: Tool = {
        name: "process_input",
        description: "Process user input",
        inputSchema: {
          type: "object",
          properties: {
            input: { type: "string" },
          },
        },
      };

      const result = await service.runFullAssessment(
        "reflection-server",
        [reflectionTool],
        mockCallTool,
      );

      // Enhanced detection should catch payload reflection
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });

  describe("Verbose Error Detection", () => {
    it("should detect information disclosure through verbose errors", async () => {
      mockCallTool.mockImplementation(() => {
        return Promise.resolve({
          content: [
            {
              type: "text",
              text: "Error: Database connection failed at line 42 in file /app/database.js, function connectDB(). Stack trace: Error\n    at Database.connect (/app/database.js:42:15)\n    at /app/server.js:123:20",
            },
          ],
        });
      });

      const errorTool: Tool = {
        name: "database_operation",
        description: "Perform database operations",
        inputSchema: {
          type: "object",
          properties: {
            operation: { type: "string" },
          },
        },
      };

      const result = await service.runFullAssessment(
        "verbose-error-server",
        [errorTool],
        mockCallTool,
      );

      // Enhanced detection should catch verbose error information
      expect(result.security.vulnerabilities.length).toBeGreaterThan(0);
    });
  });
});
