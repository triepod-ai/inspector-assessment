/**
 * Security Assessor - API Wrapper False Positives Fix (Issue #58)
 *
 * Tests that read-only API wrapper tools returning JSON with numeric fields
 * are NOT flagged as Calculator Injection vulnerabilities.
 *
 * Root cause: Response like {"records": 4, "page": 1} contains the digit "4",
 * which was incorrectly matched as the computed result of "2+2".
 *
 * Key principles:
 * - API wrapper tools returning data with coincidental numbers should NOT be flagged
 * - Only flag if response contains computational language (e.g., "The answer is 4")
 * - Tool classification heuristics (get_*, list_*, fetch_*) should reduce confidence
 */

import { SecurityAssessor } from "../modules/SecurityAssessor";
import { SecurityResponseAnalyzer } from "../modules/securityTests/SecurityResponseAnalyzer";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("SecurityAssessor - API Wrapper False Positives Fix (Issue #58)", () => {
  let assessor: SecurityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 5000,
      delayBetweenTests: 0,
      enableDomainTesting: true,
    });
    assessor = new SecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("JSON responses with coincidental numeric fields (Should NOT be flagged)", () => {
    it("should NOT flag API response with 'records: 4' as Calculator Injection for '2+2' payload", async () => {
      const tool: Tool = {
        name: "get_company_data",
        description: "Fetch company data from external REST API",
        inputSchema: {
          type: "object",
          properties: {
            company_id: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        // API returns JSON with numeric fields - "4" is record count, not computed
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                records: 4,
                page: 1,
                employees: 150,
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "get_company_data" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag API response with 'count: 25' for '5*5' payload", async () => {
      const tool: Tool = {
        name: "fetch_user_info",
        description: "Retrieve user information from API",
        inputSchema: {
          type: "object",
          properties: {
            user_id: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                count: 25,
                status: "active",
                items: [],
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "fetch_user_info" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag nested JSON with matching numbers", async () => {
      const tool: Tool = {
        name: "list_records",
        description: "List all records from database",
        inputSchema: {
          type: "object",
          properties: {
            filter: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                data: {
                  stats: {
                    total: 100,
                    page: 1,
                  },
                },
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "list_records" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });
  });

  describe("Read-only tool name patterns (Should NOT be flagged)", () => {
    it("should NOT flag 'get_users' tool returning data with numbers", async () => {
      const tool: Tool = {
        name: "get_users",
        description: "Get all users",
        inputSchema: {
          type: "object",
          properties: {},
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                users: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }],
                total: 4,
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "get_users" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag 'list_items' tool returning data with numbers", async () => {
      const tool: Tool = {
        name: "list_items",
        description: "List all items in inventory",
        inputSchema: {
          type: "object",
          properties: {},
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "Found 25 items in the database",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "list_items" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });

    it("should NOT flag 'fetch_data' tool returning data with numbers", async () => {
      const tool: Tool = {
        name: "fetch_data",
        description: "Fetch data from external service",
        inputSchema: {
          type: "object",
          properties: {},
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "Total: 100 records retrieved",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "fetch_data" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorTests.length).toBe(0);
    });
  });

  describe("Actual Calculator Injection (Should STILL be detected)", () => {
    it("should flag 'The answer is 4' as VULNERABLE", async () => {
      const tool: Tool = {
        name: "calculator_tool",
        description: "Calculate math expressions",
        inputSchema: {
          type: "object",
          properties: {
            expression: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "The answer is 4",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "calculator_tool" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      // Should detect at least one Calculator Injection vulnerability
      expect(calculatorTests.length).toBeGreaterThan(0);
    });

    it("should flag plain '4' response as VULNERABLE", async () => {
      const tool: Tool = {
        name: "eval_tool",
        description: "Evaluate expressions",
        inputSchema: {
          type: "object",
          properties: {
            expr: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "4",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "eval_tool" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      // Should detect Calculator Injection when response is exactly the result
      expect(calculatorTests.length).toBeGreaterThan(0);
    });

    it("should flag 'Result = 4' as VULNERABLE", async () => {
      const tool: Tool = {
        name: "math_processor",
        description: "Process mathematical operations",
        inputSchema: {
          type: "object",
          properties: {
            input: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: "Result = 4",
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorTests = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "math_processor" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      // Should detect Calculator Injection with computational language
      expect(calculatorTests.length).toBeGreaterThan(0);
    });
  });
});

describe("SecurityResponseAnalyzer - isCoincidentalNumericInStructuredData", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  describe("JSON structure detection", () => {
    it("should detect numeric value in 'records' field", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        4,
        JSON.stringify({ records: 4, page: 1 }),
      );
      expect(result).toBe(true);
    });

    it("should detect numeric value in 'count' field", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        25,
        JSON.stringify({ count: 25, status: "ok" }),
      );
      expect(result).toBe(true);
    });

    it("should detect numeric value in 'total' field", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        100,
        JSON.stringify({ total: 100, items: [] }),
      );
      expect(result).toBe(true);
    });

    it("should detect numeric value in nested 'total' field", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        100,
        JSON.stringify({ data: { stats: { total: 100 } } }),
      );
      expect(result).toBe(true);
    });

    it("should NOT detect numeric value in random field name", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        4,
        JSON.stringify({ someRandomField: 4 }),
      );
      expect(result).toBe(false);
    });

    it("should NOT detect when number is not in response", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        4,
        JSON.stringify({ records: 10, page: 1 }),
      );
      expect(result).toBe(false);
    });
  });

  describe("Text pattern detection", () => {
    it("should detect 'Records: 4' pattern", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        4,
        "Records: 4 found",
      );
      expect(result).toBe(true);
    });

    it("should detect '4 records' pattern", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        4,
        "Found 4 records in database",
      );
      expect(result).toBe(true);
    });

    it("should detect 'Total: 100' pattern", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        100,
        "Total: 100 entries",
      );
      expect(result).toBe(true);
    });

    it("should detect 'Page 1 of 4' pattern", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        4,
        "Showing Page 1 of 4",
      );
      expect(result).toBe(true);
    });

    it("should NOT detect number without data context", () => {
      const result = analyzer.isCoincidentalNumericInStructuredData(
        4,
        "The answer is 4",
      );
      expect(result).toBe(false);
    });
  });
});

describe("SecurityResponseAnalyzer - analyzeComputedMathResult", () => {
  let analyzer: SecurityResponseAnalyzer;

  beforeEach(() => {
    analyzer = new SecurityResponseAnalyzer();
  });

  describe("Confidence levels", () => {
    it("should return HIGH confidence for computational response", () => {
      const result = analyzer.analyzeComputedMathResult(
        "2+2",
        "The answer is 4",
      );
      expect(result.isComputed).toBe(true);
      expect(result.confidence).toBe("high");
    });

    it("should return HIGH confidence when response is exactly the result", () => {
      const result = analyzer.analyzeComputedMathResult("2+2", "4");
      expect(result.isComputed).toBe(true);
      expect(result.confidence).toBe("high");
    });

    it("should return LOW confidence for structured data response", () => {
      const result = analyzer.analyzeComputedMathResult(
        "2+2",
        JSON.stringify({ records: 4, page: 1 }),
      );
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("low");
    });

    it("should return LOW confidence for read-only tool pattern", () => {
      const tool: Tool = {
        name: "get_users",
        description: "Get all users",
        inputSchema: { type: "object", properties: {} },
      };

      const result = analyzer.analyzeComputedMathResult(
        "2+2",
        "User ID: 4 retrieved",
        tool,
      );
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("low");
    });

    it("should return MEDIUM confidence for ambiguous response without computational language", () => {
      const result = analyzer.analyzeComputedMathResult(
        "2+2",
        "Processing completed. Status: 4 active, 2 pending.",
      );
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("medium");
    });

    it("should return HIGH confidence with reason when not a math expression", () => {
      const result = analyzer.analyzeComputedMathResult(
        "hello world",
        "some response",
      );
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("high");
      expect(result.reason).toBe("Not a math expression");
    });

    it("should return HIGH confidence with reason for HTTP error", () => {
      const result = analyzer.analyzeComputedMathResult("2+2", "404 Not Found");
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("high");
      expect(result.reason).toBe("HTTP error response");
    });
  });

  describe("Tool classification integration", () => {
    it("should return LOW confidence for DATA_FETCHER tools", () => {
      const tool: Tool = {
        name: "get_company_data",
        description: "Fetch company data from external API",
        inputSchema: { type: "object", properties: {} },
      };

      const result = analyzer.analyzeComputedMathResult(
        "2+2",
        "Response contains 4 items",
        tool,
      );
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("low");
    });

    it("should return LOW confidence for fetch_ prefix tools", () => {
      const tool: Tool = {
        name: "fetch_orders",
        description: "Fetch orders from API",
        inputSchema: { type: "object", properties: {} },
      };

      const result = analyzer.analyzeComputedMathResult(
        "2+2",
        "4 orders found",
        tool,
      );
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("low");
    });

    it("should return LOW confidence for list_ prefix tools", () => {
      const tool: Tool = {
        name: "list_products",
        description: "List all products",
        inputSchema: { type: "object", properties: {} },
      };

      const result = analyzer.analyzeComputedMathResult(
        "5*5",
        "25 products available",
        tool,
      );
      expect(result.isComputed).toBe(false);
      expect(result.confidence).toBe("low");
    });
  });
});

/**
 * Critical Gap Tests - Issue #58 Regression, Pagination, and Mixed Tools
 *
 * These tests cover scenarios identified as gaps in the original test coverage:
 * 1. Exact Issue #58 scenario (kintone_get_app)
 * 2. Pagination metadata patterns (common REST API response)
 * 3. Mixed tool detection (safe + vulnerable on same server)
 */
describe("Critical Gap Tests - Issue #58 Regression & Edge Cases", () => {
  let assessor: SecurityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 5000,
      delayBetweenTests: 0,
      enableDomainTesting: true,
    });
    assessor = new SecurityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("Issue #58 Regression - Exact kintone_get_app scenario", () => {
    it("should NOT flag kintone_get_app returning {records: 4} for Calculator Injection", async () => {
      // This is the EXACT scenario from Issue #58
      // Tool: kintone_get_app (read-only API wrapper for Kintone)
      // Payload: "2+2"
      // Response: {"records": 4, "totalCount": 4} - "4" is record count, NOT computed
      const tool: Tool = {
        name: "kintone_get_app",
        description:
          "Retrieves information from a Kintone application via REST API",
        inputSchema: {
          type: "object",
          properties: {
            app_id: { type: "string", description: "Kintone app ID" },
            query: { type: "string", description: "Filter query" },
          },
          required: ["app_id"],
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        // Exact response pattern from Issue #58
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                records: [
                  { id: "1", name: "Project A" },
                  { id: "2", name: "Project B" },
                  { id: "3", name: "Project C" },
                  { id: "4", name: "Project D" },
                ],
                totalCount: 4,
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      // Should NOT be flagged as Calculator Injection
      const calculatorVulns = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "kintone_get_app" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorVulns.length).toBe(0);
    });

    it("should NOT flag kintone_get_records returning numeric totalCount", async () => {
      const tool: Tool = {
        name: "kintone_get_records",
        description: "Get records from Kintone app",
        inputSchema: {
          type: "object",
          properties: {
            app: { type: "number" },
            query: { type: "string" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                records: [],
                totalCount: 25, // Matches 5*5 payload
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorVulns = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "kintone_get_records" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorVulns.length).toBe(0);
    });
  });

  describe("Pagination Metadata Patterns", () => {
    it("should NOT flag REST API pagination response with page/per_page/total", async () => {
      // Common REST API pagination pattern
      const tool: Tool = {
        name: "get_paginated_results",
        description: "Fetch paginated results from REST API",
        inputSchema: {
          type: "object",
          properties: {
            endpoint: { type: "string" },
            page: { type: "number" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                data: [{ id: 1 }, { id: 2 }],
                page: 2, // Matches 1+1 payload
                per_page: 25, // Matches 5*5 payload
                total: 100, // Matches 10*10 payload
                total_pages: 4, // Matches 2+2 payload
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorVulns = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "get_paginated_results" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorVulns.length).toBe(0);
    });

    it("should NOT flag offset-based pagination response", async () => {
      const tool: Tool = {
        name: "list_api_resources",
        description: "List resources with offset pagination",
        inputSchema: {
          type: "object",
          properties: {
            offset: { type: "number" },
            limit: { type: "number" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                items: [],
                offset: 0,
                limit: 25,
                total: 100,
                has_more: true,
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorVulns = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "list_api_resources" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorVulns.length).toBe(0);
    });

    it("should NOT flag cursor-based pagination with count field", async () => {
      const tool: Tool = {
        name: "fetch_cursor_results",
        description: "Fetch results using cursor pagination",
        inputSchema: {
          type: "object",
          properties: {
            cursor: { type: "string" },
            count: { type: "number" },
          },
        },
      };

      mockContext.tools = [tool];
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                data: [],
                next_cursor: "abc123",
                count: 4, // Matches 2+2 payload
                total_count: 100,
              }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      const calculatorVulns = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "fetch_cursor_results" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );

      expect(calculatorVulns.length).toBe(0);
    });
  });

  describe("Mixed Tool Detection - Safe API Wrappers + Vulnerable Calculators", () => {
    it("should correctly distinguish safe API wrapper from vulnerable calculator on same server", async () => {
      // Server has BOTH a safe API wrapper AND a vulnerable calculator
      const safeApiTool: Tool = {
        name: "get_customer_data",
        description: "Retrieve customer information from CRM API",
        inputSchema: {
          type: "object",
          properties: {
            customer_id: { type: "string" },
          },
        },
      };

      const vulnerableCalculator: Tool = {
        name: "calculate_expression",
        description: "Evaluate mathematical expressions",
        inputSchema: {
          type: "object",
          properties: {
            expression: { type: "string" },
          },
        },
      };

      mockContext.tools = [safeApiTool, vulnerableCalculator];

      // Different responses for different tools
      mockContext.callTool = jest.fn().mockImplementation((name) => {
        if (name === "get_customer_data") {
          // Safe: Returns JSON data where "4" is customer count
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  customers: 4,
                  status: "active",
                  lastSync: "2024-01-15",
                }),
              },
            ],
          });
        } else {
          // Vulnerable: Actually computes the expression
          return Promise.resolve({
            isError: false,
            content: [
              {
                type: "text",
                text: "The answer is 4",
              },
            ],
          });
        }
      });

      const result = await assessor.assess(mockContext);

      // Safe API wrapper should NOT be flagged
      const safeApiVulns = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "get_customer_data" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );
      expect(safeApiVulns.length).toBe(0);

      // Vulnerable calculator SHOULD be flagged
      const calculatorVulns = result.promptInjectionTests.filter(
        (t) =>
          t.toolName === "calculate_expression" &&
          t.testName === "Calculator Injection" &&
          t.vulnerable,
      );
      expect(calculatorVulns.length).toBeGreaterThan(0);
    });

    it("should flag vulnerable tool even when safe tools exist on same server", async () => {
      // Multiple safe tools + one vulnerable
      const tools: Tool[] = [
        {
          name: "list_users",
          description: "List all users",
          inputSchema: { type: "object", properties: {} },
        },
        {
          name: "get_settings",
          description: "Get application settings",
          inputSchema: { type: "object", properties: {} },
        },
        {
          name: "fetch_reports",
          description: "Fetch reports from API",
          inputSchema: { type: "object", properties: {} },
        },
        {
          name: "eval_math",
          description: "Evaluate math",
          inputSchema: {
            type: "object",
            properties: { expr: { type: "string" } },
          },
        },
      ];

      mockContext.tools = tools;
      mockContext.callTool = jest.fn().mockImplementation((name) => {
        if (name === "eval_math") {
          return Promise.resolve({
            isError: false,
            content: [{ type: "text", text: "Result: 4" }],
          });
        }
        // All other tools return safe JSON data
        return Promise.resolve({
          isError: false,
          content: [
            {
              type: "text",
              text: JSON.stringify({ count: 4, items: [] }),
            },
          ],
        });
      });

      const result = await assessor.assess(mockContext);

      // Only eval_math should be flagged
      const vulnerableTools = result.promptInjectionTests.filter(
        (t) => t.testName === "Calculator Injection" && t.vulnerable,
      );

      // All vulnerabilities should be from eval_math
      for (const vuln of vulnerableTools) {
        expect(vuln.toolName).toBe("eval_math");
      }

      // Safe tools should NOT be flagged
      const safeFalsePositives = result.promptInjectionTests.filter(
        (t) =>
          t.testName === "Calculator Injection" &&
          t.vulnerable &&
          ["list_users", "get_settings", "fetch_reports"].includes(t.toolName),
      );
      expect(safeFalsePositives.length).toBe(0);
    });
  });
});
