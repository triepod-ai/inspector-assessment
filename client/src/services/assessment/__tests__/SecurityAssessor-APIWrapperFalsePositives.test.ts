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
