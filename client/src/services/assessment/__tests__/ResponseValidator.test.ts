/**
 * ResponseValidator Test Suite
 * Tests business logic error detection for API operational errors
 */

import { ResponseValidator, ValidationContext } from "../ResponseValidator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("ResponseValidator - isBusinessLogicError", () => {
  describe("API Operational Errors", () => {
    it("should recognize insufficient credits as business logic error", () => {
      const tool: Tool = {
        name: "firecrawl_scrape",
        description: "Scrape web content",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { url: "https://example.com" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Insufficient credits to perform this request. For more credits, you can upgrade your plan.",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize quota exceeded as business logic error", () => {
      const tool: Tool = {
        name: "api_call",
        description: "Make API call",
        inputSchema: {
          type: "object",
          properties: {
            endpoint: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { endpoint: "/api/v1/data" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Quota exceeded. Please upgrade your subscription.",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize billing/payment errors as business logic error", () => {
      const tool: Tool = {
        name: "premium_feature",
        description: "Use premium feature",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { action: "analyze" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Payment required to access this feature.",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize trial expired as business logic error", () => {
      const tool: Tool = {
        name: "trial_feature",
        description: "Trial feature",
        inputSchema: {
          type: "object",
          properties: {
            action: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { action: "test" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Trial expired. Please upgrade your account.",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });
  });

  describe("Resource Validation Errors", () => {
    it("should recognize 'job not found' as business logic error", () => {
      const tool: Tool = {
        name: "firecrawl_check_crawl_status",
        description: "Check crawl job status",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string" },
          },
          required: ["id"],
        },
      };

      const context: ValidationContext = {
        tool,
        input: { id: "550e8400-e29b-41d4-a716-446655440000" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Job not found",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize 'resource not found' as business logic error", () => {
      const tool: Tool = {
        name: "get_entity",
        description: "Get entity by ID",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string" },
          },
          required: ["id"],
        },
      };

      const context: ValidationContext = {
        tool,
        input: { id: "test-id" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Resource not found",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });
  });

  describe("Input Validation Errors", () => {
    it("should recognize URL validation as business logic error", () => {
      const tool: Tool = {
        name: "firecrawl_extract",
        description: "Extract data from URLs",
        inputSchema: {
          type: "object",
          properties: {
            urls: {
              type: "array",
              items: { type: "string" },
            },
          },
          required: ["urls"],
        },
      };

      const context: ValidationContext = {
        tool,
        input: { urls: ["test"] },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "URL must have a valid top-level domain or be a valid path",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize invalid format as business logic error", () => {
      const tool: Tool = {
        name: "parse_date",
        description: "Parse date string",
        inputSchema: {
          type: "object",
          properties: {
            date: { type: "string" },
          },
          required: ["date"],
        },
      };

      const context: ValidationContext = {
        tool,
        input: { date: "invalid-date" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Invalid format: date must be in ISO 8601 format",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });
  });

  describe("Scraping/API Tool Type Detection", () => {
    it("should recognize scrape tools as validation-expected", () => {
      const tools = [
        "firecrawl_scrape",
        "web_scraper",
        "scrape_page",
        "data_scraper",
      ];

      tools.forEach((toolName) => {
        const tool: Tool = {
          name: toolName,
          description: "Scraping tool",
          inputSchema: { type: "object" },
        };

        const context: ValidationContext = {
          tool,
          input: {},
          response: {
            isError: true,
            content: [
              {
                type: "text",
                text: "Invalid input provided",
              },
            ],
          },
        };

        // Should be recognized as validation-expected tool type
        expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
      });
    });

    it("should recognize crawl tools as validation-expected", () => {
      const tools = [
        "firecrawl_crawl",
        "web_crawler",
        "crawl_site",
        "site_crawler",
      ];

      tools.forEach((toolName) => {
        const tool: Tool = {
          name: toolName,
          description: "Crawling tool",
          inputSchema: { type: "object" },
        };

        const context: ValidationContext = {
          tool,
          input: {},
          response: {
            isError: true,
            content: [
              {
                type: "text",
                text: "Invalid input provided",
              },
            ],
          },
        };

        expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
      });
    });

    it("should recognize extract/parse/map tools as validation-expected", () => {
      const tools = [
        "firecrawl_extract",
        "firecrawl_map",
        "parse_data",
        "extract_info",
      ];

      tools.forEach((toolName) => {
        const tool: Tool = {
          name: toolName,
          description: "Data extraction tool",
          inputSchema: { type: "object" },
        };

        const context: ValidationContext = {
          tool,
          input: {},
          response: {
            isError: true,
            content: [
              {
                type: "text",
                text: "Invalid input provided",
              },
            ],
          },
        };

        expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
      });
    });
  });

  describe("Rate Limiting Errors", () => {
    it("should recognize rate limit errors as business logic error", () => {
      const tool: Tool = {
        name: "api_endpoint",
        description: "Call API endpoint",
        inputSchema: {
          type: "object",
          properties: {
            endpoint: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { endpoint: "/api/data" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Rate limit exceeded. Too many requests.",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize throttling as business logic error", () => {
      const tool: Tool = {
        name: "bulk_operation",
        description: "Perform bulk operation",
        inputSchema: {
          type: "object",
          properties: {
            items: { type: "array" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { items: [] },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Request throttled. Please slow down.",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });
  });

  describe("Non-Business Logic Errors", () => {
    it("should NOT recognize genuine tool failures as business logic error", () => {
      const tool: Tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: {
          type: "object",
          properties: {
            value: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { value: "test" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Internal server error: NullPointerException at line 42",
            },
          ],
        },
      };

      // This is a genuine tool failure, not business logic validation
      expect(ResponseValidator.isBusinessLogicError(context)).toBe(false);
    });

    it("should NOT recognize crash errors as business logic error", () => {
      const tool: Tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: {
          type: "object",
          properties: {
            value: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { value: "test" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Uncaught exception: Tool crashed unexpectedly",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(false);
    });
  });

  describe("Confidence Calculation", () => {
    it("should meet confidence threshold for API tools with operational errors", () => {
      const tool: Tool = {
        name: "firecrawl_scrape",
        description: "Scrape web content",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { url: "https://example.com" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Insufficient credits to perform this request",
            },
          ],
        },
      };

      // With increased weights:
      // - hasBusinessErrorPattern: 2/2 (matches "insufficient credits")
      // - isValidationExpected: 2/2 (tool name includes "scrape")
      // - Total: 4/8 = 50% confidence
      // - Should meet 50% threshold for non-CRUD tools
      // - Should meet 30% threshold for validation-expected tools
      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });
  });
});
