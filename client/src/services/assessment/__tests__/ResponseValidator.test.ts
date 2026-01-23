/**
 * ResponseValidator Test Suite
 * Tests business logic error detection for API operational errors
 */

import { ResponseValidator, ValidationContext } from "../ResponseValidator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("ResponseValidator - isBusinessLogicError", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

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

  /**
   * Issue #203: File/Media Operation Errors
   * Tests that file-based tools returning validation errors (e.g., "file not found")
   * are correctly recognized as business logic errors, not tool failures.
   */
  describe("File/Media Operation Errors (Issue #203)", () => {
    it("should recognize 'file not found' from load_audio as business logic error", () => {
      const tool: Tool = {
        name: "load_audio",
        description: "Load audio data from a file path",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
          required: ["path"],
        },
      };

      const context: ValidationContext = {
        tool,
        input: { path: "/nonexistent/file.mp3" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "File not found: /nonexistent/file.mp3",
            },
          ],
        },
      };

      // Issue #203: This should be true because:
      // 1. Tool name "load_audio" matches "load" pattern (isValidationExpected)
      // 2. Error text matches high-confidence pattern "file not found"
      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize 'no such file' as business logic error", () => {
      const tool: Tool = {
        name: "open_document",
        description: "Open a document file",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { path: "/missing/document.pdf" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "No such file or directory: /missing/document.pdf",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize 'path does not exist' as business logic error", () => {
      const tool: Tool = {
        name: "play_media",
        description: "Play media file",
        inputSchema: {
          type: "object",
          properties: {
            file: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { file: "/invalid/path/video.mp4" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Path does not exist: /invalid/path/video.mp4",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize 'permission denied' as business logic error", () => {
      const tool: Tool = {
        name: "save_file",
        description: "Save file to disk",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string" },
            content: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { path: "/root/protected.txt", content: "data" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Permission denied: cannot write to /root/protected.txt",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize validation errors from execute tools", () => {
      const tool: Tool = {
        name: "execute_script",
        description: "Execute a script file",
        inputSchema: {
          type: "object",
          properties: {
            script: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { script: "/missing/script.sh" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Invalid path: script file does not exist",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize errors from upload/download tools", () => {
      const tool: Tool = {
        name: "upload_file",
        description: "Upload a file to storage",
        inputSchema: {
          type: "object",
          properties: {
            localPath: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { localPath: "/missing/file.txt" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "File not found: /missing/file.txt",
            },
          ],
        },
      };

      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize 'missing required parameter' as business logic error", () => {
      // This tests high-confidence validation pattern even without tool name match
      const tool: Tool = {
        name: "custom_tool",
        description: "A custom tool without matching name patterns",
        inputSchema: {
          type: "object",
          properties: {
            data: { type: "string" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: {},
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Missing required parameter: data",
            },
          ],
        },
      };

      // Should pass due to high-confidence pattern "missing required"
      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    it("should recognize 'invalid input' as business logic error", () => {
      const tool: Tool = {
        name: "unknown_tool",
        description: "Tool with unknown name pattern",
        inputSchema: {
          type: "object",
          properties: {
            value: { type: "number" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { value: "not-a-number" },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "Invalid input: expected number, got string",
            },
          ],
        },
      };

      // Should pass due to high-confidence pattern "invalid input"
      expect(ResponseValidator.isBusinessLogicError(context)).toBe(true);
    });

    // TODO: Issue #204 - Substring matching causes false positives
    // Tools like "payload_validator" contain "load" but aren't file operations.
    // Current implementation uses toolName.includes("load") which is too broad.
    // Fix requires refactoring to word boundary matching (e.g., /\bload\b/).
    it.skip("should NOT incorrectly flag tools with substring matches (payload_validator)", () => {
      const tool: Tool = {
        name: "payload_validator",
        description: "Validate API payload structure",
        inputSchema: {
          type: "object",
          properties: {
            payload: { type: "object" },
          },
        },
      };

      const context: ValidationContext = {
        tool,
        input: { payload: { data: "test" } },
        response: {
          isError: true,
          content: [
            {
              type: "text",
              text: "TypeError: Cannot read property 'foo' of undefined",
            },
          ],
        },
      };

      // EXPECTED: false (crash, not validation)
      // ACTUAL: true (substring match causes false positive)
      expect(ResponseValidator.isBusinessLogicError(context)).toBe(false);
    });
  });
});

/**
 * Issue #121: Zod Integration Tests
 * Tests the integration between ResponseValidator and Zod schema validation
 */
describe("ResponseValidator - Zod Integration", () => {
  // Helper to create a minimal valid tool for tests
  const createTestTool = (name: string = "test_tool"): Tool => ({
    name,
    description: "Test tool",
    inputSchema: { type: "object", properties: {} },
  });

  describe("safeGetContentArray() integration via extractResponseMetadata", () => {
    it("handles malformed content array gracefully (returns empty metadata)", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          // Invalid: content is not an array
          content: "not an array" as unknown as Array<{ type: string }>,
        },
      };

      // Should not throw, should return empty counts
      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.contentTypes).toEqual([]);
      expect(metadata.textBlockCount).toBe(0);
      expect(metadata.imageCount).toBe(0);
      expect(metadata.resourceCount).toBe(0);
    });

    it("handles null content gracefully", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: null as unknown as Array<{ type: string }>,
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.contentTypes).toEqual([]);
      expect(metadata.textBlockCount).toBe(0);
    });

    it("handles content array with invalid blocks gracefully", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [
            { invalid: "block" }, // Missing type
            123, // Not an object
          ] as unknown as Array<{ type: string }>,
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      // Schema validation fails, so safeGetContentArray returns undefined
      // which means counts are 0
      expect(metadata.textBlockCount).toBe(0);
    });

    it("processes valid text content block correctly", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [
            { type: "text", text: "Hello world" },
            { type: "text", text: "Another text block" },
          ],
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.contentTypes).toContain("text");
      expect(metadata.textBlockCount).toBe(2);
    });

    it("processes valid image content block correctly", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [
            { type: "image", data: "base64data", mimeType: "image/png" },
          ],
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.contentTypes).toContain("image");
      expect(metadata.imageCount).toBe(1);
    });

    it("processes valid resource content block correctly", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [
            { type: "resource", uri: "file:///path/to/resource" },
            {
              type: "resource_link",
              uri: "https://example.com/resource",
              mimeType: "application/json",
            },
          ],
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.contentTypes).toContain("resource");
      expect(metadata.contentTypes).toContain("resource_link");
      expect(metadata.resourceCount).toBe(2);
    });
  });

  describe("safeGetMCPResponse() integration via extractResponseMetadata", () => {
    it("prefers validated data for structuredContent access", () => {
      const structuredData = { result: "success", value: 42 };
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [{ type: "text", text: "Result" }],
          structuredContent: structuredData,
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.hasStructuredContent).toBe(true);
    });

    it("falls back to raw response when structuredContent check needed", () => {
      // Response that passes validation but also has structuredContent via raw check
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [{ type: "text", text: "OK" }],
          structuredContent: { data: "test" },
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      // Both paths should detect structuredContent
      expect(metadata.hasStructuredContent).toBe(true);
    });

    it("handles _meta property via validated response", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [{ type: "text", text: "Result" }],
          _meta: { requestId: "abc123", timestamp: Date.now() },
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.hasMeta).toBe(true);
    });

    it("correctly reports when _meta is absent", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [{ type: "text", text: "Result" }],
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      expect(metadata.hasMeta).toBe(false);
    });
  });

  describe("extractResponseMetadata() full integration", () => {
    it("extracts metadata from complex MCP response with multiple content types", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [
            { type: "text", text: "Analysis result" },
            { type: "text", text: "Additional details" },
            { type: "image", data: "base64imagedata", mimeType: "image/jpeg" },
            {
              type: "resource",
              uri: "file:///data.json",
              mimeType: "application/json",
            },
          ],
          structuredContent: { analysis: { score: 95 } },
          _meta: { version: "1.0" },
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      // Verify all content types detected
      expect(metadata.contentTypes).toContain("text");
      expect(metadata.contentTypes).toContain("image");
      expect(metadata.contentTypes).toContain("resource");

      // Verify counts
      expect(metadata.textBlockCount).toBe(2);
      expect(metadata.imageCount).toBe(1);
      expect(metadata.resourceCount).toBe(1);

      // Verify structured content and meta
      expect(metadata.hasStructuredContent).toBe(true);
      expect(metadata.hasMeta).toBe(true);
    });

    it("populates all metadata fields correctly for minimal response", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [{ type: "text", text: "OK" }],
        },
      };

      const metadata = ResponseValidator.extractResponseMetadata(context);

      // All fields should be defined
      expect(metadata.contentTypes).toBeDefined();
      expect(typeof metadata.hasStructuredContent).toBe("boolean");
      expect(typeof metadata.hasMeta).toBe("boolean");
      expect(typeof metadata.textBlockCount).toBe("number");
      expect(typeof metadata.imageCount).toBe("number");
      expect(typeof metadata.resourceCount).toBe("number");

      // Verify correct values
      expect(metadata.contentTypes).toEqual(["text"]);
      expect(metadata.hasStructuredContent).toBe(false);
      expect(metadata.hasMeta).toBe(false);
      expect(metadata.textBlockCount).toBe(1);
      expect(metadata.imageCount).toBe(0);
      expect(metadata.resourceCount).toBe(0);
    });

    it("handles partial validation failures gracefully", () => {
      // Mix of valid and invalid content blocks
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          // This array has some blocks that might not match strict schemas
          // but GenericContentBlockSchema should catch them
          content: [
            { type: "text", text: "Valid text" },
            { type: "unknown_type", data: "something" }, // Unknown type
          ],
          structuredContent: { data: "test" },
        },
      };

      // Should not throw
      const metadata = ResponseValidator.extractResponseMetadata(context);

      // The GenericContentBlockSchema fallback allows unknown types
      expect(metadata.contentTypes).toContain("text");
      expect(metadata.hasStructuredContent).toBe(true);
    });

    it("validateResponse uses extractResponseMetadata correctly", () => {
      const context: ValidationContext = {
        tool: createTestTool(),
        input: {},
        response: {
          content: [
            { type: "text", text: "Operation successful" },
            { type: "image", data: "png-data", mimeType: "image/png" },
          ],
        },
      };

      const result = ResponseValidator.validateResponse(context);

      // Result should include responseMetadata
      expect(result.responseMetadata).toBeDefined();
      expect(result.responseMetadata?.textBlockCount).toBe(1);
      expect(result.responseMetadata?.imageCount).toBe(1);

      // Evidence should include metadata details
      expect(result.evidence).toContain("Response includes 1 text block(s)");
      expect(result.evidence).toContain("Response includes 1 image(s)");
    });
  });
});
