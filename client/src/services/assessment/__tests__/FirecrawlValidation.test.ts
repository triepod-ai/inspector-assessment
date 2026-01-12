/**
 * Validation Test for Firecrawl False Positive Fix
 * Tests that Firecrawl-like tools are correctly recognized as working
 */

import { FunctionalityAssessor } from "../modules/FunctionalityAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("Firecrawl False Positive Fix Validation", () => {
  let assessor: FunctionalityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 5000,
      delayBetweenTests: 0,
    });
    assessor = new FunctionalityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should correctly assess firecrawl_scrape with insufficient credits error", async () => {
    const tool: Tool = {
      name: "firecrawl_scrape",
      description: "Scrape content from a single URL",
      inputSchema: {
        type: "object",
        properties: {
          url: { type: "string", format: "uri" },
        },
        required: ["url"],
      },
    };

    mockContext.tools = [tool];
    mockContext.callTool = jest.fn().mockResolvedValue({
      isError: true,
      content: [
        {
          type: "text",
          text: "Tool 'firecrawl_scrape' execution failed: Insufficient credits to perform this request. For more credits, you can upgrade your plan at https://firecrawl.dev/pricing or try changing the request limit to a lower value.",
        },
      ],
    });

    const result = await assessor.assess(mockContext);

    // Should be marked as working, not broken
    expect(result.workingTools).toBe(1);
    expect(result.brokenTools).toEqual([]);
    expect(result.status).toBe("PASS");

    // Verify tool result details
    const toolResult = result.toolResults[0];
    expect(toolResult.status).toBe("working");
    expect(toolResult.toolName).toBe("firecrawl_scrape");
  });

  it("should correctly assess firecrawl_check_crawl_status with job not found error", async () => {
    const tool: Tool = {
      name: "firecrawl_check_crawl_status",
      description: "Check the status of a crawl job",
      inputSchema: {
        type: "object",
        properties: {
          id: { type: "string" },
        },
        required: ["id"],
      },
    };

    mockContext.tools = [tool];
    mockContext.callTool = jest.fn().mockResolvedValue({
      isError: true,
      content: [
        {
          type: "text",
          text: "Tool 'firecrawl_check_crawl_status' execution failed: Job not found",
        },
      ],
    });

    const result = await assessor.assess(mockContext);

    // Should be marked as working (correctly validating job IDs)
    expect(result.workingTools).toBe(1);
    expect(result.brokenTools).toEqual([]);
    expect(result.status).toBe("PASS");
  });

  it("should correctly assess firecrawl_extract with URL validation error", async () => {
    const tool: Tool = {
      name: "firecrawl_extract",
      description: "Extract structured data from URLs",
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

    mockContext.tools = [tool];
    mockContext.callTool = jest.fn().mockResolvedValue({
      isError: true,
      content: [
        {
          type: "text",
          text: "Tool 'firecrawl_extract' execution failed: URL must have a valid top-level domain or be a valid path",
        },
      ],
    });

    const result = await assessor.assess(mockContext);

    // Should be marked as working (correctly validating URLs)
    expect(result.workingTools).toBe(1);
    expect(result.brokenTools).toEqual([]);
    expect(result.status).toBe("PASS");
  });

  it("should correctly assess all 6 Firecrawl tools together", async () => {
    const tools: Tool[] = [
      {
        name: "firecrawl_scrape",
        description: "Scrape content",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" } },
        },
      },
      {
        name: "firecrawl_map",
        description: "Map a website",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" } },
        },
      },
      {
        name: "firecrawl_search",
        description: "Search the web",
        inputSchema: {
          type: "object",
          properties: { query: { type: "string" } },
        },
      },
      {
        name: "firecrawl_crawl",
        description: "Crawl a website",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" } },
        },
      },
      {
        name: "firecrawl_check_crawl_status",
        description: "Check crawl status",
        inputSchema: { type: "object", properties: { id: { type: "string" } } },
      },
      {
        name: "firecrawl_extract",
        description: "Extract data",
        inputSchema: {
          type: "object",
          properties: { urls: { type: "array" } },
        },
      },
    ];

    mockContext.tools = tools;
    mockContext.callTool = jest.fn().mockImplementation((toolName) => {
      if (toolName === "firecrawl_check_crawl_status") {
        return Promise.resolve({
          isError: true,
          content: [{ type: "text", text: "Job not found" }],
        });
      }
      if (toolName === "firecrawl_extract") {
        return Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "URL must have a valid top-level domain or be a valid path",
            },
          ],
        });
      }
      // All others get insufficient credits error
      return Promise.resolve({
        isError: true,
        content: [
          {
            type: "text",
            text: "Insufficient credits to perform this request.",
          },
        ],
      });
    });

    const result = await assessor.assess(mockContext);

    // ALL tools should be marked as working
    expect(result.totalTools).toBe(6);
    expect(result.workingTools).toBe(6);
    expect(result.brokenTools).toEqual([]);
    expect(result.status).toBe("PASS");
    expect(result.coveragePercentage).toBe(100);

    // Verify each tool individually
    result.toolResults.forEach((toolResult) => {
      expect(toolResult.status).toBe("working");
      expect(toolResult.tested).toBe(true);
    });
  });

  it("should distinguish between operational errors and real tool failures", async () => {
    const tools: Tool[] = [
      {
        name: "firecrawl_scrape",
        description: "Scrape content",
        inputSchema: {
          type: "object",
          properties: { url: { type: "string" } },
        },
      },
      {
        name: "broken_tool",
        description: "Actually broken tool",
        inputSchema: {
          type: "object",
          properties: { param: { type: "string" } },
        },
      },
    ];

    mockContext.tools = tools;
    mockContext.callTool = jest.fn().mockImplementation((toolName) => {
      if (toolName === "firecrawl_scrape") {
        // Operational error (tool is working)
        return Promise.resolve({
          isError: true,
          content: [
            {
              type: "text",
              text: "Insufficient credits to perform this request.",
            },
          ],
        });
      }
      // Real tool failure
      return Promise.resolve({
        isError: true,
        content: [
          {
            type: "text",
            text: "Internal server error: NullPointerException at line 42",
          },
        ],
      });
    });

    const result = await assessor.assess(mockContext);

    // Only broken_tool should be marked as broken
    expect(result.workingTools).toBe(1);
    expect(result.brokenTools).toEqual(["broken_tool"]);
    // With 50% working, status is NEED_MORE_INFO not FAIL
    expect(result.status).toBe("NEED_MORE_INFO");

    // Verify individual results
    const scrapeResult = result.toolResults.find(
      (r) => r.toolName === "firecrawl_scrape",
    );
    const brokenResult = result.toolResults.find(
      (r) => r.toolName === "broken_tool",
    );

    expect(scrapeResult?.status).toBe("working");
    expect(brokenResult?.status).toBe("broken");
  });
});
