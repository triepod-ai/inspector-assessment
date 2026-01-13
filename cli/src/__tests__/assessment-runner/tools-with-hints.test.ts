/**
 * Tests for tools-with-hints module
 *
 * Issue #155: Verifies that hint properties (readOnlyHint, etc.) are preserved
 * from raw MCP transport responses, even when the SDK's Zod validation would
 * normally strip them.
 */

import {
  jest,
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
} from "@jest/globals";
import {
  getToolsWithPreservedHints,
  type ToolWithHints,
} from "../../lib/assessment-runner/tools-with-hints.js";

// Use looser typing to avoid jest.fn() type conflicts
interface MockTransport {
  onmessage: ((message: unknown, extra?: unknown) => void) | undefined;
}

interface MockClient {
  transport: MockTransport | null;
  listTools: jest.Mock;
}

describe("getToolsWithPreservedHints", () => {
  let mockClient: MockClient;
  let mockTransport: MockTransport;

  beforeEach(() => {
    mockTransport = {
      onmessage: undefined,
    };

    mockClient = {
      transport: mockTransport,
      listTools: jest.fn(),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should preserve readOnlyHint from direct property in raw response", async () => {
    // SDK returns tool without readOnlyHint (stripped by Zod)
    mockClient.listTools.mockImplementation(async () => {
      // Simulate raw response before SDK processes it
      if (mockTransport.onmessage) {
        mockTransport.onmessage({
          result: {
            tools: [
              {
                name: "browse_subreddit",
                description: "Browse posts",
                readOnlyHint: true, // Direct property in raw response
              },
            ],
          },
        });
      }
      // Return SDK-processed tools (without direct readOnlyHint)
      return {
        tools: [
          {
            name: "browse_subreddit",
            description: "Browse posts",
            // readOnlyHint stripped by SDK Zod validation
          },
        ],
      };
    });

    const tools = await getToolsWithPreservedHints(mockClient as any);

    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe("browse_subreddit");
    expect(tools[0].readOnlyHint).toBe(true);
  });

  it("should preserve all hint properties from raw response", async () => {
    mockClient.listTools.mockImplementation(async () => {
      if (mockTransport.onmessage) {
        mockTransport.onmessage({
          result: {
            tools: [
              {
                name: "delete_item",
                readOnlyHint: false,
                destructiveHint: true,
                idempotentHint: false,
                openWorldHint: true,
              },
            ],
          },
        });
      }
      return { tools: [{ name: "delete_item" }] };
    });

    const tools = await getToolsWithPreservedHints(mockClient as any);

    expect(tools[0].readOnlyHint).toBe(false);
    expect(tools[0].destructiveHint).toBe(true);
    expect(tools[0].idempotentHint).toBe(false);
    expect(tools[0].openWorldHint).toBe(true);
  });

  it("should not override SDK annotations with raw direct properties", async () => {
    // If SDK has annotations, they take precedence
    mockClient.listTools.mockImplementation(async () => {
      if (mockTransport.onmessage) {
        mockTransport.onmessage({
          result: {
            tools: [
              {
                name: "read_file",
                readOnlyHint: false, // Raw says false
              },
            ],
          },
        });
      }
      return {
        tools: [
          {
            name: "read_file",
            annotations: {
              readOnlyHint: true, // SDK annotations say true
            },
          },
        ],
      };
    });

    const tools = await getToolsWithPreservedHints(mockClient as any);

    // SDK annotations should take precedence
    expect(tools[0].annotations?.readOnlyHint).toBe(true);
    // Direct property should NOT override
    expect(tools[0].readOnlyHint).toBeUndefined();
  });

  it("should handle tools with no raw match gracefully", async () => {
    mockClient.listTools.mockImplementation(async () => {
      if (mockTransport.onmessage) {
        mockTransport.onmessage({
          result: {
            tools: [
              { name: "tool_a", readOnlyHint: true },
              // tool_b missing from raw
            ],
          },
        });
      }
      return {
        tools: [
          { name: "tool_a" },
          { name: "tool_b" }, // Not in raw response
        ],
      };
    });

    const tools = await getToolsWithPreservedHints(mockClient as any);

    expect(tools).toHaveLength(2);
    expect(tools[0].readOnlyHint).toBe(true);
    expect(tools[1].readOnlyHint).toBeUndefined();
  });

  it("should fallback to SDK tools when transport not available", async () => {
    mockClient.transport = null;
    mockClient.listTools.mockImplementation(async () => ({
      tools: [{ name: "test_tool", annotations: { readOnlyHint: true } }],
    }));

    const tools = await getToolsWithPreservedHints(mockClient as any);

    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe("test_tool");
  });

  it("should fallback to SDK tools when raw capture fails", async () => {
    mockClient.listTools.mockImplementation(async () => {
      // Don't trigger onmessage (simulating capture failure)
      return {
        tools: [{ name: "fallback_tool" }],
      };
    });

    const tools = await getToolsWithPreservedHints(mockClient as any);

    expect(tools).toHaveLength(1);
    expect(tools[0].name).toBe("fallback_tool");
  });

  it("should preserve hints from metadata object", async () => {
    mockClient.listTools.mockImplementation(async () => {
      if (mockTransport.onmessage) {
        mockTransport.onmessage({
          result: {
            tools: [
              {
                name: "query_db",
                metadata: {
                  readOnlyHint: true,
                },
              },
            ],
          },
        });
      }
      return { tools: [{ name: "query_db" }] };
    });

    const tools = await getToolsWithPreservedHints(mockClient as any);

    expect(tools[0].readOnlyHint).toBe(true);
  });

  it("should preserve hints from _meta object", async () => {
    mockClient.listTools.mockImplementation(async () => {
      if (mockTransport.onmessage) {
        mockTransport.onmessage({
          result: {
            tools: [
              {
                name: "custom_tool",
                _meta: {
                  destructiveHint: true,
                },
              },
            ],
          },
        });
      }
      return { tools: [{ name: "custom_tool" }] };
    });

    const tools = await getToolsWithPreservedHints(mockClient as any);

    expect(tools[0].destructiveHint).toBe(true);
  });

  it("should restore original onmessage handler after call", async () => {
    const originalHandler = jest.fn();
    mockTransport.onmessage = originalHandler;

    mockClient.listTools.mockImplementation(async () => {
      if (mockTransport.onmessage) {
        mockTransport.onmessage({ result: { tools: [] } });
      }
      return { tools: [] };
    });

    await getToolsWithPreservedHints(mockClient as any);

    // Original handler should be restored
    expect(mockTransport.onmessage).toBe(originalHandler);
  });

  it("should restore handler even on error", async () => {
    const originalHandler = jest.fn();
    mockTransport.onmessage = originalHandler;

    mockClient.listTools.mockImplementation(async () => {
      throw new Error("Test error");
    });

    await expect(getToolsWithPreservedHints(mockClient as any)).rejects.toThrow(
      "Test error",
    );

    // Original handler should be restored despite error
    expect(mockTransport.onmessage).toBe(originalHandler);
  });
});
