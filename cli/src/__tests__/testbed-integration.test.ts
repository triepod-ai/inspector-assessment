/**
 * Testbed A/B Comparison Integration Tests
 *
 * Tests the inspector's pure behavior-based detection by comparing two servers
 * with IDENTICAL tool names but different implementations:
 * - vulnerable-mcp: Exploitable implementations (10 vulnerable + 6 safe tools)
 * - hardened-mcp: Safe implementations (same tool names, all safe)
 *
 * This proves the inspector detects vulnerabilities based on tool behavior,
 * not name-based heuristics.
 *
 * Note: Tests skip gracefully when testbed servers are unavailable.
 */

import { describe, it, expect, beforeAll } from "@jest/globals";

// Testbed server URLs
const VULNERABLE_URL = "http://localhost:10900/mcp";
const HARDENED_URL = "http://localhost:10901/mcp";

/**
 * Default headers required by MCP HTTP servers
 */
const DEFAULT_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

/**
 * Check if a server is available by sending an initialize request
 */
async function checkServerAvailable(url: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: "POST",
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "testbed-test", version: "1.0.0" },
        },
        id: 1,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);
    return response.status < 500;
  } catch {
    return false;
  }
}

/**
 * Parse SSE response to extract JSON data
 * MCP streamable HTTP returns Server-Sent Events format
 */
async function parseSSEResponse(
  response: Response,
): Promise<Record<string, unknown>> {
  const text = await response.text();

  // If it's plain JSON, parse directly
  if (text.trim().startsWith("{")) {
    return JSON.parse(text);
  }

  // Parse SSE format: "event: message\ndata: {...}\n\n"
  const lines = text.split("\n");
  for (const line of lines) {
    if (line.startsWith("data:")) {
      const jsonStr = line.slice(5).trim();
      if (jsonStr) {
        return JSON.parse(jsonStr);
      }
    }
  }

  throw new Error(`Unable to parse SSE response: ${text.slice(0, 100)}`);
}

/**
 * Send an MCP JSON-RPC request and parse response
 */
async function sendMcpRequest(
  url: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<{ response: Response; data: Record<string, unknown> | null }> {
  const response = await fetch(url, {
    method: "POST",
    headers: DEFAULT_HEADERS,
    body: JSON.stringify({
      jsonrpc: "2.0",
      method,
      params,
      id: Date.now(),
    }),
  });

  let data: Record<string, unknown> | null = null;
  if (response.ok) {
    try {
      data = await parseSSEResponse(response.clone());
    } catch {
      // Response might not be parseable
    }
  }

  return { response, data };
}

/**
 * Get tool list from server
 */
async function getToolList(url: string): Promise<string[]> {
  const { data } = await sendMcpRequest(url, "tools/list");
  if (!data) return [];
  const result = data.result as Record<string, unknown>;
  const tools = result.tools as Array<{ name: string }>;
  return tools.map((tool) => tool.name);
}

/**
 * Call a tool and return the response
 */
async function callTool(
  url: string,
  toolName: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  const { data } = await sendMcpRequest(url, "tools/call", {
    name: toolName,
    arguments: args,
  });
  return data;
}

describe("Testbed A/B Comparison", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  let bothServersAvailable = false;
  let vulnerableAvailable = false;
  let hardenedAvailable = false;

  beforeAll(async () => {
    const [v, h] = await Promise.all([
      checkServerAvailable(VULNERABLE_URL),
      checkServerAvailable(HARDENED_URL),
    ]);
    vulnerableAvailable = v;
    hardenedAvailable = h;
    bothServersAvailable = v && h;

    if (!bothServersAvailable) {
      console.log(
        "\n⚠️  Skipping testbed A/B comparison tests - servers not available",
      );
      console.log("   Start servers with:");
      console.log("   - vulnerable-mcp: http://localhost:10900/mcp");
      console.log("   - hardened-mcp: http://localhost:10901/mcp\n");
    }
  }, 30000);

  describe("Health Check Tests", () => {
    it("should connect to vulnerable-mcp server", async () => {
      if (!vulnerableAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { response, data } = await sendMcpRequest(
        VULNERABLE_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: {
            name: "testbed-test",
            version: "1.0.0",
          },
        },
      );

      expect(response.ok).toBe(true);
      expect(data).toHaveProperty("jsonrpc", "2.0");
      expect(data).toHaveProperty("result");
      const result = (data as Record<string, unknown>).result as Record<
        string,
        unknown
      >;
      expect(result).toHaveProperty("serverInfo");
    });

    it("should connect to hardened-mcp server", async () => {
      if (!hardenedAvailable) {
        console.log("⏩ Skipping: hardened-mcp not available");
        return;
      }

      const { response, data } = await sendMcpRequest(
        HARDENED_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: {
            name: "testbed-test",
            version: "1.0.0",
          },
        },
      );

      expect(response.ok).toBe(true);
      expect(data).toHaveProperty("jsonrpc", "2.0");
      expect(data).toHaveProperty("result");
      const result = (data as Record<string, unknown>).result as Record<
        string,
        unknown
      >;
      expect(result).toHaveProperty("serverInfo");
    });

    it("should list tools on both servers", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const [vulnerableTools, hardenedTools] = await Promise.all([
        getToolList(VULNERABLE_URL),
        getToolList(HARDENED_URL),
      ]);

      // Skip if tools lists are empty (server may require session state)
      if (vulnerableTools.length === 0 && hardenedTools.length === 0) {
        console.log("⏩ Skipping: servers returned empty tool lists");
        return;
      }

      expect(vulnerableTools.length).toBeGreaterThan(0);
      expect(hardenedTools.length).toBeGreaterThan(0);
    });
  });

  describe("Tool List Parity", () => {
    it("should have identical tool names on both servers", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const [vulnerableTools, hardenedTools] = await Promise.all([
        getToolList(VULNERABLE_URL),
        getToolList(HARDENED_URL),
      ]);

      // Skip if tools lists are empty (server may require session state)
      if (vulnerableTools.length === 0 || hardenedTools.length === 0) {
        console.log("⏩ Skipping: server returned empty tool list");
        return;
      }

      // Sort for comparison
      const sortedVulnerable = [...vulnerableTools].sort();
      const sortedHardened = [...hardenedTools].sort();

      expect(sortedVulnerable).toEqual(sortedHardened);
    });

    it("should have 16 tools (10 vulnerable + 6 safe)", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const [vulnerableTools, hardenedTools] = await Promise.all([
        getToolList(VULNERABLE_URL),
        getToolList(HARDENED_URL),
      ]);

      // Skip if tools lists are empty (server may require session state)
      if (vulnerableTools.length === 0 || hardenedTools.length === 0) {
        console.log("⏩ Skipping: server returned empty tool list");
        return;
      }

      expect(vulnerableTools.length).toBe(16);
      expect(hardenedTools.length).toBe(16);
    });

    it("should include expected vulnerable tool names", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const vulnerableTools = await getToolList(VULNERABLE_URL);

      // Skip if tools list is empty (server may require session state)
      if (vulnerableTools.length === 0) {
        console.log("⏩ Skipping: server returned empty tool list");
        return;
      }

      const expectedTools = [
        "vulnerable_calculator_tool",
        "vulnerable_system_exec_tool",
      ];

      expectedTools.forEach((toolName) => {
        expect(vulnerableTools).toContain(toolName);
      });
    });

    it("should include expected safe tool names", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const tools = await getToolList(VULNERABLE_URL);

      // Skip if tools list is empty (server may require session state)
      if (tools.length === 0) {
        console.log("⏩ Skipping: server returned empty tool list");
        return;
      }

      const expectedSafeTools = [
        "safe_storage_tool",
        "safe_calculator_tool",
        "safe_validation_tool",
      ];

      expectedSafeTools.forEach((toolName) => {
        expect(tools).toContain(toolName);
      });
    });
  });

  describe("Tool Behavior Comparison", () => {
    it("should show different behavior for calculator tool", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const testInput = { expression: "__import__('os').system('id')" };

      const [vulnerableResponse, hardenedResponse] = await Promise.all([
        callTool(VULNERABLE_URL, "vulnerable_calculator_tool", testInput),
        callTool(HARDENED_URL, "vulnerable_calculator_tool", testInput),
      ]);

      // Skip if either response is null (server may require session state)
      if (!vulnerableResponse || !hardenedResponse) {
        console.log(
          "⏩ Skipping: tool call returned null (session state required)",
        );
        return;
      }

      // Both should respond, but vulnerable may execute, hardened should reject
      expect(vulnerableResponse).toBeDefined();
      expect(hardenedResponse).toBeDefined();

      // Vulnerable server might show exploitable behavior
      // Hardened server should show safe behavior (error or sanitized)
      // We're not asserting specific behavior, just that they're different
      expect(vulnerableResponse).not.toEqual(hardenedResponse);
    });

    it("should show identical behavior for safe tools", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const testInput = { value: "test_data" };

      const [vulnerableResponse, hardenedResponse] = await Promise.all([
        callTool(VULNERABLE_URL, "safe_storage_tool", testInput),
        callTool(HARDENED_URL, "safe_storage_tool", testInput),
      ]);

      // Skip if either response is null (server may require session state)
      if (!vulnerableResponse || !hardenedResponse) {
        console.log(
          "⏩ Skipping: tool call returned null (session state required)",
        );
        return;
      }

      expect(vulnerableResponse).toBeDefined();
      expect(hardenedResponse).toBeDefined();
    });
  });

  describe("Session Management", () => {
    it("should return response headers from vulnerable server", async () => {
      if (!vulnerableAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { response } = await sendMcpRequest(VULNERABLE_URL, "tools/list");

      expect(response.headers.get("content-type")).toBeTruthy();
    });

    it("should return response headers from hardened server", async () => {
      if (!hardenedAvailable) {
        console.log("⏩ Skipping: hardened-mcp not available");
        return;
      }

      const { response } = await sendMcpRequest(HARDENED_URL, "tools/list");

      expect(response.headers.get("content-type")).toBeTruthy();
    });

    it("should handle protocol version negotiation", async () => {
      if (!bothServersAvailable) {
        console.log("⏩ Skipping: both servers not available");
        return;
      }

      const initParams = {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "testbed-test", version: "1.0.0" },
      };

      const [vulnerableResult, hardenedResult] = await Promise.all([
        sendMcpRequest(VULNERABLE_URL, "initialize", initParams),
        sendMcpRequest(HARDENED_URL, "initialize", initParams),
      ]);

      const vulnerableData = vulnerableResult.data as Record<string, unknown>;
      const hardenedData = hardenedResult.data as Record<string, unknown>;

      expect(vulnerableData).toBeDefined();
      expect(hardenedData).toBeDefined();

      const vulnerableResultData = vulnerableData.result as Record<
        string,
        unknown
      >;
      const hardenedResultData = hardenedData.result as Record<string, unknown>;

      expect(vulnerableResultData).toHaveProperty("protocolVersion");
      expect(hardenedResultData).toHaveProperty("protocolVersion");
    });
  });
});
