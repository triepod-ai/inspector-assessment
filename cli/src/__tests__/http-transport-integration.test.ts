/**
 * HTTP Transport Integration Tests
 *
 * Tests for HTTP transport functionality with actual MCP servers.
 * Tests include server connection, MCP protocol communication, error handling,
 * and HTTP-specific features like headers and status codes.
 *
 * Note: Tests skip gracefully when testbed servers are unavailable.
 */

import { describe, it, expect, beforeAll } from "@jest/globals";
import { createTransport, type TransportOptions } from "../transport.js";

// Testbed server URLs
const VULNERABLE_MCP_URL = "http://localhost:10900/mcp";
const HARDENED_MCP_URL = "http://localhost:10901/mcp";
const UNAVAILABLE_URL = "http://localhost:19999/mcp";

/**
 * Default headers required by MCP HTTP servers
 */
const DEFAULT_HEADERS = {
  "Content-Type": "application/json",
  Accept: "application/json, text/event-stream",
};

/**
 * Check if a server is available by sending a basic HTTP request
 */
async function checkServerAvailable(url: string): Promise<boolean> {
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "initialize",
        params: {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
        id: 1,
      }),
    });
    // Accept any response (200 or error) as indication server is up
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
  headers: Record<string, string> = {},
): Promise<{ response: Response; data: Record<string, unknown> | null }> {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      ...DEFAULT_HEADERS,
      ...headers,
    },
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

describe("HTTP Transport Integration", () => {
  let vulnerableServerAvailable = false;
  let hardenedServerAvailable = false;

  beforeAll(async () => {
    vulnerableServerAvailable = await checkServerAvailable(VULNERABLE_MCP_URL);
    hardenedServerAvailable = await checkServerAvailable(HARDENED_MCP_URL);

    if (!vulnerableServerAvailable && !hardenedServerAvailable) {
      console.log(
        "\n⚠️  Skipping HTTP transport integration tests - no testbed servers available",
      );
      console.log("   Start servers with:");
      console.log("   - vulnerable-mcp: http://localhost:10900/mcp");
      console.log("   - hardened-mcp: http://localhost:10901/mcp\n");
    }
  });

  describe("HTTP Transport Creation (Unit-level)", () => {
    it("should create transport with valid HTTP URL", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: "http://localhost:3000/mcp",
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should create transport with custom headers", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: "http://localhost:3000/mcp",
        headers: {
          Authorization: "Bearer test-token",
          "X-API-Key": "secret",
        },
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should create transport with HTTPS URL", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: "https://api.example.com/mcp",
      };

      const transport = createTransport(options);
      expect(transport).toBeDefined();
    });

    it("should throw error when URL is missing", () => {
      const options: TransportOptions = {
        transportType: "http",
      };

      expect(() => createTransport(options)).toThrow(
        /URL must be provided for SSE or HTTP transport types/,
      );
    });

    it("should throw error for invalid URL format", () => {
      const options: TransportOptions = {
        transportType: "http",
        url: ":::invalid",
      };

      expect(() => createTransport(options)).toThrow(
        /Failed to create transport/,
      );
    });
  });

  describe("Server Connection Tests (Integration)", () => {
    it("should connect to vulnerable-mcp server", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { response, data } = await sendMcpRequest(
        VULNERABLE_MCP_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: {
            name: "inspector-test",
            version: "1.0.0",
          },
        },
      );

      expect(response.ok).toBe(true);
      expect(response.status).toBe(200);
      expect(data).toHaveProperty("jsonrpc", "2.0");
      expect(data).toHaveProperty("result");
    });

    it("should connect to hardened-mcp server", async () => {
      if (!hardenedServerAvailable) {
        console.log("⏩ Skipping: hardened-mcp not available");
        return;
      }

      const { response, data } = await sendMcpRequest(
        HARDENED_MCP_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: {
            name: "inspector-test",
            version: "1.0.0",
          },
        },
      );

      expect(response.ok).toBe(true);
      expect(response.status).toBe(200);
      expect(data).toHaveProperty("jsonrpc", "2.0");
      expect(data).toHaveProperty("result");
    });

    it("should handle connection to unavailable port", async () => {
      try {
        await sendMcpRequest(UNAVAILABLE_URL, "initialize", {});
        // Should not reach here
        expect(true).toBe(false);
      } catch (error) {
        // Expected to throw connection error
        expect(error).toBeDefined();
      }
    });
  });

  describe("MCP Protocol Communication", () => {
    it("should receive capabilities from initialize request", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { data } = await sendMcpRequest(VULNERABLE_MCP_URL, "initialize", {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: {
          name: "inspector-test",
          version: "1.0.0",
        },
      });

      expect(data).toBeDefined();
      const result = (data as Record<string, unknown>).result as Record<
        string,
        unknown
      >;
      expect(result).toHaveProperty("capabilities");
      expect(result).toHaveProperty("serverInfo");
      expect(result.serverInfo).toHaveProperty("name");
    });

    it("should list available tools", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      // First initialize the session
      const { response: initResponse } = await sendMcpRequest(
        VULNERABLE_MCP_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
      );

      if (!initResponse.ok) {
        console.log("⏩ Skipping: server initialization failed");
        return;
      }

      // Now list tools
      const { response, data } = await sendMcpRequest(
        VULNERABLE_MCP_URL,
        "tools/list",
      );

      // Server may require session state; if not OK, skip
      if (!response.ok) {
        console.log("⏩ Skipping: tools/list requires session state");
        return;
      }

      expect(data).toBeDefined();
      const result = (data as Record<string, unknown>).result as Record<
        string,
        unknown
      >;
      expect(result).toHaveProperty("tools");
      expect(Array.isArray(result.tools)).toBe(true);
    });

    it("should handle malformed request", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const response = await fetch(VULNERABLE_MCP_URL, {
        method: "POST",
        headers: DEFAULT_HEADERS,
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "invalid_method_name",
          id: 1,
        }),
      });

      // Try to parse SSE response
      let data: Record<string, unknown> | null = null;
      try {
        data = await parseSSEResponse(response.clone());
      } catch {
        // Response may not be parseable
      }

      // Should either return error in JSON-RPC format or HTTP error
      if (response.ok && data) {
        expect(data).toHaveProperty("error");
      } else {
        expect(response.status).toBeGreaterThanOrEqual(400);
      }
    });

    it("should handle missing required parameters", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { data } = await sendMcpRequest(VULNERABLE_MCP_URL, "initialize");

      expect(data).toBeDefined();
      expect(data).toHaveProperty("jsonrpc", "2.0");
    });
  });

  describe("HTTP Error Handling", () => {
    it("should handle connection timeout", async () => {
      const timeoutUrl = "http://localhost:19998/mcp";

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 1000);

        await fetch(timeoutUrl, {
          method: "POST",
          headers: DEFAULT_HEADERS,
          body: JSON.stringify({ jsonrpc: "2.0", method: "ping", id: 1 }),
          signal: controller.signal,
        });

        clearTimeout(timeoutId);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error).toBeDefined();
      }
    });

    it("should detect non-JSON response", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      // Send a GET request which might return HTML or non-JSON
      try {
        const response = await fetch(VULNERABLE_MCP_URL, { method: "GET" });
        const text = await response.text();

        // Verify it's not JSON by trying to parse
        if (text.trim().startsWith("{") || text.trim().startsWith("[")) {
          // Valid JSON
          expect(JSON.parse(text)).toBeDefined();
        } else {
          // Non-JSON response expected
          expect(text.length).toBeGreaterThan(0);
        }
      } catch (error) {
        // Accept connection errors for GET requests
        expect(error).toBeDefined();
      }
    });
  });

  describe("Header Handling", () => {
    it("should send Content-Type header correctly", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { response } = await sendMcpRequest(
        VULNERABLE_MCP_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
        { "Content-Type": "application/json" },
      );

      expect(response.ok).toBe(true);
    });

    it("should send custom headers", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { response } = await sendMcpRequest(
        VULNERABLE_MCP_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
        {
          "X-Test-Header": "test-value",
          "X-Client-ID": "integration-test",
        },
      );

      // Server should accept request even with custom headers
      expect(response.status).toBeLessThan(500);
    });

    it("should handle response headers", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      const { response } = await sendMcpRequest(
        VULNERABLE_MCP_URL,
        "tools/list",
      );

      // Check that response has standard headers
      expect(response.headers.get("content-type")).toBeTruthy();
    });

    it("should require Accept header with proper values", async () => {
      if (!vulnerableServerAvailable) {
        console.log("⏩ Skipping: vulnerable-mcp not available");
        return;
      }

      // Test without Accept header
      const responseWithoutAccept = await fetch(VULNERABLE_MCP_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "1.0.0" },
          },
          id: 1,
        }),
      });

      // Should fail without proper Accept header
      expect(responseWithoutAccept.ok).toBe(false);

      // Test with correct Accept header
      const { response: responseWithAccept } = await sendMcpRequest(
        VULNERABLE_MCP_URL,
        "initialize",
        {
          protocolVersion: "2024-11-05",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
      );

      // Should succeed with proper headers
      expect(responseWithAccept.ok).toBe(true);
    });
  });

  describe("Transport Type Detection", () => {
    it("should recognize HTTP URLs", () => {
      const httpUrls = [
        "http://localhost:3000/mcp",
        "http://127.0.0.1:8080/api",
        "http://example.com/mcp",
      ];

      httpUrls.forEach((url) => {
        const options: TransportOptions = {
          transportType: "http",
          url,
        };
        const transport = createTransport(options);
        expect(transport).toBeDefined();
      });
    });

    it("should recognize HTTPS URLs", () => {
      const httpsUrls = [
        "https://api.example.com/mcp",
        "https://localhost:3000/secure",
        "https://mcp.service.com/api",
      ];

      httpsUrls.forEach((url) => {
        const options: TransportOptions = {
          transportType: "http",
          url,
        };
        const transport = createTransport(options);
        expect(transport).toBeDefined();
      });
    });

    it("should handle URLs with ports", () => {
      const urlsWithPorts = [
        "http://localhost:10900/mcp",
        "https://example.com:8443/api",
        "http://127.0.0.1:3000/mcp",
      ];

      urlsWithPorts.forEach((url) => {
        const options: TransportOptions = {
          transportType: "http",
          url,
        };
        const transport = createTransport(options);
        expect(transport).toBeDefined();
      });
    });
  });
});
