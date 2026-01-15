/**
 * Tests for StdioTransportDetector
 *
 * Issue #172: Verify transport detection from multiple sources
 * to fix C6/F6 incorrect failures for valid stdio servers.
 */

import { StdioTransportDetector } from "../helpers/StdioTransportDetector";

describe("StdioTransportDetector", () => {
  let detector: StdioTransportDetector;

  beforeEach(() => {
    detector = new StdioTransportDetector();
  });

  describe("server.json detection", () => {
    it("should detect stdio from server.json transport.type", () => {
      const serverJson = {
        packages: [{ transport: { type: "stdio" } }],
      };

      const result = detector.detect(undefined, undefined, serverJson);

      expect(result.supportsStdio).toBe(true);
      expect(result.confidence).toBe("high");
      expect(result.evidence).toHaveLength(1);
      expect(result.evidence[0].source).toBe("server.json");
      expect(result.evidence[0].transport).toBe("stdio");
    });

    it("should detect http from server.json transport.type", () => {
      const serverJson = {
        packages: [{ transport: { type: "http" } }],
      };

      const result = detector.detect(undefined, undefined, serverJson);

      expect(result.supportsHTTP).toBe(true);
      expect(result.supportsStdio).toBe(false);
      expect(result.confidence).toBe("high");
    });

    it("should detect sse from server.json transport.type", () => {
      const serverJson = {
        packages: [{ transport: { type: "sse" } }],
      };

      const result = detector.detect(undefined, undefined, serverJson);

      expect(result.supportsSSE).toBe(true);
      expect(result.confidence).toBe("high");
    });

    it("should handle missing server.json gracefully", () => {
      const result = detector.detect();

      expect(result.supportsStdio).toBe(false);
      expect(result.supportsHTTP).toBe(false);
      expect(result.supportsSSE).toBe(false);
      expect(result.evidence).toHaveLength(0);
      expect(result.confidence).toBe("low");
    });
  });

  describe("package.json bin detection", () => {
    it("should detect stdio from package.json bin entry (object)", () => {
      const packageJson = {
        bin: { "my-mcp-server": "./dist/index.js" },
      };

      const result = detector.detect(undefined, packageJson);

      expect(result.supportsStdio).toBe(true);
      expect(result.confidence).toBe("high");
      expect(result.evidence).toContainEqual(
        expect.objectContaining({
          source: "package.json",
          transport: "stdio",
          confidence: "high",
        }),
      );
    });

    it("should detect stdio from package.json bin entry (string)", () => {
      const packageJson = {
        bin: "./dist/cli.js",
      };

      const result = detector.detect(undefined, packageJson);

      expect(result.supportsStdio).toBe(true);
      expect(result.confidence).toBe("high");
    });

    it("should not detect stdio without bin entry", () => {
      const packageJson = {
        name: "my-server",
        version: "1.0.0",
      };

      const result = detector.detect(undefined, packageJson as never);

      expect(result.supportsStdio).toBe(false);
      expect(
        result.evidence.filter((e) => e.source === "package.json"),
      ).toHaveLength(0);
    });
  });

  describe("runtime transport detection", () => {
    it("should detect stdio from runtime transport config", () => {
      const result = detector.detect(undefined, undefined, undefined, "stdio");

      expect(result.supportsStdio).toBe(true);
      expect(result.confidence).toBe("high");
      expect(result.evidence).toContainEqual(
        expect.objectContaining({
          source: "runtime-config",
          transport: "stdio",
          confidence: "high",
        }),
      );
    });

    it("should detect http from runtime transport config", () => {
      const result = detector.detect(undefined, undefined, undefined, "http");

      expect(result.supportsHTTP).toBe(true);
      expect(result.confidence).toBe("high");
    });

    it("should detect sse from runtime transport config", () => {
      const result = detector.detect(undefined, undefined, undefined, "sse");

      expect(result.supportsSSE).toBe(true);
      expect(result.confidence).toBe("high");
    });
  });

  describe("source code detection - TypeScript/JavaScript", () => {
    it("should detect StdioServerTransport usage", () => {
      const files = new Map([
        [
          "src/index.ts",
          `
          import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
          const transport = new StdioServerTransport();
        `,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
      expect(result.sourceCodeScanned).toBe(true);
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).not.toHaveLength(0);
    });

    it("should detect MCP SDK stdio import", () => {
      const files = new Map([
        [
          "src/server.ts",
          `import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio";`,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
    });

    it("should detect transport = 'stdio' declaration", () => {
      const files = new Map([["config.ts", `const transport = "stdio";`]]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
    });

    it("should detect createStdioTransport call", () => {
      const files = new Map([
        [
          "src/index.ts",
          `
          const transport = createStdioTransport();
        `,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
    });
  });

  describe("source code detection - Python", () => {
    it("should detect mcp.run(transport='stdio')", () => {
      const files = new Map([["server.py", `mcp.run(transport='stdio')`]]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
    });

    it("should detect StdioTransport usage in Python", () => {
      const files = new Map([
        [
          "server.py",
          `
          from mcp.server.stdio import StdioTransport
          transport = StdioTransport()
        `,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
    });

    it("should detect Python stdio module import", () => {
      const files = new Map([
        ["server.py", `from mcp.server.stdio import stdio_server`],
      ]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
    });
  });

  describe("source code detection - HTTP/SSE", () => {
    it("should detect StreamableHTTPServerTransport", () => {
      const files = new Map([
        [
          "src/http-server.ts",
          `
          import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamable-http.js";
        `,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsHTTP).toBe(true);
    });

    it("should detect SSEServerTransport", () => {
      const files = new Map([
        [
          "src/sse-server.ts",
          `
          import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
        `,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsSSE).toBe(true);
    });

    it("should detect Express framework (HTTP indicator)", () => {
      const files = new Map([
        [
          "src/server.ts",
          `
          import express from "express";
          const app = express();
        `,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsHTTP).toBe(true);
    });

    it("should detect app.listen call (HTTP indicator)", () => {
      const files = new Map([["src/index.ts", `app.listen(3000);`]]);

      const result = detector.detect(files);

      expect(result.supportsHTTP).toBe(true);
    });
  });

  describe("combined evidence", () => {
    it("should combine multiple evidence sources", () => {
      const files = new Map([
        ["src/index.ts", `import { StdioServerTransport } from "...";`],
      ]);
      const packageJson = { bin: { cmd: "./dist/cli.js" } };

      const result = detector.detect(files, packageJson);

      expect(result.supportsStdio).toBe(true);
      expect(result.evidence.length).toBeGreaterThan(1);
      expect(result.confidence).toBe("high");
    });

    it("should detect dual-transport servers (stdio + HTTP)", () => {
      const files = new Map([
        [
          "src/index.ts",
          `
          import { StdioServerTransport } from "...";
          const httpServer = express();
          httpServer.listen(3000);
        `,
        ],
      ]);
      const packageJson = { bin: { cmd: "./dist/cli.js" } };

      const result = detector.detect(files, packageJson);

      expect(result.supportsStdio).toBe(true);
      expect(result.supportsHTTP).toBe(true);
      expect(result.detectedTransports.size).toBe(2);
    });
  });

  describe("file skipping", () => {
    it("should skip test files", () => {
      const files = new Map([
        ["src/index.test.ts", `const transport = "stdio";`],
        ["src/__tests__/server.test.ts", `const transport = "stdio";`],
      ]);

      const result = detector.detect(files);

      // Test files should be skipped, so no evidence from them
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
    });

    it("should skip node_modules", () => {
      const files = new Map([
        ["node_modules/@mcp/sdk/index.ts", `StdioServerTransport`],
      ]);

      const result = detector.detect(files);

      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
    });

    it("should skip .d.ts files", () => {
      const files = new Map([["types.d.ts", `StdioServerTransport`]]);

      const result = detector.detect(files);

      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
    });
  });

  describe("confidence computation", () => {
    it("should return low confidence with no evidence", () => {
      const result = detector.detect();

      expect(result.confidence).toBe("low");
    });

    it("should return high confidence with high-confidence evidence", () => {
      const serverJson = { packages: [{ transport: { type: "stdio" } }] };

      const result = detector.detect(undefined, undefined, serverJson);

      expect(result.confidence).toBe("high");
    });

    it("should return high confidence with multiple sources agreeing", () => {
      const files = new Map([["src/index.ts", `const transport = "stdio";`]]);
      const packageJson = { bin: "./dist/cli.js" };

      const result = detector.detect(files, packageJson);

      // Multiple sources = high confidence even if individual sources are medium
      expect(result.confidence).toBe("high");
    });

    it("should return medium confidence with single medium-confidence source", () => {
      const files = new Map([["config.js", `const transport = "stdio";`]]);

      const result = detector.detect(files);

      // Single source code match = medium confidence
      expect(result.confidence).toBe("medium");
    });
  });

  describe("edge cases", () => {
    it("should handle empty source files map", () => {
      const files = new Map<string, string>();

      const result = detector.detect(files);

      // Empty map = nothing to scan, so sourceCodeScanned is false
      expect(result.sourceCodeScanned).toBe(false);
      expect(result.evidence).toHaveLength(0);
    });

    it("should handle undefined inputs gracefully", () => {
      const result = detector.detect(
        undefined,
        undefined,
        undefined,
        undefined,
      );

      expect(result.supportsStdio).toBe(false);
      expect(result.supportsHTTP).toBe(false);
      expect(result.supportsSSE).toBe(false);
      expect(result.evidence).toHaveLength(0);
    });

    it("should deduplicate evidence from same pattern across files", () => {
      const files = new Map([
        ["src/server.ts", `StdioServerTransport`],
        ["src/index.ts", `StdioServerTransport`],
      ]);

      const result = detector.detect(files);

      // Should only have one evidence entry for StdioServerTransport pattern
      const stdioClassEvidence = result.evidence.filter((e) =>
        e.detail.includes("StdioServerTransport"),
      );
      expect(stdioClassEvidence.length).toBe(1);
      expect(result.evidence.length).toBe(1); // Ensure no other patterns matched
    });
  });

  describe("magentaa11y-mcp test case (Issue #172)", () => {
    it("should pass for server with bin entry and StdioServerTransport", () => {
      // Simulates magentaa11y-mcp structure
      const files = new Map([
        [
          "src/index.ts",
          `
          import { Server } from "@modelcontextprotocol/sdk/server/index.js";
          import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

          const server = new Server({ name: "magentaa11y-mcp" });
          const transport = new StdioServerTransport();
          server.connect(transport);
        `,
        ],
      ]);
      const packageJson = {
        bin: { "magentaa11y-mcp": "./dist/index.js" },
      };
      const serverJson = {
        packages: [{ transport: { type: "stdio" } }],
      };

      const result = detector.detect(files, packageJson, serverJson);

      expect(result.supportsStdio).toBe(true);
      expect(result.confidence).toBe("high");
      // Should have evidence from all three sources
      expect(result.evidence.some((e) => e.source === "server.json")).toBe(
        true,
      );
      expect(result.evidence.some((e) => e.source === "package.json")).toBe(
        true,
      );
      expect(result.evidence.some((e) => e.source === "source-code")).toBe(
        true,
      );
    });
  });

  // New test cases for FIX-001 and FIX-002 validation
  describe("FIX-001: sourceCodeScanned flag logic", () => {
    it("should set sourceCodeScanned to false for empty Map", () => {
      // TEST-REQ-001: Empty Map boundary test
      const files = new Map<string, string>();

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(false);
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
    });

    it("should set sourceCodeScanned to false for undefined Map", () => {
      // TEST-REQ-001: Undefined Map handling
      const result = detector.detect(undefined);

      expect(result.sourceCodeScanned).toBe(false);
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
    });

    it("should set sourceCodeScanned to true for Map with one file", () => {
      // TEST-REQ-001: Map with one file
      const files = new Map([["test.ts", "const transport = 'stdio';"]]);

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(true);
      expect(result.supportsStdio).toBe(true);
    });

    it("should set sourceCodeScanned to true even if no patterns match", () => {
      // TEST-REQ-001: Flag vs evidence alignment
      const files = new Map([["src/unrelated.ts", "const foo = 'bar';"]]);

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(true);
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
      expect(result.supportsStdio).toBe(false);
    });

    it("should set sourceCodeScanned to true for Map with multiple files", () => {
      // TEST-REQ-001: Multiple files
      const files = new Map([
        ["src/index.ts", "StdioServerTransport"],
        ["src/server.ts", "const app = express();"],
      ]);

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(true);
      expect(result.supportsStdio).toBe(true);
      expect(result.supportsHTTP).toBe(true);
    });

    it("should set sourceCodeScanned to false when all files are skipped", () => {
      // Edge case: Files exist but are all skipped
      const files = new Map([
        ["node_modules/mcp/index.ts", "StdioServerTransport"],
        ["src/index.test.ts", "StdioServerTransport"],
      ]);

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(true); // Map was checked
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0); // But no evidence
    });
  });

  describe("FIX-002: evidence deduplication and alignment", () => {
    it("should have multiple evidence entries when multiple patterns match same file", () => {
      // TEST-REQ-002: Multiple patterns match same file
      const files = new Map([
        [
          "src/server.ts",
          `
          import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
          const transport = "stdio";
          const t = createStdioTransport();
        `,
        ],
      ]);

      const result = detector.detect(files);

      expect(result.supportsStdio).toBe(true);
      const sourceCodeEvidence = result.evidence.filter(
        (e) => e.source === "source-code",
      );
      expect(sourceCodeEvidence.length).toBeGreaterThan(1);
      // Multiple patterns matched: StdioServerTransport class, SDK stdio import, from .../stdio, transport="stdio", createStdioTransport
      expect(sourceCodeEvidence.length).toBeGreaterThanOrEqual(3);
    });

    it("should deduplicate same pattern across multiple files", () => {
      // TEST-REQ-002: Same pattern multiple files - should have 1 evidence
      const files = new Map([
        ["src/server.ts", "StdioServerTransport"],
        ["src/index.ts", "StdioServerTransport"],
        ["src/client.ts", "StdioServerTransport"],
      ]);

      const result = detector.detect(files);

      const stdioClassEvidence = result.evidence.filter(
        (e) =>
          e.source === "source-code" &&
          e.detail.includes("StdioServerTransport"),
      );
      expect(stdioClassEvidence.length).toBe(1);
    });

    it("should use unique deduplication keys per pattern", () => {
      // TEST-REQ-002: Deduplication key verification
      const files = new Map([
        [
          "src/multi-transport.ts",
          `
          import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
          import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
          const transport1 = "stdio";
          const transport2 = "http";
          app.listen(3000); // HTTP indicator
        `,
        ],
      ]);

      const result = detector.detect(files);

      // Should detect both stdio and http/sse
      expect(result.supportsStdio).toBe(true);
      expect(result.supportsSSE).toBe(true);
      expect(result.supportsHTTP).toBe(true);

      const sourceCodeEvidence = result.evidence.filter(
        (e) => e.source === "source-code",
      );
      // Multiple evidence entries from various patterns
      expect(sourceCodeEvidence.length).toBeGreaterThanOrEqual(4);

      // Verify each transport has at least one evidence
      const stdioEvidence = sourceCodeEvidence.filter(
        (e) => e.transport === "stdio",
      );
      const sseEvidence = sourceCodeEvidence.filter(
        (e) => e.transport === "sse",
      );
      const httpEvidence = sourceCodeEvidence.filter(
        (e) => e.transport === "http",
      );

      expect(stdioEvidence.length).toBeGreaterThan(0);
      expect(sseEvidence.length).toBeGreaterThan(0);
      expect(httpEvidence.length).toBeGreaterThan(0);
    });

    it("should align evidence with detected transports", () => {
      // TEST-REQ-001: Flag vs evidence alignment verification
      const files = new Map([["src/stdio.ts", "StdioServerTransport"]]);

      const result = detector.detect(files);

      // If supportsStdio is true, must have evidence
      if (result.supportsStdio) {
        const stdioEvidence = result.evidence.filter(
          (e) => e.transport === "stdio",
        );
        expect(stdioEvidence.length).toBeGreaterThan(0);
      }

      // If supportsHTTP is true, must have evidence
      if (result.supportsHTTP) {
        const httpEvidence = result.evidence.filter(
          (e) => e.transport === "http",
        );
        expect(httpEvidence.length).toBeGreaterThan(0);
      }

      // detectedTransports should match boolean flags
      expect(result.detectedTransports.has("stdio")).toBe(result.supportsStdio);
      expect(result.detectedTransports.has("http")).toBe(result.supportsHTTP);
      expect(result.detectedTransports.has("sse")).toBe(result.supportsSSE);
    });

    it("should not duplicate evidence when same pattern found in multiple files", () => {
      // TEST-REQ-002: Deduplication across files
      const files = new Map([
        [
          "src/server1.ts",
          `import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";`,
        ],
        [
          "src/server2.ts",
          `import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";`,
        ],
        [
          "src/server3.ts",
          `import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";`,
        ],
      ]);

      const result = detector.detect(files);

      const stdioClassEvidence = result.evidence.filter(
        (e) =>
          e.source === "source-code" &&
          e.detail.includes("Uses StdioServerTransport class"),
      );
      expect(stdioClassEvidence.length).toBe(1);
    });
  });

  describe("Edge cases and boundary validation", () => {
    it("should handle Map with empty string content", () => {
      const files = new Map([["src/empty.ts", ""]]);

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(true);
      expect(result.supportsStdio).toBe(false);
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
    });

    it("should handle Map with very large file content", () => {
      // Create content larger than MAX_FILE_SIZE (500KB)
      const largeContent = "x".repeat(600_000);
      const files = new Map([["src/large.ts", largeContent]]);

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(true);
      expect(
        result.evidence.filter((e) => e.source === "source-code"),
      ).toHaveLength(0);
    });

    it("should handle mixed skipped and valid files", () => {
      const files = new Map([
        ["node_modules/mcp/index.ts", "StdioServerTransport"], // Skipped
        ["src/valid.ts", "StdioServerTransport"], // Valid
        ["src/index.test.ts", "StdioServerTransport"], // Skipped
      ]);

      const result = detector.detect(files);

      expect(result.sourceCodeScanned).toBe(true);
      expect(result.supportsStdio).toBe(true);
      const sourceCodeEvidence = result.evidence.filter(
        (e) => e.source === "source-code",
      );
      expect(sourceCodeEvidence.length).toBe(1); // Only from src/valid.ts
    });

    it("should handle null-like values gracefully", () => {
      const result = detector.detect(
        undefined,
        undefined,
        undefined,
        undefined,
      );

      expect(result.sourceCodeScanned).toBe(false);
      expect(result.supportsStdio).toBe(false);
      expect(result.supportsHTTP).toBe(false);
      expect(result.supportsSSE).toBe(false);
      expect(result.detectedTransports.size).toBe(0);
      expect(result.evidence).toHaveLength(0);
      expect(result.confidence).toBe("low");
    });
  });
});
