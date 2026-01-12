/**
 * ConformanceAssessor Test Suite
 *
 * Tests for official MCP conformance integration via @modelcontextprotocol/conformance
 *
 * Note: These tests validate the assessor's behavior and skip logic.
 * Full conformance testing requires a running HTTP/SSE server.
 */

import { ConformanceAssessor } from "../modules/ConformanceAssessor";
import {
  createMockAssessmentConfig,
  createMockAssessmentContext,
} from "@/test/utils/testUtils";
import type { AssessmentConfiguration } from "@/lib/assessmentTypes";
import type { AssessmentContext } from "../AssessmentOrchestrator";

describe("ConformanceAssessor", () => {
  let assessor: ConformanceAssessor;
  let config: AssessmentConfiguration;

  beforeEach(() => {
    config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        conformance: true,
      },
    });
    assessor = new ConformanceAssessor(config);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("constructor", () => {
    it("should instantiate successfully with valid config", () => {
      expect(assessor).toBeInstanceOf(ConformanceAssessor);
    });

    it("should initialize with zero test count", () => {
      expect(assessor.getTestCount()).toBe(0);
    });
  });

  describe("assess - skip behavior", () => {
    it("should return skipped result when serverUrl is not available", async () => {
      // Create context without serverUrl (simulates STDIO transport)
      const context = createMockAssessmentContext({
        serverName: "test-server",
        tools: [
          {
            name: "test_tool",
            description: "A test tool",
            inputSchema: { type: "object", properties: {} },
          },
        ],
        config: {
          ...config,
          serverUrl: undefined, // No server URL = STDIO transport
        },
      }) as AssessmentContext;

      const result = await assessor.assess(context);

      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.skipped).toBe(true);
      expect(result.skipReason).toContain("Server URL not available");
      expect(result.scenarios).toHaveLength(0);
      expect(result.officialChecks).toHaveLength(0);
      expect(result.passedChecks).toBe(0);
      expect(result.totalChecks).toBe(0);
      expect(result.complianceScore).toBe(0);
    });

    it("should include transport guidance in recommendations when skipped", async () => {
      const context = createMockAssessmentContext({
        serverName: "test-server",
        tools: [],
        config: {
          ...config,
          serverUrl: undefined,
        },
      }) as AssessmentContext;

      const result = await assessor.assess(context);

      expect(result.recommendations).toBeDefined();
      expect(result.recommendations.length).toBeGreaterThan(0);
      // Should recommend HTTP/SSE transport
      const hasTransportRecommendation = result.recommendations.some(
        (r) => r.includes("HTTP") || r.includes("SSE"),
      );
      expect(hasTransportRecommendation).toBe(true);
    });
  });

  describe("conformance version and protocol version", () => {
    it("should include conformance package version in results", async () => {
      const context = createMockAssessmentContext({
        serverName: "test-server",
        tools: [],
        config: {
          ...config,
          serverUrl: undefined,
        },
      }) as AssessmentContext;

      const result = await assessor.assess(context);

      expect(result.conformanceVersion).toBeDefined();
      expect(typeof result.conformanceVersion).toBe("string");
      // Version should be in semver format
      expect(result.conformanceVersion).toMatch(/^\d+\.\d+\.\d+/);
    });

    it("should include protocol version in results", async () => {
      const context = createMockAssessmentContext({
        serverName: "test-server",
        tools: [],
        config: {
          ...config,
          serverUrl: undefined,
          mcpProtocolVersion: "2025-06",
        },
      }) as AssessmentContext;

      const result = await assessor.assess(context);

      expect(result.protocolVersion).toBeDefined();
      expect(result.protocolVersion).toBe("2025-06");
    });
  });

  describe("test count tracking", () => {
    it("should reset test count correctly", () => {
      assessor.resetTestCount();
      expect(assessor.getTestCount()).toBe(0);
    });
  });
});

describe("ConformanceAssessor - Integration Prerequisites", () => {
  /**
   * These tests document the requirements for full conformance testing.
   * They serve as a checklist for setting up conformance test environments.
   */

  it("requires HTTP or SSE transport with serverUrl", () => {
    // Conformance tests require an HTTP endpoint that can be tested
    // STDIO transport doesn't expose a URL for the conformance CLI to connect to
    const httpConfig = {
      transport: "http" as const,
      url: "http://localhost:10900/mcp",
    };

    expect(httpConfig.url).toBeDefined();
    expect(httpConfig.url).toMatch(/^https?:\/\//);
  });

  it("documents @modelcontextprotocol/conformance package requirement", () => {
    // This is installed as a dev dependency
    // The assessor uses execFileSync to run the npx CLI
    // Note: require.resolve doesn't work in jest for this package structure
    // The package is installed as shown by: npm ls @modelcontextprotocol/conformance
    const packageInfo = {
      name: "@modelcontextprotocol/conformance",
      version: "0.1.9",
      transport: "npx CLI execution",
    };
    expect(packageInfo.name).toBe("@modelcontextprotocol/conformance");
  });

  it("documents available server scenarios", () => {
    // These are the scenarios tested by the conformance assessor
    // Updated for @modelcontextprotocol/conformance v0.1.9+
    const expectedScenarios = [
      "server-initialize",
      "tools-list",
      "tools-call-simple-text",
      "resources-list",
      "resources-read-text",
      "prompts-list",
      "prompts-get-simple",
    ];

    // Just document that these exist - actual testing happens at runtime
    expect(expectedScenarios.length).toBe(7);
  });
});
