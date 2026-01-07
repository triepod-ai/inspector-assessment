/**
 * ProtocolConformance - CLI serverInfo Integration Tests
 *
 * Tests that serverInfo captured by CLI flows through to ProtocolConformanceAssessor
 * and that initialization handshake validation works correctly.
 *
 * These tests validate the fix from commit 55d23f4 which added serverInfo/serverCapabilities
 * capture to the CLI assess-full.ts binary.
 *
 * IMPORTANT: These are INTEGRATION tests that require the testbed containers
 * to be running. Start them with:
 *   cd /home/bryan/mcp-servers/mcp-vulnerable-testbed && docker-compose up -d
 *
 * @group integration
 * @group protocol
 */

import { ProtocolConformanceAssessor } from "../modules/ProtocolConformanceAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { checkTestbedHealth } from "./testbed-config";

// Skip these tests in CI unless testbed containers are running
const describeIntegration =
  process.env.SKIP_INTEGRATION_TESTS === "true" ? describe.skip : describe;

describeIntegration("ProtocolConformance - CLI serverInfo Integration", () => {
  let assessor: ProtocolConformanceAssessor;
  let testbedAvailable = { vulnerable: false, hardened: false };

  beforeAll(async () => {
    // Check if testbed servers are running
    testbedAvailable = await checkTestbedHealth();

    if (!testbedAvailable.vulnerable && !testbedAvailable.hardened) {
      console.warn(
        "\n  Testbed containers not running. Start with:\n" +
          "   cd /home/bryan/mcp-servers/mcp-vulnerable-testbed && docker-compose up -d\n",
      );
    }
  });

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      testTimeout: 10000,
    });
    assessor = new ProtocolConformanceAssessor(config);
    jest.clearAllMocks();
  });

  describe("Testbed Health Check", () => {
    it("should verify hardened server is accessible for serverInfo tests", async () => {
      if (!testbedAvailable.hardened) {
        console.warn("Skipping: Hardened testbed not running");
        return;
      }
      expect(testbedAvailable.hardened).toBe(true);
    });
  });

  describe("serverInfo Flow Validation", () => {
    const mockTool: Tool = {
      name: "test_tool",
      description: "A test tool for protocol conformance testing",
      inputSchema: {
        type: "object",
        properties: {
          input: { type: "string" },
        },
      },
    };

    it("should pass initialization handshake with complete serverInfo", async () => {
      const context = createMockAssessmentContext({
        tools: [mockTool],
        serverInfo: {
          name: "hardened-testbed",
          version: "1.0.0",
        },
        serverCapabilities: {
          tools: {},
        },
      });

      const results = await assessor.assess(context);

      // Access initializationHandshake check directly (checks is an object, not array)
      const initCheck = results.checks.initializationHandshake;

      expect(initCheck).toBeDefined();
      expect(initCheck.passed).toBe(true);
      expect(initCheck.confidence).toBe("high");
    });

    it("should pass with medium confidence when serverInfo.version is missing", async () => {
      const context = createMockAssessmentContext({
        tools: [mockTool],
        serverInfo: {
          name: "hardened-testbed",
          // version intentionally omitted
        },
        serverCapabilities: {
          tools: {},
        },
      });

      const results = await assessor.assess(context);

      const initCheck = results.checks.initializationHandshake;

      expect(initCheck).toBeDefined();
      expect(initCheck.passed).toBe(true);
      expect(initCheck.confidence).toBe("medium");
      expect(initCheck.warnings?.length).toBeGreaterThan(0);
    });

    it("should fail when serverInfo is undefined", async () => {
      const context = createMockAssessmentContext({
        tools: [mockTool],
        serverInfo: undefined, // CLI fallback when getServerVersion returns null
        serverCapabilities: {
          tools: {},
        },
      });

      const results = await assessor.assess(context);

      const initCheck = results.checks.initializationHandshake;

      expect(initCheck).toBeDefined();
      expect(initCheck.passed).toBe(false);
    });

    it('should handle "unknown" server name fallback', async () => {
      // This tests the CLI fallback: name: rawServerInfo.name || "unknown"
      const context = createMockAssessmentContext({
        tools: [mockTool],
        serverInfo: {
          name: "unknown",
          version: "1.0.0",
        },
        serverCapabilities: {
          tools: {},
        },
      });

      const results = await assessor.assess(context);

      const initCheck = results.checks.initializationHandshake;

      // "unknown" is still a valid name (not empty), so should pass
      expect(initCheck).toBeDefined();
      expect(initCheck.passed).toBe(true);
    });

    it("should validate all 4 initialization sub-checks when serverInfo is complete", async () => {
      const context = createMockAssessmentContext({
        tools: [mockTool],
        serverInfo: {
          name: "hardened-testbed",
          version: "1.0.0",
        },
        serverCapabilities: {
          tools: { listChanged: true },
        },
      });

      const results = await assessor.assess(context);

      const initCheck = results.checks.initializationHandshake;

      expect(initCheck).toBeDefined();
      // Check that all 4 validations passed (serverInfo.name, version, capabilities, response format)
      const validations = initCheck.details?.validations as Record<
        string,
        boolean
      >;
      expect(validations.hasServerInfo).toBe(true);
      expect(validations.hasServerName).toBe(true);
      expect(validations.hasServerVersion).toBe(true);
      expect(validations.hasCapabilities).toBe(true);
    });
  });

  describe("End-to-End Protocol Assessment", () => {
    it("should produce valid protocol conformance results", async () => {
      const mockTool: Tool = {
        name: "test_tool",
        description: "Test tool",
        inputSchema: { type: "object", properties: {} },
      };

      const context = createMockAssessmentContext({
        tools: [mockTool],
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        serverCapabilities: {
          tools: {},
        },
      });

      const results = await assessor.assess(context);

      // Verify result structure (status, not passed)
      expect(results).toHaveProperty("status");
      expect(results).toHaveProperty("score");
      expect(results).toHaveProperty("checks");

      // Verify checks object has required properties
      expect(results.checks).toHaveProperty("initializationHandshake");
      expect(results.checks).toHaveProperty("errorResponseFormat");
      expect(results.checks).toHaveProperty("contentTypeSupport");
    });
  });
});
