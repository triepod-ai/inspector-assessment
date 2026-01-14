/**
 * TemporalAssessor - External API Tool Handling Tests (Issue #166)
 *
 * Tests for detecting and handling external API tools where content variation
 * is expected because data is fetched from live external services.
 *
 * Key scenarios:
 * - isExternalAPITool() detection via name patterns and description
 * - isError variance handling (error vs success responses)
 * - External API false positive prevention
 *
 * @group unit
 * @group temporal
 */

import { VarianceClassifier } from "../modules/temporal/VarianceClassifier";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("TemporalAssessor - External API Tool Handling (Issue #166)", () => {
  let varianceClassifier: VarianceClassifier;

  beforeEach(() => {
    varianceClassifier = new VarianceClassifier();
  });

  /**
   * Helper to create a mock tool
   */
  function createTool(name: string, description?: string): Tool {
    return {
      name,
      description: description || `Tool for ${name.replace(/_/g, " ")}`,
      inputSchema: { type: "object", properties: {} },
    };
  }

  describe("isExternalAPITool - name pattern detection", () => {
    it.each([
      // API prefixes
      ["api_fetch_data", true],
      ["external_service", true],
      ["remote_query", true],
      ["live_feed", true],
      // Data type patterns
      ["get_weather", true],
      ["fetch_stock_price", true],
      ["market_data", true],
      ["currency_exchange", true],
      ["exchange_rate", true],
      ["forex_rates", true],
      // Service-specific
      ["wb_get_indicators", true],
      ["wb_search_documents", true],
      ["worldbank_data", true],
      // Action patterns
      ["poll_status", true],
      ["realtime_updates", true],
      ["current_price", true],
    ])("%s should return %s (external API pattern)", (toolName, expected) => {
      const tool = createTool(toolName);
      expect(varianceClassifier.isExternalAPITool(tool)).toBe(expected);
    });

    it.each([
      // NOT external API
      ["calculate_sum", false],
      ["store_memory", false],
      ["delete_item", false],
      ["search_docs", false],
      ["add_record", false],
      ["validate_input", false],
    ])("%s should return %s (not external API)", (toolName, expected) => {
      const tool = createTool(toolName);
      expect(varianceClassifier.isExternalAPITool(tool)).toBe(expected);
    });
  });

  describe("isExternalAPITool - description detection", () => {
    it("detects external API from description mentioning 'external api'", () => {
      const tool = createTool(
        "get_data",
        "Fetches data from the World Bank external API",
      );
      expect(varianceClassifier.isExternalAPITool(tool)).toBe(true);
    });

    it("detects external API from description mentioning 'fetches from'", () => {
      const tool = createTool(
        "get_info",
        "This tool fetches from the company database and external services",
      );
      expect(varianceClassifier.isExternalAPITool(tool)).toBe(true);
    });

    it("detects external API from description mentioning 'real-time'", () => {
      const tool = createTool(
        "price_check",
        "Returns real-time pricing information",
      );
      expect(varianceClassifier.isExternalAPITool(tool)).toBe(true);
    });

    it("detects external API from description mentioning 'third-party'", () => {
      const tool = createTool(
        "verify_email",
        "Uses third-party API service to verify email addresses",
      );
      expect(varianceClassifier.isExternalAPITool(tool)).toBe(true);
    });

    it("does NOT detect external API from unrelated description", () => {
      const tool = createTool(
        "calculate_total",
        "Calculates the total of all items in the cart",
      );
      expect(varianceClassifier.isExternalAPITool(tool)).toBe(false);
    });
  });

  describe("classifyVariance - isError variance handling", () => {
    it("returns LEGITIMATE for error vs success variance on external API tool", () => {
      const baseline = { isError: true, content: "Error: API 500" };
      const current = {
        isError: false,
        content: "Search Results: 586,112 documents",
      };
      const tool = createTool("wb_search_documents");

      const result = varianceClassifier.classifyVariance(
        baseline,
        current,
        tool,
      );

      expect(result.type).toBe("LEGITIMATE");
      expect(result.confidence).toBe("medium");
      expect(result.reasons).toContain(
        "API error vs success variance (expected for external API/stateful tools)",
      );
    });

    it("returns LEGITIMATE for error vs success variance on stateful tool", () => {
      const baseline = { isError: true, content: "Connection timeout" };
      const current = { isError: false, content: "Found 10 results" };
      const tool = createTool("search_database"); // Stateful pattern "search"

      const result = varianceClassifier.classifyVariance(
        baseline,
        current,
        tool,
      );

      expect(result.type).toBe("LEGITIMATE");
      expect(result.reasons[0]).toContain("API error vs success variance");
    });

    it("does NOT return LEGITIMATE for error variance on non-stateful/non-external tool", () => {
      const baseline = { isError: true, content: "Error" };
      const current = { isError: false, content: "OK" };
      const tool = createTool("validate_input"); // Neither stateful nor external API

      const result = varianceClassifier.classifyVariance(
        baseline,
        current,
        tool,
      );

      // Should go through normal schema comparison and fail
      expect(result.type).not.toBe("LEGITIMATE");
    });

    it("still detects BEHAVIORAL changes even with external API tool", () => {
      // Both responses have isError=false, same structure, but promotional content added
      const baseline = { isError: false, data: "Normal data" };
      const current = { isError: false, data: "Upgrade to premium for $99!" };
      const tool = createTool("get_weather");

      const result = varianceClassifier.classifyVariance(
        baseline,
        current,
        tool,
      );

      // Behavioral content detection should still flag promotional keywords
      expect(result.type).toBe("BEHAVIORAL");
    });
  });

  describe("edge cases", () => {
    it("handles undefined tool gracefully", () => {
      const baseline = { isError: true, content: "Error" };
      const current = { isError: false, content: "OK" };

      // No tool passed - should not crash and should use default behavior
      const result = varianceClassifier.classifyVariance(baseline, current);

      // Without tool, can't check isStateful/isExternalAPI, so won't get LEGITIMATE
      expect(result).toBeDefined();
      expect(["SUSPICIOUS", "BEHAVIORAL", "LEGITIMATE"]).toContain(result.type);
    });

    it("handles both responses being errors", () => {
      const baseline = { isError: true, content: "Error 500" };
      const current = { isError: true, content: "Error 503" };
      const tool = createTool("wb_get_data");

      // Both are errors (isError same), so won't trigger isError variance logic
      const result = varianceClassifier.classifyVariance(
        baseline,
        current,
        tool,
      );

      // Should go through normal schema comparison - schemas match
      expect(result).toBeDefined();
    });

    it("handles tool with name AND description indicating external API", () => {
      const tool = createTool(
        "get_weather",
        "Fetches real-time weather data from external weather API",
      );

      expect(varianceClassifier.isExternalAPITool(tool)).toBe(true);
    });
  });
});
