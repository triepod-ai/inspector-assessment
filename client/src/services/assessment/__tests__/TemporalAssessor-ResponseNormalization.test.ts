/**
 * TemporalAssessor - Response Normalization Tests
 *
 * Tests for the response normalization algorithm that eliminates naturally-varying data
 * before comparison (timestamps, UUIDs, IDs, counters).
 */

import { TemporalAssessor } from "../modules/TemporalAssessor";
import {
  getPrivateMethod,
  createTemporalTestConfig,
} from "@/test/utils/testUtils";

// Convenience alias for cleaner test code
const createConfig = createTemporalTestConfig;

describe("TemporalAssessor - Response Normalization", () => {
  let assessor: TemporalAssessor;
  let normalizeResponse: (response: unknown) => string;

  beforeEach(() => {
    assessor = new TemporalAssessor(createConfig());
    normalizeResponse = getPrivateMethod(assessor, "normalizeResponse");
  });

  describe("Timestamp Normalization", () => {
    it("normalizes ISO timestamps", () => {
      const input = { timestamp: "2025-12-27T10:30:00.123Z" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<TIMESTAMP>"');
      expect(result).not.toContain("2025-12-27");
    });

    it("normalizes ISO timestamps without Z suffix", () => {
      const input = { time: "2025-01-15T08:45:30.999" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<TIMESTAMP>"');
      expect(result).not.toContain("2025-01-15");
    });

    it("normalizes unix timestamps (13-digit)", () => {
      const input = { ts: "1735294200000" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<TIMESTAMP>"');
      expect(result).not.toContain("1735294200000");
    });
  });

  describe("UUID Normalization", () => {
    it("normalizes UUIDs (lowercase)", () => {
      // Use a field name other than 'id' to avoid string ID normalization
      const input = { uuid: "550e8400-e29b-41d4-a716-446655440000" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<UUID>"');
      expect(result).not.toContain("550e8400");
    });

    it("normalizes UUIDs (uppercase)", () => {
      const input = { uuid: "550E8400-E29B-41D4-A716-446655440000" };
      const result = normalizeResponse(input);
      expect(result).toContain('"<UUID>"');
      expect(result).not.toContain("550E8400");
    });
  });

  describe("Numeric ID Fields", () => {
    it("normalizes numeric id fields", () => {
      const input = { id: 12345 };
      const result = normalizeResponse(input);
      expect(result).toContain('"id": <NUMBER>');
      expect(result).not.toContain("12345");
    });

    it("normalizes Id fields (capitalized)", () => {
      const input = { userId: 99, Id: 42 };
      const result = normalizeResponse(input);
      expect(result).toContain('"Id": <NUMBER>');
    });

    it("normalizes nested JSON with escaped quotes", () => {
      // Simulates MCP response with JSON in content[].text
      const input = {
        content: [{ text: '{"id": 42, "count": 10}' }],
      };
      const result = normalizeResponse(input);
      // The escaped JSON should have normalized numbers
      expect(result).toContain('\\"id\\": <NUMBER>');
      expect(result).toContain('\\"count\\": <NUMBER>');
    });
  });

  describe("Counter Fields", () => {
    it("normalizes counter fields (total_items)", () => {
      const input = { total_items: 100 };
      const result = normalizeResponse(input);
      expect(result).toContain('"total_items": <NUMBER>');
      expect(result).not.toContain("100");
    });

    it("normalizes counter fields (count)", () => {
      const input = { count: 5 };
      const result = normalizeResponse(input);
      expect(result).toContain('"count": <NUMBER>');
    });

    it("normalizes counter fields (invocation_count)", () => {
      const input = { invocation_count: 25 };
      const result = normalizeResponse(input);
      expect(result).toContain('"invocation_count": <NUMBER>');
    });

    it("normalizes counter fields (sequence)", () => {
      const input = { sequence: 3 };
      const result = normalizeResponse(input);
      expect(result).toContain('"sequence": <NUMBER>');
    });

    it("normalizes counter fields (index)", () => {
      const input = { index: 0 };
      const result = normalizeResponse(input);
      expect(result).toContain('"index": <NUMBER>');
    });

    // Issue: Accumulation-related counter patterns should be normalized
    it("normalizes accumulation counter fields (total_observations)", () => {
      const input = { total_observations: 42 };
      const result = normalizeResponse(input);
      expect(result).toContain('"total_observations": <NUMBER>');
      expect(result).not.toContain("42");
    });

    it("normalizes accumulation counter fields (size, length, total)", () => {
      const input = { size: 100, length: 50, total: 25 };
      const result = normalizeResponse(input);
      expect(result).toContain('"size": <NUMBER>');
      expect(result).toContain('"length": <NUMBER>');
      expect(result).toContain('"total": <NUMBER>');
      expect(result).not.toContain("100");
      expect(result).not.toContain("50");
      expect(result).not.toContain("25");
    });

    it("normalizes nested JSON accumulation counters", () => {
      // Simulates MCP response with JSON in content[].text
      const input = {
        content: [{ text: '{"total_observations": 10, "size": 5}' }],
      };
      const result = normalizeResponse(input);
      expect(result).toContain('\\"total_observations\\": <NUMBER>');
      expect(result).toContain('\\"size\\": <NUMBER>');
    });
  });

  describe("String ID Fields", () => {
    it("normalizes request_id fields", () => {
      const input = { request_id: "req-abc123-xyz" };
      const result = normalizeResponse(input);
      expect(result).toContain('"request_id": "<ID>"');
      expect(result).not.toContain("abc123");
    });

    it("normalizes requestId fields (camelCase)", () => {
      const input = { requestId: "REQ-12345" };
      const result = normalizeResponse(input);
      expect(result).toContain('"requestId": "<ID>"');
    });

    it("normalizes trace_id fields", () => {
      const input = { trace_id: "trace-xyz-789" };
      const result = normalizeResponse(input);
      expect(result).toContain('"trace_id": "<ID>"');
    });

    it("normalizes string id fields", () => {
      const input = { id: "user_abc123" };
      const result = normalizeResponse(input);
      expect(result).toContain('"id": "<ID>"');
    });
  });

  describe("Preservation Tests", () => {
    it("preserves non-varying data", () => {
      const input = { status: "success", message: "Operation completed" };
      const result = normalizeResponse(input);
      expect(result).toContain('"status":"success"');
      expect(result).toContain('"message":"Operation completed"');
    });
  });

  describe("Edge Cases", () => {
    it("handles null", () => {
      // null serializes to "null" string
      expect(() => normalizeResponse(null)).not.toThrow();
      expect(normalizeResponse(null)).toBe("null");
    });

    it("handles empty objects and arrays", () => {
      expect(normalizeResponse({})).toBe("{}");
      expect(normalizeResponse([])).toBe("[]");
    });
  });
});
