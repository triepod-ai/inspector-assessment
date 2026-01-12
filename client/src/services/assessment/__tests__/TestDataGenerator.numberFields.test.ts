/**
 * TestDataGenerator - Number Field Detection Tests
 *
 * Tests for intelligent number field detection based on field names.
 * Covers port, timeout, count, limit, page, offset, size, length fields.
 *
 * Related test files:
 * - TestDataGenerator.test.ts - Core functionality & configuration
 * - TestDataGenerator.stringFields.test.ts - String field detection
 * - TestDataGenerator.typeHandlers.test.ts - Boolean/Array/Object/Enum handling
 * - TestDataGenerator.scenarios.test.ts - Scenario generation
 * - TestDataGenerator.dataPool.test.ts - Data pool validation
 * - TestDataGenerator.boundary.test.ts - Boundary scenario optimization
 */

import { TestDataGenerator } from "../TestDataGenerator";

// Helper to access private static methods
const getPrivateStaticMethod = (methodName: string) => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (TestDataGenerator as any)[methodName].bind(TestDataGenerator);
};

describe("TestDataGenerator - Number Field Detection", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  const generateRealisticValue = getPrivateStaticMethod(
    "generateRealisticValue",
  );

  it("should return 8080 for port field", () => {
    const result = generateRealisticValue(
      "port",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(8080);
  });

  it("should return 5000 for timeout field", () => {
    const result = generateRealisticValue(
      "timeout",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(5000);
  });

  it("should return 5000 for delay field", () => {
    const result = generateRealisticValue(
      "delay",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(5000);
  });

  it("should return 10 for count field", () => {
    const result = generateRealisticValue(
      "count",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(10);
  });

  it("should return 10 for limit field", () => {
    const result = generateRealisticValue(
      "limit",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(10);
  });

  it("should return 0 for page field", () => {
    const result = generateRealisticValue(
      "page",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(0);
  });

  it("should return 0 for offset field", () => {
    const result = generateRealisticValue(
      "offset",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(0);
  });

  it("should return 100 for size field", () => {
    const result = generateRealisticValue(
      "size",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(100);
  });

  it("should return 100 for length field", () => {
    const result = generateRealisticValue(
      "length",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(100);
  });

  it("should return 1 for unknown number field", () => {
    const result = generateRealisticValue(
      "unknownNumber",
      { type: "number" },
      "typical",
    );
    expect(result).toBe(1);
  });

  it("should return schema.minimum for unknown number with minimum", () => {
    const result = generateRealisticValue(
      "unknownNumber",
      { type: "number", minimum: 5 },
      "typical",
    );
    expect(result).toBe(5);
  });

  it("should return 0 for empty variant with no minimum", () => {
    const result = generateRealisticValue(
      "anyNumber",
      { type: "number" },
      "empty",
    );
    expect(result).toBe(0);
  });

  it("should return schema.minimum for empty variant with minimum", () => {
    const result = generateRealisticValue(
      "anyNumber",
      { type: "number", minimum: 10 },
      "empty",
    );
    expect(result).toBe(10);
  });

  it("should return 999999 for maximum variant with no maximum", () => {
    const result = generateRealisticValue(
      "anyNumber",
      { type: "number" },
      "maximum",
    );
    expect(result).toBe(999999);
  });

  it("should return schema.maximum for maximum variant with maximum", () => {
    const result = generateRealisticValue(
      "anyNumber",
      { type: "number", maximum: 100 },
      "maximum",
    );
    expect(result).toBe(100);
  });

  it("should handle integer type same as number", () => {
    const result = generateRealisticValue(
      "port",
      { type: "integer" },
      "typical",
    );
    expect(result).toBe(8080);
  });
});
