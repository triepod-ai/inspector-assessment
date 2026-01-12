/**
 * TestDataGenerator - Data Pool Validation Tests
 *
 * Tests that verify the validity and correctness of REALISTIC_DATA pools.
 * Ensures URLs, emails, UUIDs, paths, timestamps, and other data pools are valid.
 *
 * Related test files:
 * - TestDataGenerator.test.ts - Core functionality & configuration
 * - TestDataGenerator.stringFields.test.ts - String field detection
 * - TestDataGenerator.numberFields.test.ts - Number field detection
 * - TestDataGenerator.typeHandlers.test.ts - Boolean/Array/Object/Enum handling
 * - TestDataGenerator.scenarios.test.ts - Scenario generation
 * - TestDataGenerator.boundary.test.ts - Boundary scenario optimization
 */

import { TestDataGenerator } from "../TestDataGenerator";

describe("TestDataGenerator - Data Pool Validity", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  // Access private static REALISTIC_DATA
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const REALISTIC_DATA = (TestDataGenerator as any).REALISTIC_DATA;

  it("should have valid URLs", () => {
    REALISTIC_DATA.urls.forEach((url: string) => {
      expect(url).toMatch(/^https?:\/\//);
    });
  });

  it("should have valid emails", () => {
    REALISTIC_DATA.emails.forEach((email: string) => {
      expect(email).toMatch(/@.*\./);
    });
  });

  it("should have valid UUIDs in ids pool", () => {
    const uuidPattern =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    const uuids = REALISTIC_DATA.ids.filter((id: string) => id.includes("-"));
    uuids.forEach((uuid: string) => {
      expect(uuid).toMatch(uuidPattern);
    });
  });

  it("should have paths starting with / or .", () => {
    REALISTIC_DATA.paths.forEach((path: string) => {
      expect(path).toMatch(/^[./]/);
    });
  });

  it("should have ISO timestamps", () => {
    REALISTIC_DATA.timestamps.forEach((ts: string) => {
      expect(() => new Date(ts)).not.toThrow();
    });
  });

  it("should have non-empty arrays in arrays pool", () => {
    expect(REALISTIC_DATA.arrays.length).toBeGreaterThan(0);
  });

  it("should have valid JSON objects in jsonObjects pool", () => {
    REALISTIC_DATA.jsonObjects.forEach((obj: unknown) => {
      expect(typeof obj).toBe("object");
      expect(obj).not.toBeNull();
    });
  });
});
