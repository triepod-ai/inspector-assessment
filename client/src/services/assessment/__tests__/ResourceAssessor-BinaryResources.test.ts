/**
 * Issue #127, Challenge #24: Binary Resource Vulnerability Detection Tests
 *
 * Tests for:
 * - Blob DoS detection (CWE-400, CWE-409)
 * - Polyglot file detection (CWE-434, CWE-436)
 * - MIME type validation (CWE-436)
 */

import { ResourceAssessor } from "../modules/ResourceAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";

// Default test configuration
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  testTimeout: 5000,
  skipBrokenTools: false,
  delayBetweenTests: 0,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
  },
  ...overrides,
});

describe("ResourceAssessor - Binary Resource Vulnerabilities (Issue #127)", () => {
  let assessor: ResourceAssessor;

  beforeEach(() => {
    assessor = new ResourceAssessor(createConfig());
  });

  describe("Blob DoS Detection (CWE-400, CWE-409)", () => {
    it("should detect HIGH risk for 1GB blob size acceptance", async () => {
      // Use shared assessor from beforeEach
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "blob://{size}/{mime_base}/{mime_subtype}",
            name: "blob_generator",
          },
        ],
        readResource: async (uri: string) => {
          // Simulate vulnerable server accepting any size
          return JSON.stringify({
            uri,
            size_requested: uri.match(/blob:\/\/(\d+)/)?.[1],
            vulnerable: true,
          });
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.blobDosVulnerabilities).toBeGreaterThan(0);
      expect(result.status).toBe("FAIL");
      expect(result.explanation).toContain("blob DoS vulnerability");
    });

    it("should detect MEDIUM risk for invalid size values (-1, NaN)", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "blob://{size}/{mime_base}/{mime_subtype}",
            name: "blob_generator",
          },
        ],
        readResource: async (uri: string) => {
          // Simulate vulnerable server accepting invalid sizes
          const sizeParam = uri.split("/")[2];
          if (sizeParam === "-1" || sizeParam === "NaN") {
            return JSON.stringify({ uri, invalid_size_accepted: true });
          }
          throw new Error("Size rejected");
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      const invalidSizeResults = result.results.filter(
        (r) =>
          r.blobDosTested &&
          r.blobDosRiskLevel === "MEDIUM" &&
          r.securityIssues.some((i) => i.includes("validation bypass")),
      );
      expect(invalidSizeResults.length).toBeGreaterThan(0);
    });

    it("should not flag blob templates when sizes are properly rejected", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "blob://{size}/{mime_base}/{mime_subtype}",
            name: "blob_generator",
          },
        ],
        readResource: async () => {
          // Server rejects all large/invalid sizes
          throw new Error("Size validation failed");
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.blobDosVulnerabilities).toBe(0);
    });

    it("should skip non-blob templates", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "file://{path}",
            name: "file_reader",
          },
        ],
        readResource: async () => "some content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      const blobResults = result.results.filter((r) => r.blobDosTested);
      expect(blobResults.length).toBe(0);
    });
  });

  describe("Polyglot File Detection (CWE-434, CWE-436)", () => {
    it("should detect polyglot vulnerability when server returns vulnerable flag", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "polyglot://{base_type}/{hidden_type}",
            name: "polyglot_generator",
          },
        ],
        readResource: async (uri: string) => {
          return JSON.stringify({
            uri,
            vulnerable: true,
            polyglot_known: true,
          });
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.polyglotVulnerabilities).toBeGreaterThan(0);
      expect(result.status).toBe("FAIL");
      expect(result.explanation).toContain("polyglot file vulnerability");
    });

    it("should detect polyglot via magic bytes in content", async () => {
      // GIF89a magic bytes as string (simulating raw binary response)
      const gifMagicBytes = String.fromCharCode(
        0x47,
        0x49,
        0x46,
        0x38,
        0x39,
        0x61,
      );

      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "polyglot://{base_type}/{hidden_type}",
            name: "polyglot_generator",
          },
        ],
        readResource: async (uri: string) => {
          if (uri.includes("gif")) {
            // Return content with GIF magic bytes
            return gifMagicBytes + "/*<script>alert(1)</script>*/";
          }
          throw new Error("Not found");
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      const polyglotResults = result.results.filter(
        (r) => r.polyglotTested && r.securityIssues.length > 0,
      );
      expect(polyglotResults.length).toBeGreaterThan(0);
    });

    it("should not flag polyglot when server rejects requests", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "polyglot://{base_type}/{hidden_type}",
            name: "polyglot_generator",
          },
        ],
        readResource: async () => {
          throw new Error("Polyglot generation not allowed");
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.polyglotVulnerabilities).toBe(0);
    });

    it("should skip non-polyglot templates", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "file://{path}",
            name: "file_reader",
          },
        ],
        readResource: async () => "some content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      const polyglotResults = result.results.filter((r) => r.polyglotTested);
      expect(polyglotResults.length).toBe(0);
    });
  });

  describe("MIME Type Validation (CWE-436)", () => {
    it("should detect MIME type mismatch", async () => {
      // PNG magic bytes as string
      const pngMagicBytes = String.fromCharCode(0x89, 0x50, 0x4e, 0x47);

      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [
          {
            uri: "resource://image.jpg",
            name: "test_image",
            mimeType: "image/jpeg", // Claims JPEG
          },
        ],
        resourceTemplates: [],
        readResource: async () => {
          // Return PNG content (not JPEG)
          return pngMagicBytes + "rest of file content";
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      const mismatchResults = result.results.filter((r) => r.mimeTypeMismatch);
      expect(mismatchResults.length).toBeGreaterThan(0);
      expect(result.mimeValidationFailures).toBeGreaterThan(0);
      expect(result.status).toBe("NEED_MORE_INFO");
    });

    it("should pass when MIME type matches content", async () => {
      // PNG magic bytes as string
      const pngMagicBytes = String.fromCharCode(0x89, 0x50, 0x4e, 0x47);

      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [
          {
            uri: "resource://image.png",
            name: "test_image",
            mimeType: "image/png", // Correctly claims PNG
          },
        ],
        resourceTemplates: [],
        readResource: async () => {
          return pngMagicBytes + "rest of file content";
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      const mismatchResults = result.results.filter((r) => r.mimeTypeMismatch);
      expect(mismatchResults.length).toBe(0);
      expect(result.mimeValidationFailures).toBe(0);
    });

    it("should not flag when no MIME type is declared", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [
          {
            uri: "resource://data.bin",
            name: "binary_data",
            // No mimeType declared
          },
        ],
        resourceTemplates: [],
        readResource: async () => "binary content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.mimeValidationFailures).toBe(0);
    });
  });

  describe("Recommendations", () => {
    it("should include blob DoS recommendation when vulnerability detected", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "blob://{size}/{mime_base}/{mime_subtype}",
            name: "blob_generator",
          },
        ],
        readResource: async () =>
          JSON.stringify({ vulnerable: true, size_accepted: 1000000000 }),
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(
        result.recommendations.some((r) => r.includes("blob size limits")),
      ).toBe(true);
      expect(result.recommendations.some((r) => r.includes("CWE-400"))).toBe(
        true,
      );
    });

    it("should include polyglot recommendation when vulnerability detected", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "polyglot://{base_type}/{hidden_type}",
            name: "polyglot_generator",
          },
        ],
        readResource: async () => JSON.stringify({ vulnerable: true }),
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(
        result.recommendations.some((r) =>
          r.toLowerCase().includes("polyglot"),
        ),
      ).toBe(true);
      expect(result.recommendations.some((r) => r.includes("CWE-434"))).toBe(
        true,
      );
    });

    it("should include MIME validation recommendation when mismatch detected", async () => {
      const pngMagicBytes = String.fromCharCode(0x89, 0x50, 0x4e, 0x47);

      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [
          {
            uri: "resource://image.jpg",
            name: "test_image",
            mimeType: "image/jpeg",
          },
        ],
        resourceTemplates: [],
        readResource: async () => pngMagicBytes + "content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.recommendations.some((r) => r.includes("magic byte"))).toBe(
        true,
      );
      expect(result.recommendations.some((r) => r.includes("CWE-436"))).toBe(
        true,
      );
    });
  });

  describe("New Result Fields", () => {
    it("should include binary resource fields in ResourceAssessment", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [],
        readResource: async () => "content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      // Verify new fields exist in the result
      expect(result).toHaveProperty("blobDosVulnerabilities");
      expect(result).toHaveProperty("polyglotVulnerabilities");
      expect(result).toHaveProperty("mimeValidationFailures");
      expect(typeof result.blobDosVulnerabilities).toBe("number");
      expect(typeof result.polyglotVulnerabilities).toBe("number");
      expect(typeof result.mimeValidationFailures).toBe("number");
    });

    it("should include blob DoS fields in ResourceTestResult", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "blob://{size}/{mime_base}/{mime_subtype}",
            name: "blob_generator",
          },
        ],
        readResource: async () => JSON.stringify({ vulnerable: true }),
      };

      const result = await assessor.assess(context as AssessmentContext);

      const blobResults = result.results.filter((r) => r.blobDosTested);
      expect(blobResults.length).toBeGreaterThan(0);

      const blobResult = blobResults[0];
      expect(blobResult).toHaveProperty("blobDosTested", true);
      expect(blobResult).toHaveProperty("blobDosRiskLevel");
      expect(blobResult).toHaveProperty("blobRequestedSize");
    });

    it("should include polyglot fields in ResourceTestResult", async () => {
      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [],
        resourceTemplates: [
          {
            uriTemplate: "polyglot://{base_type}/{hidden_type}",
            name: "polyglot_generator",
          },
        ],
        readResource: async () => JSON.stringify({ vulnerable: true }),
      };

      const result = await assessor.assess(context as AssessmentContext);

      const polyglotResults = result.results.filter((r) => r.polyglotTested);
      expect(polyglotResults.length).toBeGreaterThan(0);

      const polyglotResult = polyglotResults[0];
      expect(polyglotResult).toHaveProperty("polyglotTested", true);
      expect(polyglotResult).toHaveProperty("polyglotCombination");
    });

    it("should include MIME validation fields in ResourceTestResult", async () => {
      const pngMagicBytes = String.fromCharCode(0x89, 0x50, 0x4e, 0x47);

      const context: Partial<AssessmentContext> = {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        resources: [
          {
            uri: "resource://image.png",
            name: "test_image",
            mimeType: "image/png",
          },
        ],
        resourceTemplates: [],
        readResource: async () => pngMagicBytes + "content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      const mimeResults = result.results.filter(
        (r) => r.mimeValidationPerformed,
      );
      expect(mimeResults.length).toBeGreaterThan(0);

      const mimeResult = mimeResults[0];
      expect(mimeResult).toHaveProperty("mimeValidationPerformed", true);
      expect(mimeResult).toHaveProperty("declaredMimeType");
      expect(mimeResult).toHaveProperty("expectedMimeType");
    });
  });
});
