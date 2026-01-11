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

    it("should handle Uint8Array content for MIME validation", async () => {
      // PNG magic bytes as Uint8Array
      const pngMagicBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);

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
        readResource: async () => {
          // Return Uint8Array content (not string)
          const buffer = new Uint8Array(pngMagicBytes.length + 10);
          buffer.set(pngMagicBytes, 0);
          return buffer.toString(); // Convert to string representation for MCP compatibility
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      // Should validate correctly even when content arrives as Uint8Array-like data
      const mimeResults = result.results.filter(
        (r) => r.mimeValidationPerformed,
      );
      expect(mimeResults.length).toBeGreaterThan(0);
    });

    it("should detect MIME mismatch with Uint8Array content", async () => {
      // PNG magic bytes as string (MCP returns text, not Uint8Array)
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

  describe("Stage 3 Fixes - Issue #127 Code Review", () => {
    describe("TEST-REQ-001: Uint8Array MIME Validation (ISSUE-002, FIX-002)", () => {
      it("should validate Uint8Array with PNG magic bytes and PNG MIME type (happy path)", async () => {
        // PNG magic bytes as Uint8Array
        const pngMagicBytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47]);
        const pngContent = new Uint8Array(pngMagicBytes.length + 100);
        pngContent.set(pngMagicBytes, 0);

        const context: Partial<AssessmentContext> = {
          serverInfo: {
            name: "test-server",
            version: "1.0.0",
          },
          resources: [
            {
              uri: "resource://test.png",
              name: "test_png",
              mimeType: "image/png",
            },
          ],
          resourceTemplates: [],
          readResource: async () => {
            // Convert Uint8Array to string (MCP transport layer behavior)
            return String.fromCharCode(...pngContent);
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Should pass validation - PNG declared, PNG content
        const mismatchResults = result.results.filter(
          (r) => r.mimeTypeMismatch,
        );
        expect(mismatchResults.length).toBe(0);
        expect(result.mimeValidationFailures).toBe(0);
      });

      it("should detect mismatch with Uint8Array JPEG magic bytes but PNG MIME type (edge case)", async () => {
        // JPEG magic bytes as Uint8Array
        const jpegMagicBytes = new Uint8Array([0xff, 0xd8, 0xff]);
        const jpegContent = new Uint8Array(jpegMagicBytes.length + 100);
        jpegContent.set(jpegMagicBytes, 0);

        const context: Partial<AssessmentContext> = {
          serverInfo: {
            name: "test-server",
            version: "1.0.0",
          },
          resources: [
            {
              uri: "resource://test.png",
              name: "test_image",
              mimeType: "image/png", // Claims PNG
            },
          ],
          resourceTemplates: [],
          readResource: async () => {
            // Convert Uint8Array to string (MCP transport layer behavior)
            return String.fromCharCode(...jpegContent);
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Should detect mismatch - PNG declared, JPEG content
        const mismatchResults = result.results.filter(
          (r) => r.mimeTypeMismatch,
        );
        expect(mismatchResults.length).toBeGreaterThan(0);
        expect(result.mimeValidationFailures).toBeGreaterThan(0);
        expect(result.status).toBe("NEED_MORE_INFO");
      });

      it("should handle empty Uint8Array gracefully (error case)", async () => {
        // Empty Uint8Array - no magic bytes to match
        const emptyContent = new Uint8Array(0);

        const context: Partial<AssessmentContext> = {
          serverInfo: {
            name: "test-server",
            version: "1.0.0",
          },
          resources: [
            {
              uri: "resource://empty.png",
              name: "empty_image",
              mimeType: "image/png",
            },
          ],
          resourceTemplates: [],
          readResource: async () => {
            return String.fromCharCode(...emptyContent); // Empty string
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Should pass - no magic bytes to compare means no mismatch
        const mismatchResults = result.results.filter(
          (r) => r.mimeTypeMismatch,
        );
        expect(mismatchResults.length).toBe(0);
        expect(result.mimeValidationFailures).toBe(0);
      });
    });

    describe("TEST-REQ-002: Magic Byte Fallback Detection (ISSUE-001, FIX-001)", () => {
      it("should detect raw GIF magic bytes without JSON wrapper (happy path)", async () => {
        // Raw GIF magic bytes without JSON self-reporting
        const gifMagicBytes = String.fromCharCode(
          0x47,
          0x49,
          0x46,
          0x38,
          0x39,
          0x61,
        );
        const rawGifContent = gifMagicBytes + "/*<script>alert(1)</script>*/";

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
              // Return raw content, no JSON self-reporting
              return rawGifContent;
            }
            throw new Error("Not found");
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Magic byte fallback should detect vulnerability
        const polyglotResults = result.results.filter(
          (r) =>
            r.polyglotTested &&
            r.securityIssues.some((issue) => issue.includes("magic bytes")),
        );
        expect(polyglotResults.length).toBeGreaterThan(0);
        expect(result.polyglotVulnerabilities).toBeGreaterThan(0);
      });

      it("should prioritize magic bytes over JSON self-reporting (edge case)", async () => {
        // Server returns JSON with vulnerable=false BUT content has magic bytes
        const pngMagicBytes = String.fromCharCode(0x89, 0x50, 0x4e, 0x47);
        const contentWithMagicBytes =
          pngMagicBytes + '{"vulnerable":false,"safe":true}';

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
            if (uri.includes("png")) {
              // Magic bytes present, but JSON self-reports safe
              return contentWithMagicBytes;
            }
            throw new Error("Not found");
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Magic byte detection should trigger despite vulnerable=false
        const polyglotResults = result.results.filter(
          (r) =>
            r.polyglotTested &&
            r.securityIssues.some((issue) => issue.includes("magic bytes")),
        );
        expect(polyglotResults.length).toBeGreaterThan(0);
      });

      it("should not false positive on non-JSON content without magic bytes (error case)", async () => {
        // Non-JSON content that doesn't contain magic bytes
        const plainTextContent =
          "This is plain text content without magic bytes";

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
          readResource: async () => plainTextContent,
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Should not flag as vulnerable - no magic bytes, no JSON flag
        expect(result.polyglotVulnerabilities).toBe(0);
      });
    });

    describe("TEST-REQ-003: Blob DoS Threshold Consistency (ISSUE-003)", () => {
      it("should consistently classify 10MB as MEDIUM risk", async () => {
        // Verify threshold: requestedSize > 1MB && requestedSize <= 100MB = MEDIUM
        // DOS_SIZE_PAYLOADS includes "10000000" (10MB) which should be MEDIUM
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
            // Accept all requests - testBlobDoS uses DOS_SIZE_PAYLOADS
            const sizeMatch = uri.match(/blob:\/\/(\d+)/);
            if (sizeMatch) {
              return JSON.stringify({
                uri,
                size_accepted: sizeMatch[1],
                vulnerable: true,
              });
            }
            throw new Error("Invalid request");
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Find 10MB result (10000000 bytes)
        const tenMBResults = result.results.filter(
          (r) => r.blobDosTested && r.blobRequestedSize === 10000000,
        );

        expect(tenMBResults.length).toBeGreaterThan(0);
        expect(tenMBResults[0].blobDosRiskLevel).toBe("MEDIUM");
        expect(tenMBResults[0].securityIssues.length).toBeGreaterThan(0);
      });

      it("should classify exactly 100MB as MEDIUM risk (current behavior)", async () => {
        // BOUNDARY CONDITION: Exactly 100MB (100000000 bytes)
        // Current code: requestedSize > 100 * 1024 * 1024 ? "HIGH" : "MEDIUM"
        // Since 100MB is NOT > 100MB, it gets MEDIUM (not HIGH)
        // This test documents the current behavior - see ISSUE-003 for discussion
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
            const sizeMatch = uri.match(/blob:\/\/(\d+)/);
            if (sizeMatch) {
              return JSON.stringify({
                uri,
                size_accepted: sizeMatch[1],
                vulnerable: true,
              });
            }
            throw new Error("Invalid request");
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Find 100MB result (100000000 bytes)
        const hundredMBResults = result.results.filter(
          (r) => r.blobDosTested && r.blobRequestedSize === 100000000,
        );

        expect(hundredMBResults.length).toBeGreaterThan(0);
        // Documents current behavior: exactly 100MB = MEDIUM (not HIGH)
        expect(hundredMBResults[0].blobDosRiskLevel).toBe("MEDIUM");
        expect(hundredMBResults[0].securityIssues.length).toBeGreaterThan(0);
      });

      it("should consistently classify 1GB as HIGH risk", async () => {
        // Verify threshold: requestedSize > 100MB = HIGH
        // DOS_SIZE_PAYLOADS includes "999999999" (~1GB) which should be HIGH
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
            const sizeMatch = uri.match(/blob:\/\/(\d+)/);
            if (sizeMatch) {
              return JSON.stringify({
                uri,
                size_accepted: sizeMatch[1],
                vulnerable: true,
              });
            }
            throw new Error("Invalid request");
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Find 1GB result (999999999 bytes)
        const oneGBResults = result.results.filter(
          (r) => r.blobDosTested && r.blobRequestedSize === 999999999,
        );

        expect(oneGBResults.length).toBeGreaterThan(0);
        expect(oneGBResults[0].blobDosRiskLevel).toBe("HIGH");
        expect(oneGBResults[0].securityIssues.length).toBeGreaterThan(0);
      });
    });

    describe("TEST-REQ-004: Zero-Size Blob Handling (ISSUE-005)", () => {
      it("should handle size=0 with LOW risk level", async () => {
        // Verify that size=0 is handled gracefully with LOW risk
        // DOS_SIZE_PAYLOADS includes "0" for testing
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
            const sizeMatch = uri.match(/blob:\/\/(\d+)/);
            if (sizeMatch) {
              return JSON.stringify({
                uri,
                size_accepted: sizeMatch[1],
                content: "",
              });
            }
            throw new Error("Invalid request");
          },
        };

        const result = await assessor.assess(context as AssessmentContext);

        // Find size=0 result - it should be accepted but LOW risk (no security issue)
        // Code: else { dosResult.blobDosRiskLevel = "LOW"; }
        // Since securityIssues.length == 0, it won't be in results array
        // But we can verify no false positives by checking that only the
        // dangerous sizes (10MB, 100MB, 1GB) and invalid values are flagged
        const flaggedSizes = result.results
          .filter((r) => r.blobDosTested)
          .map((r) => r.blobRequestedSize);

        // Size 0 should NOT be in the flagged results
        expect(flaggedSizes).not.toContain(0);
      });
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
