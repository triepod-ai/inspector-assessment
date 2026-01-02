/**
 * ResourceAssessor Tests - Issue #9 Enrichment Fields
 *
 * Comprehensive test cases for the new enrichment fields added to ResourceTestResult:
 * - sensitivePatterns: Detailed pattern detection with severity levels
 * - accessControls: Auth requirements inferred from URI
 * - dataClassification: Data sensitivity classification
 *
 * These fields support Stage B Claude analysis alignment for better security insights.
 */

import { ResourceAssessor } from "../modules/ResourceAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";

const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  testTimeout: 5000,
  skipBrokenTools: false,
  delayBetweenTests: 0,
  maxToolsToTestForErrors: -1,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
  },
  ...overrides,
});

describe("ResourceAssessor - Issue #9 Enrichment Fields", () => {
  let assessor: ResourceAssessor;

  beforeEach(() => {
    assessor = new ResourceAssessor(createConfig());
  });

  describe("sensitivePatterns Field", () => {
    const createContext = (
      resourceContent: string,
      uri = "resource://test/doc",
    ): Partial<AssessmentContext> => ({
      resources: [{ uri, name: "Test Document" }],
      readResource: async () => resourceContent,
    });

    describe("Pattern Detection - Critical Severity", () => {
      it("should detect private key pattern with critical severity", async () => {
        const content = `
          -----BEGIN RSA PRIVATE KEY-----
          MIIEpAIBAAKCAQEAr7eWuQv...
          -----END RSA PRIVATE KEY-----
        `;

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const privateKeyPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "private_key",
        );
        expect(privateKeyPattern).toBeDefined();
        expect(privateKeyPattern?.detected).toBe(true);
        expect(privateKeyPattern?.severity).toBe("critical");
      });

      it("should detect AWS access key pattern with critical severity", async () => {
        const content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const awsPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "aws_access_key",
        );
        expect(awsPattern).toBeDefined();
        expect(awsPattern?.detected).toBe(true);
        expect(awsPattern?.severity).toBe("critical");
      });

      it("should detect SSN pattern with critical severity", async () => {
        const content = "Social Security Number: 123-45-6789";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const ssnPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "ssn_pattern",
        );
        expect(ssnPattern).toBeDefined();
        expect(ssnPattern?.detected).toBe(true);
        expect(ssnPattern?.severity).toBe("critical");
      });

      it("should detect credit card pattern with critical severity", async () => {
        const content = "Card Number: 4532-1234-5678-9010";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const ccPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "credit_card",
        );
        expect(ccPattern).toBeDefined();
        expect(ccPattern?.detected).toBe(true);
        expect(ccPattern?.severity).toBe("critical");
      });
    });

    describe("Pattern Detection - High Severity", () => {
      it("should detect OpenAI API key pattern with high severity", async () => {
        const content =
          "OPENAI_API_KEY=sk-abcdef1234567890abcdef1234567890abcd";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const apiKeyPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "api_key_openai",
        );
        expect(apiKeyPattern).toBeDefined();
        expect(apiKeyPattern?.detected).toBe(true);
        expect(apiKeyPattern?.severity).toBe("high");
      });

      it("should detect GitHub token pattern with high severity", async () => {
        const content = "GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const githubPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "github_token",
        );
        expect(githubPattern).toBeDefined();
        expect(githubPattern?.detected).toBe(true);
        expect(githubPattern?.severity).toBe("high");
      });

      it("should detect GitLab token pattern with high severity", async () => {
        const content = "GITLAB_TOKEN=glpat-1234567890abcdefghij";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const gitlabPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "gitlab_token",
        );
        expect(gitlabPattern).toBeDefined();
        expect(gitlabPattern?.detected).toBe(true);
        expect(gitlabPattern?.severity).toBe("high");
      });

      it("should detect Slack token pattern with high severity", async () => {
        const content = "SLACK_TOKEN=xoxb-1234567890-abcdefghijk";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const slackPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "slack_token",
        );
        expect(slackPattern).toBeDefined();
        expect(slackPattern?.detected).toBe(true);
        expect(slackPattern?.severity).toBe("high");
      });

      it("should detect password assignment pattern with high severity", async () => {
        const content = 'password = "super_secret_123"';

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const passwordPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "password_assignment",
        );
        expect(passwordPattern).toBeDefined();
        expect(passwordPattern?.detected).toBe(true);
        expect(passwordPattern?.severity).toBe("high");
      });

      it("should detect secret assignment pattern with high severity", async () => {
        const content = 'secret: "my-secret-value-123"';

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const secretPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "secret_assignment",
        );
        expect(secretPattern).toBeDefined();
        expect(secretPattern?.detected).toBe(true);
        expect(secretPattern?.severity).toBe("high");
      });
    });

    describe("Pattern Detection - Medium Severity", () => {
      it("should detect email address pattern with medium severity", async () => {
        const content = "Contact: user@example.com for support";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const emailPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "email_address",
        );
        expect(emailPattern).toBeDefined();
        expect(emailPattern?.detected).toBe(true);
        expect(emailPattern?.severity).toBe("medium");
      });
    });

    describe("Pattern Initialization - No Detection", () => {
      it("should initialize all patterns with detected=false for clean content", async () => {
        const content = "This is a normal document with no sensitive data.";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const patterns = result.results[0].sensitivePatterns || [];
        expect(patterns.length).toBeGreaterThan(0); // Should have all pattern definitions

        // All patterns should be marked as not detected
        const detectedPatterns = patterns.filter((p) => p.detected);
        expect(detectedPatterns.length).toBe(0);

        // Verify all patterns have required fields
        patterns.forEach((p) => {
          expect(p).toHaveProperty("pattern");
          expect(p).toHaveProperty("severity");
          expect(p).toHaveProperty("detected");
          expect(["critical", "high", "medium"]).toContain(p.severity);
        });
      });

      it("should initialize sensitivePatterns array even without readResource", async () => {
        const context: Partial<AssessmentContext> = {
          resources: [{ uri: "resource://test/doc", name: "Test" }],
          // No readResource function provided
        };

        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].sensitivePatterns).toBeDefined();
        expect(Array.isArray(result.results[0].sensitivePatterns)).toBe(true);
        // Without content, all patterns should be not detected
        const detectedCount = result.results[0].sensitivePatterns?.filter(
          (p) => p.detected,
        ).length;
        expect(detectedCount).toBe(0);
      });
    });

    describe("Multiple Pattern Detection", () => {
      it("should detect multiple patterns in same content", async () => {
        const content = `
          Configuration File

          GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
          password = "super_secret"
          Contact: admin@company.com
          SSN: 123-45-6789
        `;

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const patterns = result.results[0].sensitivePatterns || [];
        const detected = patterns.filter((p) => p.detected);

        // Should detect at least 4 patterns
        expect(detected.length).toBeGreaterThanOrEqual(4);

        // Check for specific patterns
        expect(detected.some((p) => p.pattern === "github_token")).toBe(true);
        expect(detected.some((p) => p.pattern === "password_assignment")).toBe(
          true,
        );
        expect(detected.some((p) => p.pattern === "email_address")).toBe(true);
        expect(detected.some((p) => p.pattern === "ssn_pattern")).toBe(true);
      });
    });
  });

  describe("accessControls Field", () => {
    const createContext = (uri: string): Partial<AssessmentContext> => ({
      resources: [{ uri, name: "Test Resource" }],
      readResource: async () => "content",
    });

    describe("Protected Path Detection", () => {
      it("should infer auth required for /admin/ paths", async () => {
        const context = createContext("https://api.example.com/admin/users");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls).toBeDefined();
        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
        expect(result.results[0].accessControls?.authType).toBe("unknown");
      });

      it("should infer auth required for /private/ paths", async () => {
        const context = createContext("file:///data/private/documents");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
      });

      it("should infer auth required for /protected/ paths", async () => {
        const context = createContext("resource://protected/config");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
      });

      it("should infer auth required for /secure/ paths", async () => {
        const context = createContext("https://api.example.com/secure/vault");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
      });
    });

    describe("Auth Type Inference", () => {
      it("should infer oauth authType for oauth URLs", async () => {
        const context = createContext("https://api.example.com/oauth/token");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
        expect(result.results[0].accessControls?.authType).toBe("oauth");
      });

      it("should infer oauth authType for bearer token URLs", async () => {
        const context = createContext("https://api.example.com/bearer/auth");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
        expect(result.results[0].accessControls?.authType).toBe("oauth");
      });

      it("should infer api_key authType for api-key URLs", async () => {
        const context = createContext(
          "https://api.example.com/api-key/validate",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
        expect(result.results[0].accessControls?.authType).toBe("api_key");
      });

      it("should infer api_key authType for apikey URLs", async () => {
        const context = createContext("https://api.example.com/apikey/check");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
        expect(result.results[0].accessControls?.authType).toBe("api_key");
      });
    });

    describe("Public Path Detection", () => {
      it("should infer no auth for /public/ paths", async () => {
        const context = createContext(
          "https://cdn.example.com/public/images/logo.png",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(false);
      });

      it("should infer no auth for /static/ paths", async () => {
        const context = createContext(
          "https://cdn.example.com/static/css/main.css",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(false);
      });

      it("should infer no auth for /assets/ paths", async () => {
        const context = createContext(
          "https://cdn.example.com/assets/js/bundle.js",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(false);
      });
    });

    describe("Default Inference", () => {
      it("should default to no auth for generic paths", async () => {
        const context = createContext("https://api.example.com/data/reports");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(false);
      });

      it("should initialize accessControls even without readResource", async () => {
        const context: Partial<AssessmentContext> = {
          resources: [
            { uri: "https://api.example.com/admin/users", name: "Test" },
          ],
          // No readResource function
        };
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls).toBeDefined();
        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
      });
    });

    describe("Case Insensitivity", () => {
      it("should detect protected paths case-insensitively", async () => {
        const context = createContext("https://api.example.com/ADMIN/users");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
      });

      it("should detect public paths case-insensitively", async () => {
        const context = createContext(
          "https://cdn.example.com/PUBLIC/logo.png",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].accessControls?.requiresAuth).toBe(false);
      });
    });
  });

  describe("dataClassification Field", () => {
    const createContext = (
      uri: string,
      content = "normal content",
    ): Partial<AssessmentContext> => ({
      resources: [{ uri, name: "Test Resource" }],
      readResource: async () => content,
    });

    describe("Restricted Classification", () => {
      it("should classify secret paths as restricted", async () => {
        const context = createContext("https://vault.example.com/secret/data");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify .pem files as restricted", async () => {
        const context = createContext("file:///certs/server.pem");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify .key files as restricted", async () => {
        const context = createContext("file:///keys/private.key");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify id_rsa files as restricted", async () => {
        const context = createContext("file:///home/user/.ssh/id_rsa");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify key-containing paths as restricted", async () => {
        const context = createContext(
          "https://vault.example.com/api-keys/master",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify credential paths as restricted", async () => {
        const context = createContext("file:///config/credentials.json");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify password paths as restricted", async () => {
        const context = createContext("file:///secure/passwords.txt");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify token paths as restricted", async () => {
        const context = createContext("https://api.example.com/tokens/access");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("restricted");
      });
    });

    describe("Confidential Classification", () => {
      it("should classify private paths as confidential", async () => {
        const context = createContext("file:///data/private/documents");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("confidential");
      });

      it("should classify confidential paths as confidential", async () => {
        const context = createContext(
          "https://api.example.com/confidential/reports",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("confidential");
      });

      it("should classify sensitive paths as confidential", async () => {
        const context = createContext("resource://sensitive/data");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("confidential");
      });

      it("should classify config paths as confidential", async () => {
        const context = createContext("file:///etc/app/config.yaml");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("confidential");
      });
    });

    describe("Public Classification", () => {
      it("should classify /public/ paths as public", async () => {
        const context = createContext(
          "https://cdn.example.com/public/logo.png",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("public");
      });

      it("should classify /static/ paths as public", async () => {
        const context = createContext(
          "https://cdn.example.com/static/main.css",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("public");
      });

      it("should classify /assets/ paths as public", async () => {
        const context = createContext(
          "https://cdn.example.com/assets/bundle.js",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("public");
      });

      it("should classify /docs/ paths as public", async () => {
        const context = createContext(
          "https://docs.example.com/docs/api-reference",
        );
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("public");
      });
    });

    describe("Internal Classification (Default)", () => {
      it("should default to internal for generic API endpoints", async () => {
        const context = createContext("https://api.example.com/data/reports");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("internal");
      });

      it("should default to internal for generic file paths", async () => {
        const context = createContext("file:///app/data/users.json");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].dataClassification).toBe("internal");
      });
    });

    describe("Content-Based Upgrade", () => {
      it("should upgrade to restricted when critical patterns detected", async () => {
        const content = `
          -----BEGIN RSA PRIVATE KEY-----
          MIIEpAIBAAKCAQEAr7eWuQv...
          -----END RSA PRIVATE KEY-----
        `;
        const context = createContext("resource://data/backup", content);
        const result = await assessor.assess(context as AssessmentContext);

        // Should upgrade from internal to restricted due to critical pattern
        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should upgrade to confidential when high-severity patterns detected", async () => {
        const content = "API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz1234";
        const context = createContext("resource://data/config", content);
        const result = await assessor.assess(context as AssessmentContext);

        // Should upgrade to confidential due to high-severity pattern
        expect(result.results[0].dataClassification).toBe("confidential");
      });

      it("should not downgrade existing classification", async () => {
        const content = "Normal content without sensitive patterns";
        const context = createContext("file:///app/.env", content);
        const result = await assessor.assess(context as AssessmentContext);

        // Should remain confidential due to .env URI pattern despite clean content
        expect(result.results[0].dataClassification).toBe("confidential");
      });
    });

    describe("URI-Based Sensitive Data Detection", () => {
      it("should mark sensitiveDataExposed=true and upgrade classification", async () => {
        const context = createContext("file:///app/.env");
        const result = await assessor.assess(context as AssessmentContext);

        expect(result.results[0].sensitiveDataExposed).toBe(true);
        expect(result.results[0].dataClassification).toBe("confidential");
      });
    });
  });

  describe("Resource Template Integration", () => {
    const createTemplateContext = (
      uriTemplate: string,
    ): Partial<AssessmentContext> => ({
      resourceTemplates: [
        { uriTemplate, name: "Test Template", mimeType: "text/plain" },
      ],
      readResource: async (uri: string) => {
        if (uri.includes("..")) {
          throw new Error("Path traversal blocked");
        }
        return "normal content";
      },
    });

    it("should initialize enrichment fields for template results", async () => {
      const context = createTemplateContext("file:///data/{filename}");
      const result = await assessor.assess(context as AssessmentContext);

      // First result is the template itself
      const templateResult = result.results[0];
      expect(templateResult.sensitivePatterns).toBeDefined();
      expect(templateResult.accessControls).toBeDefined();
      expect(templateResult.dataClassification).toBeDefined();
    });

    it("should infer accessControls from template URI", async () => {
      const context = createTemplateContext(
        "https://api.example.com/admin/{resource}",
      );
      const result = await assessor.assess(context as AssessmentContext);

      const templateResult = result.results[0];
      expect(templateResult.accessControls?.requiresAuth).toBe(true);
    });

    it("should infer dataClassification from template URI", async () => {
      const context = createTemplateContext("file:///secrets/{key}.pem");
      const result = await assessor.assess(context as AssessmentContext);

      const templateResult = result.results[0];
      expect(templateResult.dataClassification).toBe("restricted");
    });

    it("should initialize enrichment fields for traversal test results", async () => {
      const context = createTemplateContext("file:///data/{filename}");
      const result = await assessor.assess(context as AssessmentContext);

      // Remaining results are traversal tests (5 payloads)
      const traversalResults = result.results.slice(1);
      expect(traversalResults.length).toBeGreaterThan(0);

      traversalResults.forEach((r) => {
        expect(r.sensitivePatterns).toBeDefined();
        expect(r.accessControls).toBeDefined();
        expect(r.dataClassification).toBeDefined();
      });
    });

    it("should use template URI for traversal result classifications", async () => {
      const context = createTemplateContext(
        "https://api.example.com/public/{file}",
      );
      const result = await assessor.assess(context as AssessmentContext);

      // All results (template + traversals) should inherit public classification
      result.results.forEach((r) => {
        expect(r.dataClassification).toBe("public");
      });
    });
  });

  describe("Integration - All Fields Together", () => {
    it("should populate all enrichment fields for normal resource", async () => {
      const context: Partial<AssessmentContext> = {
        resources: [
          { uri: "https://api.example.com/admin/users", name: "Admin Users" },
        ],
        readResource: async () => "User data: admin@example.com",
      };

      const result = await assessor.assess(context as AssessmentContext);
      const testResult = result.results[0];

      // All enrichment fields should be populated
      expect(testResult.sensitivePatterns).toBeDefined();
      expect(Array.isArray(testResult.sensitivePatterns)).toBe(true);

      expect(testResult.accessControls).toBeDefined();
      expect(testResult.accessControls?.requiresAuth).toBe(true);

      expect(testResult.dataClassification).toBeDefined();
      expect(testResult.dataClassification).toBe("internal");

      // Email should be detected
      const emailPattern = testResult.sensitivePatterns?.find(
        (p) => p.pattern === "email_address",
      );
      expect(emailPattern?.detected).toBe(true);
    });

    it("should handle complex scenario with multiple enrichments", async () => {
      const content = `
        Configuration:
        admin_password = "super_secret"
        api_key = sk-1234567890abcdefghijklmnopqrstuvwxyz1234
        contact: admin@company.com
      `;

      const context: Partial<AssessmentContext> = {
        resources: [{ uri: "file:///config/secrets.conf", name: "Secrets" }],
        readResource: async () => content,
      };

      const result = await assessor.assess(context as AssessmentContext);
      const testResult = result.results[0];

      // Should detect multiple sensitive patterns
      const detectedPatterns =
        testResult.sensitivePatterns?.filter((p) => p.detected) || [];
      expect(detectedPatterns.length).toBeGreaterThanOrEqual(3);

      // Should be classified as restricted due to "secrets" in URI
      expect(testResult.dataClassification).toBe("restricted");

      // Should infer internal classification, but upgraded by critical content
      expect(testResult.accessControls?.requiresAuth).toBe(false); // No explicit auth indicator

      // Should mark as sensitive data exposed
      expect(testResult.sensitiveDataExposed).toBe(true);
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty URI gracefully", async () => {
      const context: Partial<AssessmentContext> = {
        resources: [{ uri: "", name: "Empty" }],
        readResource: async () => "content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.results[0].sensitivePatterns).toBeDefined();
      expect(result.results[0].accessControls).toBeDefined();
      expect(result.results[0].dataClassification).toBe("internal");
    });

    it("should handle URI with mixed case patterns", async () => {
      const context: Partial<AssessmentContext> = {
        resources: [
          { uri: "https://api.example.com/PrIvAtE/data", name: "Mixed Case" },
        ],
        readResource: async () => "content",
      };

      const result = await assessor.assess(context as AssessmentContext);

      expect(result.results[0].accessControls?.requiresAuth).toBe(true);
      expect(result.results[0].dataClassification).toBe("confidential");
    });

    it("should handle content with no sensitive patterns", async () => {
      const context: Partial<AssessmentContext> = {
        resources: [{ uri: "resource://test", name: "Clean" }],
        readResource: async () => "This is completely normal text.",
      };

      const result = await assessor.assess(context as AssessmentContext);

      const detectedPatterns =
        result.results[0].sensitivePatterns?.filter((p) => p.detected) || [];
      expect(detectedPatterns.length).toBe(0);
      expect(result.results[0].sensitiveDataExposed).toBe(false);
    });

    it("should handle read errors without breaking enrichment fields", async () => {
      const context: Partial<AssessmentContext> = {
        resources: [{ uri: "resource://broken", name: "Broken" }],
        readResource: async () => {
          throw new Error("Read failed");
        },
      };

      const result = await assessor.assess(context as AssessmentContext);

      // Enrichment fields should still be initialized from URI
      expect(result.results[0].sensitivePatterns).toBeDefined();
      expect(result.results[0].accessControls).toBeDefined();
      expect(result.results[0].dataClassification).toBe("internal");
      expect(result.results[0].accessible).toBe(false);
    });
  });
});
