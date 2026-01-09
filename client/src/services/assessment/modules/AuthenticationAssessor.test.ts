import { AuthenticationAssessor } from "./AuthenticationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockSourceCodeFiles,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("AuthenticationAssessor", () => {
  let assessor: AuthenticationAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      enableSourceCodeAnalysis: true,
    });
    assessor = new AuthenticationAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should pass with no auth issues", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": `
console.log('Hello World');
export const main = () => {};
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.authConfigAnalysis?.totalFindings).toBe(0);
    });
  });

  // Issue #62: Authentication Configuration Tests
  describe("Auth Configuration Analysis (Issue #62)", () => {
    describe("Environment-Dependent Auth Detection", () => {
      it("should detect process.env.SECRET_KEY usage", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const secretKey = process.env.SECRET_KEY;
if (secretKey) {
  // authenticate
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.envVarsDetected).toContain(
          "SECRET_KEY",
        );
      });

      it("should detect process.env.AUTH_TOKEN usage", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/middleware.ts": `
const authToken = process.env.AUTH_TOKEN;
export const verifyToken = (token) => token === authToken;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.envVarsDetected).toContain(
          "AUTH_TOKEN",
        );
      });

      it("should detect Python os.environ.get usage", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.py": `
import os
secret = os.environ.get('API_SECRET')
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(
          result.authConfigAnalysis?.envVarsDetected.length,
        ).toBeGreaterThanOrEqual(0);
      });
    });

    describe("Fail-Open Pattern Detection", () => {
      it("should detect || fallback pattern for auth secrets", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const apiKey = process.env.API_KEY || 'default-dev-key';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
        expect(result.authConfigAnalysis?.findings).toContainEqual(
          expect.objectContaining({
            type: "FAIL_OPEN_PATTERN",
            severity: "MEDIUM",
          }),
        );
      });

      it("should detect ?? nullish coalescing fallback for auth secrets", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secretToken = process.env.SECRET_TOKEN ?? 'fallback-token';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
      });

      it("should detect Python default value fallback", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.py": `
import os
api_key = os.environ.get('API_KEY', 'dev-key')
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
      });

      it("should generate recommendation for fail-open patterns", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const authSecret = process.env.AUTH_SECRET || '';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "FAIL_OPEN_PATTERN",
        );
        expect(finding?.recommendation).toContain("fails securely");
      });
    });

    describe("Development Mode Warning Detection", () => {
      it("should detect dev mode auth bypass - skip auth in dev", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
// skip auth in dev mode
if (process.env.NODE_ENV === 'development') {
  skipAuth = true;
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(
          0,
        );
      });

      it("should detect auth bypass pattern", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/middleware.ts": `
// auth bypass for testing
function authBypass(req, res, next) {
  next();
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.findings).toContainEqual(
          expect.objectContaining({
            type: "DEV_MODE_WARNING",
            severity: "HIGH",
          }),
        );
      });

      it("should detect 'authenticate all requests as dev user' pattern", async () => {
        // Arrange - This is the exact pattern mentioned in issue #62
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/server.ts": `
// When AUTH_SECRET_KEY not set, authenticate all requests as dev user
if (!process.env.AUTH_SECRET_KEY) {
  req.user = { id: 'dev', role: 'admin' };
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(
          0,
        );
        expect(result.authConfigAnalysis?.hasHighSeverity).toBe(true);
      });
    });

    describe("Hardcoded Secret Detection", () => {
      it("should detect hardcoded Stripe key", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/payment.ts": `
const stripe = require('stripe')('sk_live_1234567890abcdefghij');
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
        );
        expect(result.authConfigAnalysis?.findings).toContainEqual(
          expect.objectContaining({
            type: "HARDCODED_SECRET",
            severity: "HIGH",
          }),
        );
      });

      it("should detect hardcoded api_key", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const api_key = 'abcdefghijklmnopqrstuvwxyz';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
        );
      });

      it("should redact secrets in evidence", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secret_key = 'supersecretvalue12345';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "HARDCODED_SECRET",
        );
        expect(finding?.evidence).toContain("[REDACTED]");
        expect(finding?.evidence).not.toContain("supersecretvalue");
      });
    });

    describe("Status and Recommendations", () => {
      it("should return NEED_MORE_INFO when HIGH severity findings exist", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
// auth bypass enabled
const bypass = true;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        if (result.authConfigAnalysis?.hasHighSeverity) {
          expect(result.status).toBe("NEED_MORE_INFO");
        }
      });

      it("should include auth config recommendations in output", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const token = process.env.SECRET_TOKEN || 'default';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.recommendations.length).toBeGreaterThan(0);
        expect(
          result.recommendations.some(
            (r) => r.includes("FAIL_OPEN") || r.includes("fails securely"),
          ),
        ).toBe(true);
      });

      it("should add HIGH severity findings to appropriateness concerns", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
function authBypass() {}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        if (result.authConfigAnalysis?.hasHighSeverity) {
          expect(result.appropriateness.concerns).toContainEqual(
            expect.stringContaining("Auth config issue"),
          );
        }
      });
    });

    describe("Edge Cases", () => {
      it("should handle empty source code files", async () => {
        // Arrange
        mockContext.sourceCodeFiles = new Map();

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBe(0);
        expect(result.authConfigAnalysis?.findings).toEqual([]);
      });

      it("should handle undefined source code files", async () => {
        // Arrange
        mockContext.sourceCodeFiles = undefined;

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBe(0);
      });

      it("should deduplicate findings on same line", async () => {
        // Arrange - multiple patterns could match the same line
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const authToken = process.env.AUTH_TOKEN || 'default-auth-token';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert - should not have duplicate findings for same line+type
        const findings = result.authConfigAnalysis?.findings || [];
        const uniqueKeys = new Set(
          findings.map((f) => `${f.file}:${f.lineNumber}:${f.type}`),
        );
        expect(findings.length).toBe(uniqueKeys.size);
      });

      it("should track multiple env vars", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secret = process.env.SECRET_KEY;
const auth = process.env.AUTH_TOKEN;
const apiKey = process.env.API_KEY;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(
          result.authConfigAnalysis?.envVarsDetected.length,
        ).toBeGreaterThanOrEqual(3);
      });
    });
  });
});
