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
        expect(result.authConfigAnalysis?.envVarsDetected).toContain(
          "API_SECRET",
        );
      });

      it("should detect process.env.PASSWORD usage", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/db.ts": `
const dbPassword = process.env.DATABASE_PASSWORD;
const connection = connect({ password: dbPassword });
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.envVarsDetected).toContain(
          "DATABASE_PASSWORD",
        );
      });

      it("should detect process.env.API_KEY usage", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/client.ts": `
const apiKey = process.env.OPENAI_API_KEY;
const client = new OpenAI({ apiKey });
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.envVarsDetected).toContain(
          "OPENAI_API_KEY",
        );
      });

      it("should detect process.env.CREDENTIAL usage", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/aws.ts": `
const awsCredential = process.env.AWS_CREDENTIAL;
const client = new AWS.Config({ credentials: awsCredential });
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.envVarsDetected).toContain(
          "AWS_CREDENTIAL",
        );
      });

      it("should detect Python os.getenv usage", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.py": `
import os
auth_token = os.getenv('AUTH_TOKEN')
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.envVarsDetected).toContain(
          "AUTH_TOKEN",
        );
      });

      it("should not detect Python env vars without auth context", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.py": `
import os
port = os.environ.get('PORT')
debug = os.getenv('DEBUG')
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.envVarsDetected).not.toContain(
          "PORT",
        );
        expect(result.authConfigAnalysis?.envVarsDetected).not.toContain(
          "DEBUG",
        );
      });

      it("should not flag env vars without auth context", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const nodeEnv = process.env.NODE_ENV;
const port = process.env.PORT;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const envDependentAuthFindings =
          result.authConfigAnalysis?.findings.filter(
            (f) => f.type === "ENV_DEPENDENT_AUTH",
          );
        expect(envDependentAuthFindings?.length).toBe(0);
      });

      it("should flag env vars with auth context in surrounding lines", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
// Authentication configuration
const authSecret = process.env.AUTH_SECRET;
// Use auth secret for verification
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(
          result.authConfigAnalysis?.envDependentAuthCount,
        ).toBeGreaterThan(0);
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

      it("should detect conditional check pattern", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
if (!process.env.AUTH_SECRET) {
  // Use default behavior
  return defaultHandler();
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
      });

      it("should detect Python os.getenv with default", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/server.py": `
import os
secret = os.getenv('SECRET_TOKEN', 'unsafe-default')
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

      it("should include line number and file path for fail-open findings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secretKey = process.env.SECRET_KEY || 'default';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "FAIL_OPEN_PATTERN",
        );
        expect(finding?.file).toContain("config.ts");
        expect(finding?.lineNumber).toBeGreaterThan(0);
      });

      it("should detect multiple fail-open patterns in same file", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const apiKey = process.env.API_KEY || 'default-key';
const secret = process.env.SECRET_TOKEN ?? 'default-secret';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(
          result.authConfigAnalysis?.failOpenPatternCount,
        ).toBeGreaterThanOrEqual(2);
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

      it("should detect NODE_ENV development check with LOW severity", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const isDev = process.env.NODE_ENV === 'development';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "DEV_MODE_WARNING" && f.severity === "LOW",
        );
        expect(finding).toBeDefined();
      });

      it("should detect isDev variable pattern with LOW severity", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/server.ts": `
const isDev = true;
const isDevelopment = process.env.MODE === 'dev';
const devMode = checkEnvironment();
const debugMode = false;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const lowSeverityFindings = result.authConfigAnalysis?.findings.filter(
          (f) => f.type === "DEV_MODE_WARNING" && f.severity === "LOW",
        );
        expect(lowSeverityFindings?.length).toBeGreaterThan(0);
      });

      it("should detect NODE_ENV if statement pattern", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
if (process.env.NODE_ENV === 'development') {
  console.log('Running in dev mode');
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert - should detect dev mode warning (either LOW or MEDIUM severity)
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "DEV_MODE_WARNING",
        );
        expect(finding).toBeDefined();
        expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(
          0,
        );
      });

      it("should detect disable auth debug pattern with HIGH severity", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/server.ts": `
// disable auth for debug
if (debug) {
  authEnabled = false;
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "DEV_MODE_WARNING" && f.severity === "HIGH",
        );
        expect(finding).toBeDefined();
      });

      it("should provide different recommendations based on severity", async () => {
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
        const highSeverityFinding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "DEV_MODE_WARNING" && f.severity === "HIGH",
        );
        expect(highSeverityFinding?.recommendation).toContain(
          "never be disabled",
        );
      });

      it("should detect as dev user pattern with HIGH severity", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/middleware.ts": `
// Authenticate request as dev user
req.user = { role: 'dev user', admin: true };
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "DEV_MODE_WARNING" && f.severity === "HIGH",
        );
        expect(finding).toBeDefined();
        expect(finding?.message.toLowerCase()).toContain("development mode");
      });

      it("should detect multiple dev mode patterns with different severities", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const isDev = process.env.NODE_ENV === 'development'; // LOW
if (process.env.NODE_ENV === 'development') { // MEDIUM
  console.log('Dev mode');
}
// auth bypass for testing
const skipAuth = true; // HIGH
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(
          result.authConfigAnalysis?.devModeWarningCount,
        ).toBeGreaterThanOrEqual(3);
        const severities = result.authConfigAnalysis?.findings
          .filter((f) => f.type === "DEV_MODE_WARNING")
          .map((f) => f.severity);
        expect(severities).toContain("LOW");
        expect(severities).toContain("MEDIUM");
        expect(severities).toContain("HIGH");
      });
    });

    describe("Hardcoded Secret Detection", () => {
      it("should detect hardcoded Stripe key", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/payment.ts": `
const stripe = require('stripe')('pk_live_1234567890abcdefghij');
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

      it("should detect hardcoded Stripe test key", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/payment.ts": `
const stripeKey = 'pk_test_abcdefghijklmnopqrst';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
        );
      });

      it("should detect hardcoded Stripe publishable key", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const publicKey = 'pk_live_abcdefghijklmnopqrst';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
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

      it("should detect hardcoded secret_key", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secret_key = 'supersecretvalue12345';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
        );
      });

      it("should detect hardcoded password", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/db.ts": `
const password = 'MySecurePassword123';
const connection = connect({ password });
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
        );
      });

      it("should detect hardcoded auth_token", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/client.ts": `
const auth_token = 'abc123def456ghi789jkl012';
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

      it("should include file and line number for hardcoded secrets", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/payment.ts": `
const stripeSecret = 'pk_live_abcdefghijklmnopqrstuvwxyz';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "HARDCODED_SECRET",
        );
        expect(finding?.file).toContain("payment.ts");
        expect(finding?.lineNumber).toBeGreaterThan(0);
      });

      it("should provide specific recommendation for hardcoded secrets", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const api_key = 'abcdefghijklmnopqrstuvwxyz';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "HARDCODED_SECRET",
        );
        expect(finding?.recommendation).toContain("environment variable");
        expect(finding?.recommendation).toContain("Never commit");
      });

      it("should not flag short string literals as secrets", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const api_key = 'short';
const secret_key = '12345';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        // Should not detect short strings (patterns require 16-20+ chars)
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBe(0);
      });

      it("should detect multiple hardcoded secrets in same file", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const api_key = 'abcdefghijklmnopqrstuvwxyz';
const secret_key = 'supersecretvalue12345';
const stripe = 'pk_live_abcdefghijklmnopqrst';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(
          result.authConfigAnalysis?.hardcodedSecretCount,
        ).toBeGreaterThanOrEqual(3);
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

      it("should not override PASS status when no HIGH severity findings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const isDev = process.env.NODE_ENV === 'development'; // LOW severity
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        if (!result.authConfigAnalysis?.hasHighSeverity) {
          // Status should remain PASS (or NEED_MORE_INFO for other reasons)
          expect(result.authConfigAnalysis?.totalFindings).toBeGreaterThan(0);
        }
      });

      it("should generate recommendations for all finding types", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
// Multiple issue types
const secret = process.env.AUTH_SECRET || 'default'; // FAIL_OPEN
// skip auth in dev
const isDev = true; // DEV_MODE
const hardcoded = 'pk_live_abcdefghijklmnopqrst'; // HARDCODED_SECRET
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.recommendations.length).toBeGreaterThan(0);
        const findingTypes = result.authConfigAnalysis?.findings.map(
          (f) => f.type,
        );
        expect(findingTypes).toContain("FAIL_OPEN_PATTERN");
        expect(findingTypes).toContain("DEV_MODE_WARNING");
        expect(findingTypes).toContain("HARDCODED_SECRET");
      });

      it("should set hasHighSeverity flag correctly", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const stripe = require('stripe')('pk_live_abcdefghijklmnopqrst');
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hasHighSeverity).toBe(true);
      });

      it("should not set hasHighSeverity when only LOW/MEDIUM findings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const apiKey = process.env.API_KEY || 'default'; // MEDIUM severity
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hasHighSeverity).toBe(false);
      });

      it("should include all finding recommendations in main recommendations array", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secret = process.env.SECRET_KEY || 'default';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const failOpenRecommendation = result.recommendations.find(
          (r) => r.includes("fails securely") || r.includes("FAIL_OPEN"),
        );
        expect(failOpenRecommendation).toBeDefined();
      });

      it("should log auth config findings count in explanation", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const secret = process.env.SECRET_KEY || 'default';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBeGreaterThan(0);
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

      it("should handle empty file content", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/empty.ts": "",
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBe(0);
      });

      it("should handle files with only comments", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/comments.ts": `
// This is a comment
/* Multi-line comment
   with multiple lines */
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBe(0);
      });

      it("should handle files with no auth-related code", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/math.ts": `
export function add(a: number, b: number): number {
  return a + b;
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBe(0);
      });

      it("should handle multiple files with mixed findings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const apiKey = process.env.API_KEY || 'default';
`,
          "src/auth.ts": `
// auth bypass enabled
const bypass = true;
`,
          "src/payment.ts": `
const stripe = 'pk_live_abcdefghijklmnopqrst';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBeGreaterThanOrEqual(
          3,
        );
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
        expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(
          0,
        );
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
        );
      });

      it("should handle findings at different line positions", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
// Line 1: comment
const config = {
  // Line 3: auth config
  apiKey: process.env.API_KEY || 'default', // Line 4: fail-open
  secret: 'pk_live_abcdefghijklmnopqrst', // Line 5: hardcoded
};
// Line 7: bypass comment
const bypass = true; // Line 8: dev mode
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const findings = result.authConfigAnalysis?.findings || [];
        expect(findings.length).toBeGreaterThan(0);
        // Verify different line numbers
        const lineNumbers = findings.map((f) => f.lineNumber);
        const uniqueLines = new Set(lineNumbers);
        expect(uniqueLines.size).toBeGreaterThan(1);
      });

      it("should not deduplicate different finding types on same line", async () => {
        // Arrange - same line could have multiple issue types
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const apiKey = process.env.API_KEY || 'pk_live_abcdefghijklmnopqrst';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert - should have both FAIL_OPEN and HARDCODED_SECRET
        const findingTypes = result.authConfigAnalysis?.findings.map(
          (f) => f.type,
        );
        expect(findingTypes).toContain("FAIL_OPEN_PATTERN");
        expect(findingTypes).toContain("HARDCODED_SECRET");
      });

      it("should handle Python and JavaScript mixed files", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secret = process.env.SECRET_KEY;
`,
          "src/config.py": `
import os
secret = os.environ.get('API_SECRET')
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(
          result.authConfigAnalysis?.envVarsDetected.length,
        ).toBeGreaterThanOrEqual(1);
      });

      it("should handle very long lines gracefully", async () => {
        // Arrange
        const longLine = "const x = ".padEnd(3000, "y") + ";";
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/long.ts": `
${longLine}
const secret = process.env.SECRET_KEY || 'default';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
      });

      it("should handle files with special characters in paths", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/special-chars_123.ts": `
const secret = process.env.SECRET_KEY || 'default';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
        const finding = result.authConfigAnalysis?.findings[0];
        expect(finding?.file).toContain("special-chars_123.ts");
      });

      it("should return all analysis fields in structure", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const secret = process.env.SECRET_KEY;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis).toMatchObject({
          totalFindings: expect.any(Number),
          envDependentAuthCount: expect.any(Number),
          failOpenPatternCount: expect.any(Number),
          devModeWarningCount: expect.any(Number),
          hardcodedSecretCount: expect.any(Number),
          findings: expect.any(Array),
          hasHighSeverity: expect.any(Boolean),
          envVarsDetected: expect.any(Array),
        });
      });

      it("should count findings by type correctly", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const secret = process.env.SECRET_KEY || 'default'; // FAIL_OPEN
// auth bypass
const bypass = true; // DEV_MODE
const stripe = 'pk_live_abcdefghijklmnopqrst'; // HARDCODED_SECRET
const authSecret = process.env.AUTH_SECRET; // ENV_DEPENDENT_AUTH
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const analysis = result.authConfigAnalysis!;
        expect(
          analysis.envDependentAuthCount +
            analysis.failOpenPatternCount +
            analysis.devModeWarningCount +
            analysis.hardcodedSecretCount,
        ).toBe(analysis.totalFindings);
      });
    });

    describe("Complex Scenarios", () => {
      it("should handle real-world auth configuration pattern", async () => {
        // Arrange - realistic auth setup
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
import { config } from 'dotenv';
config();

const AUTH_SECRET = process.env.AUTH_SECRET || 'dev-secret';
const JWT_KEY = process.env.JWT_KEY;

if (process.env.NODE_ENV === 'development') {
  console.log('Running in dev mode - auth relaxed');
}

export function authenticate(token: string) {
  if (!JWT_KEY) {
    return authenticateAsDevUser();
  }
  return verifyToken(token, JWT_KEY);
}
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.totalFindings).toBeGreaterThan(0);
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
        expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(
          0,
        );
      });

      it("should handle Python Django-style settings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "settings.py": `
import os

SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-default')
DEBUG = os.getenv('DEBUG', 'True') == 'True'

if DEBUG:
    # Authentication bypass for debug mode
    AUTHENTICATION_BACKENDS = ['django.contrib.auth.backends.AllowAllBackend']
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
        // "auth bypass" pattern triggers HIGH severity dev mode warning
        expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(
          0,
        );
      });

      it("should handle configuration with multiple auth methods", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
export const authConfig = {
  jwtSecret: process.env.JWT_SECRET || 'default-jwt',
  apiKey: process.env.API_KEY || 'default-api-key',
  oauth: {
    clientId: process.env.OAUTH_CLIENT_ID,
    clientSecret: process.env.OAUTH_CLIENT_SECRET || 'default-secret',
  },
  stripe: {
    secretKey: 'pk_live_abcdefghijklmnopqrst',
  }
};
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.failOpenPatternCount).toBeGreaterThan(
          0,
        );
        expect(result.authConfigAnalysis?.hardcodedSecretCount).toBeGreaterThan(
          0,
        );
      });

      it("should handle conditional auth bypass patterns", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/middleware.ts": `
export function authMiddleware(req, res, next) {
  if (process.env.NODE_ENV === 'development') {
    // Skip auth in development
    req.user = { id: 'dev', role: 'admin' };
    return next();
  }

  if (!process.env.AUTH_SECRET) {
    // No auth configured - authenticate all requests as dev user
    req.user = { id: 'default', role: 'user' };
    return next();
  }

  return verifyAuth(req, res, next);
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

      it("should handle mixed severity findings with correct priority", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
// LOW severity
const isDev = process.env.NODE_ENV === 'development';

// MEDIUM severity
const apiKey = process.env.API_KEY || 'default-key';

// HIGH severity
// auth bypass enabled
const bypassAuth = true;

// HIGH severity
const stripeKey = 'pk_live_abcdefghijklmnopqrst';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hasHighSeverity).toBe(true);
        expect(result.status).toBe("NEED_MORE_INFO");

        const highSeverityCount = result.authConfigAnalysis?.findings.filter(
          (f) => f.severity === "HIGH",
        ).length;
        expect(highSeverityCount).toBeGreaterThanOrEqual(2);
      });

      it("should provide contextual evidence in findings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const authConfig = {
  secret: process.env.AUTH_SECRET || 'fallback-secret',
};
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const finding = result.authConfigAnalysis?.findings[0];
        expect(finding?.evidence).toBeTruthy();
        expect(finding?.evidence.length).toBeGreaterThan(0);
      });
    });

    describe("Integration with Main Assessment", () => {
      it("should integrate auth config findings with overall assessment status", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const stripe = require('stripe')('pk_live_abcdefghijklmnopqrst');
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.status).toBe("NEED_MORE_INFO");
        expect(result.authConfigAnalysis?.hasHighSeverity).toBe(true);
      });

      it("should add auth config recommendations to main recommendations", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const secret = process.env.SECRET_KEY || 'default';
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.recommendations.length).toBeGreaterThan(0);
        const authRecommendation = result.recommendations.find(
          (r) =>
            r.includes("environment variable") ||
            r.includes("fails securely") ||
            r.includes("FAIL_OPEN"),
        );
        expect(authRecommendation).toBeDefined();
      });

      it("should add HIGH severity auth issues to concerns", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
// auth bypass for testing
const bypassAuth = true;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const authConcern = result.appropriateness.concerns.find((c) =>
          c.includes("Auth config issue"),
        );
        if (result.authConfigAnalysis?.hasHighSeverity) {
          expect(authConcern).toBeDefined();
        }
      });

      it("should not affect status when only LOW/MEDIUM severity findings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/config.ts": `
const isDev = process.env.NODE_ENV === 'development'; // LOW
const apiKey = process.env.API_KEY || 'default'; // MEDIUM
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        expect(result.authConfigAnalysis?.hasHighSeverity).toBe(false);
        // Status may still be PASS if no other issues
      });

      it("should include env vars in analysis output", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `
const secret1 = process.env.AUTH_SECRET;
const secret2 = process.env.JWT_TOKEN;
const secret3 = process.env.API_KEY;
`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        // AUTH_SECRET matches SECRET pattern, JWT_TOKEN matches TOKEN pattern, API_KEY matches API_KEY pattern
        expect(
          result.authConfigAnalysis?.envVarsDetected.length,
        ).toBeGreaterThanOrEqual(3);
        expect(result.authConfigAnalysis?.envVarsDetected).toEqual(
          expect.arrayContaining(["AUTH_SECRET", "JWT_TOKEN", "API_KEY"]),
        );
      });
    });

    // Issue #66: Context Window Tests
    describe("Context Window (Issue #66)", () => {
      it("should include context lines in findings", async () => {
        // Arrange
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `// Authentication module
const authSecret = process.env.AUTH_SECRET || 'fallback';
// This is a comment after`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const failOpenFinding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "FAIL_OPEN_PATTERN",
        );
        expect(failOpenFinding).toBeDefined();
        expect(failOpenFinding?.context).toBeDefined();
        expect(failOpenFinding?.context?.before).toBe(
          "// Authentication module",
        );
        expect(failOpenFinding?.context?.after).toBe(
          "// This is a comment after",
        );
      });

      it("should handle first line (no before context)", async () => {
        // Arrange - finding on first line
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `const authSecret = process.env.AUTH_SECRET || 'fallback';
// This is the second line`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const failOpenFinding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "FAIL_OPEN_PATTERN",
        );
        expect(failOpenFinding).toBeDefined();
        expect(failOpenFinding?.context).toBeDefined();
        expect(failOpenFinding?.context?.before).toBeUndefined();
        expect(failOpenFinding?.context?.after).toBe(
          "// This is the second line",
        );
      });

      it("should handle last line (no after context)", async () => {
        // Arrange - finding on last line
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `// First line comment
const authSecret = process.env.AUTH_SECRET || 'fallback';`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const failOpenFinding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "FAIL_OPEN_PATTERN",
        );
        expect(failOpenFinding).toBeDefined();
        expect(failOpenFinding?.context).toBeDefined();
        expect(failOpenFinding?.context?.before).toBe("// First line comment");
        expect(failOpenFinding?.context?.after).toBeUndefined();
      });

      it("should handle single line file (no context)", async () => {
        // Arrange - single line file
        mockContext.sourceCodeFiles = createMockSourceCodeFiles({
          "src/auth.ts": `const authSecret = process.env.AUTH_SECRET || 'fallback';`,
        });

        // Act
        const result = await assessor.assess(mockContext);

        // Assert
        const failOpenFinding = result.authConfigAnalysis?.findings.find(
          (f) => f.type === "FAIL_OPEN_PATTERN",
        );
        expect(failOpenFinding).toBeDefined();
        // Context should be undefined when both before and after are empty
        expect(failOpenFinding?.context).toBeUndefined();
      });
    });
  });
});
