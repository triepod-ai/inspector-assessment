import { AuthenticationAssessor } from "./AuthenticationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockSourceCodeFiles,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("AuthenticationAssessor - Hardcoded Secret Detection", () => {
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
});
