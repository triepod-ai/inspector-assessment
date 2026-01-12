import { AuthenticationAssessor } from "./AuthenticationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockSourceCodeFiles,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("AuthenticationAssessor - Environment Variable Detection", () => {
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

  afterEach(() => {
    jest.clearAllMocks();
  });

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
      expect(result.authConfigAnalysis?.envVarsDetected).not.toContain("PORT");
      expect(result.authConfigAnalysis?.envVarsDetected).not.toContain("DEBUG");
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
      expect(result.authConfigAnalysis?.envDependentAuthCount).toBeGreaterThan(
        0,
      );
    });
  });
});
