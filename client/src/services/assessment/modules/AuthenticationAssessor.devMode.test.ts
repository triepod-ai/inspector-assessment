import { AuthenticationAssessor } from "./AuthenticationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockSourceCodeFiles,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("AuthenticationAssessor - Development Mode Warning Detection", () => {
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
      expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(0);
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
      expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(0);
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
      expect(result.authConfigAnalysis?.devModeWarningCount).toBeGreaterThan(0);
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
});
