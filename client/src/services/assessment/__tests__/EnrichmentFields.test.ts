/**
 * Enrichment Fields Unit Tests
 *
 * Tests for the Issue #9 enrichment fields added to assessor modules:
 * - ResourceAssessor: sensitivePatterns, accessControls, dataClassification
 * - PromptAssessor: promptTemplate, dynamicContent
 * - PortabilityAssessor: shellCommands, platformCoverage
 * - CrossCapabilitySecurityAssessor: attackChain, confidence, privilegeEscalationVector
 */

import { ResourceAssessor } from "../modules/ResourceAssessor";
import { PromptAssessor } from "../modules/PromptAssessor";
import { PortabilityAssessor } from "../modules/PortabilityAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import {
  AssessmentConfiguration,
  PortabilityIssue,
} from "@/lib/assessmentTypes";

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

describe("Enrichment Fields (Issue #9)", () => {
  describe("ResourceAssessor Enrichment", () => {
    let assessor: ResourceAssessor;

    beforeEach(() => {
      assessor = new ResourceAssessor(createConfig());
    });

    afterEach(() => {
      jest.clearAllMocks();
    });

    describe("sensitivePatterns detection", () => {
      const createContext = (
        resourceContent: string,
        uri: string = "resource://test/data",
      ): Partial<AssessmentContext> => ({
        resources: [{ uri, name: "Test Resource" }],
        readResource: async () => resourceContent,
      });

      it("should detect SSN patterns in content", async () => {
        const content = "User SSN: 123-45-6789";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        expect(result.results[0].sensitivePatterns).toBeDefined();
        const ssnPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "ssn_pattern" && p.detected,
        );
        expect(ssnPattern).toBeDefined();
        expect(ssnPattern?.severity).toBe("critical");
      });

      it("should detect credit card patterns in content", async () => {
        const content = "Card: 4532-1234-5678-9012";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        expect(result.results[0].sensitivePatterns).toBeDefined();
        const ccPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "credit_card" && p.detected,
        );
        expect(ccPattern).toBeDefined();
        expect(ccPattern?.severity).toBe("critical");
      });

      it("should detect API key patterns in content", async () => {
        // OpenAI API keys start with sk- and have 32+ characters
        const content = "API_KEY=sk-1234567890abcdefghijklmnopqrstuvwxyz";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        expect(result.results[0].sensitivePatterns).toBeDefined();
        const apiKeyPattern = result.results[0].sensitivePatterns?.find(
          (p) => p.pattern === "api_key_openai" && p.detected,
        );
        expect(apiKeyPattern).toBeDefined();
        expect(apiKeyPattern?.severity).toBe("high");
      });

      it("should not detect patterns in clean content", async () => {
        const content = "This is a normal document with no sensitive data.";

        const result = await assessor.assess(
          createContext(content) as AssessmentContext,
        );

        const detectedPatterns =
          result.results[0].sensitivePatterns?.filter((p) => p.detected) || [];
        expect(detectedPatterns.length).toBe(0);
      });
    });

    describe("accessControls inference", () => {
      const createContext = (uri: string): Partial<AssessmentContext> => ({
        resources: [{ uri, name: "Test Resource" }],
        readResource: async () => "content",
      });

      it("should infer auth required for private paths", async () => {
        const result = await assessor.assess(
          createContext("resource://api/private/user") as AssessmentContext,
        );

        expect(result.results[0].accessControls).toBeDefined();
        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
      });

      it("should infer oauth auth type for oauth URIs", async () => {
        const result = await assessor.assess(
          createContext("resource://api/oauth/token") as AssessmentContext,
        );

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
        expect(result.results[0].accessControls?.authType).toBe("oauth");
      });

      it("should infer api_key auth type for api key URIs", async () => {
        const result = await assessor.assess(
          createContext("resource://api/api-key/validate") as AssessmentContext,
        );

        expect(result.results[0].accessControls?.requiresAuth).toBe(true);
        expect(result.results[0].accessControls?.authType).toBe("api_key");
      });

      it("should not require auth for public paths", async () => {
        const result = await assessor.assess(
          createContext("resource://cdn/public/images") as AssessmentContext,
        );

        expect(result.results[0].accessControls?.requiresAuth).toBe(false);
      });
    });

    describe("dataClassification assignment", () => {
      const createContext = (uri: string): Partial<AssessmentContext> => ({
        resources: [{ uri, name: "Test Resource" }],
        readResource: async () => "content",
      });

      it("should classify secret URIs as restricted", async () => {
        const result = await assessor.assess(
          createContext("resource://config/secrets") as AssessmentContext,
        );

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify password URIs as restricted", async () => {
        const result = await assessor.assess(
          createContext("resource://auth/password-reset") as AssessmentContext,
        );

        expect(result.results[0].dataClassification).toBe("restricted");
      });

      it("should classify .env files as confidential", async () => {
        const result = await assessor.assess(
          createContext(
            "resource://config/.env.production",
          ) as AssessmentContext,
        );

        expect(result.results[0].dataClassification).toBe("confidential");
      });

      it("should classify public URIs as public", async () => {
        const result = await assessor.assess(
          createContext(
            "resource://cdn/public/assets/logo.png",
          ) as AssessmentContext,
        );

        expect(result.results[0].dataClassification).toBe("public");
      });

      it("should default to internal for unclassified URIs", async () => {
        const result = await assessor.assess(
          createContext("resource://api/users/list") as AssessmentContext,
        );

        expect(result.results[0].dataClassification).toBe("internal");
      });
    });
  });

  describe("PromptAssessor Enrichment", () => {
    let assessor: PromptAssessor;

    beforeEach(() => {
      assessor = new PromptAssessor(createConfig());
    });

    describe("promptTemplate analysis", () => {
      const createContext = (
        promptTemplate: string,
        promptArgs?: Array<{
          name: string;
          description?: string;
          required?: boolean;
        }>,
      ): Partial<AssessmentContext> => ({
        prompts: [
          {
            name: "test-prompt",
            description: promptTemplate,
            arguments: promptArgs,
          },
        ],
      });

      it("should detect parameterized template type when arguments exist", async () => {
        const result = await assessor.assess(
          createContext("Process the following request.", [
            { name: "query", required: true },
          ]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate).toBeDefined();
        expect(result.results[0].promptTemplate?.templateType).toBe(
          "parameterized",
        );
      });

      it("should detect format_string template type with placeholders", async () => {
        const result = await assessor.assess(
          createContext("Process {input} and return {output}", [
            { name: "input", required: true },
          ]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.templateType).toBe(
          "format_string",
        );
      });

      it("should extract variables from prompt arguments", async () => {
        const result = await assessor.assess(
          createContext("Process the following: {input}", [
            { name: "input", required: true },
            { name: "format", required: false },
          ]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.variables).toContain("input");
        expect(result.results[0].promptTemplate?.variables).toContain("format");
      });

      it("should mark templates with required args as validated", async () => {
        const result = await assessor.assess(
          createContext("Process request.", [
            { name: "query", required: true },
          ]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.validated).toBe(true);
      });

      it("should mark templates with type hints as validated", async () => {
        const result = await assessor.assess(
          createContext("Process request.", [
            { name: "query", description: "type: string" },
          ]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.validated).toBe(true);
      });
    });

    describe("dynamicContent analysis", () => {
      const createContext = (
        promptDescription: string,
      ): Partial<AssessmentContext> => ({
        prompts: [
          {
            name: "test-prompt",
            description: promptDescription,
          },
        ],
      });

      it("should detect interpolation in dynamic prompts", async () => {
        const result = await assessor.assess(
          createContext(
            "Process {input} and return {output}",
          ) as AssessmentContext,
        );

        expect(result.results[0].dynamicContent).toBeDefined();
        expect(result.results[0].dynamicContent?.hasInterpolation).toBe(true);
      });

      it("should detect template literal syntax", async () => {
        const result = await assessor.assess(
          createContext("Process ${userInput} safely") as AssessmentContext,
        );

        expect(result.results[0].dynamicContent?.hasInterpolation).toBe(true);
      });

      it("should not flag static content as interpolated", async () => {
        const result = await assessor.assess(
          createContext("This is a static prompt.") as AssessmentContext,
        );

        expect(result.results[0].dynamicContent?.hasInterpolation).toBe(false);
      });
    });
  });

  describe("PortabilityAssessor Enrichment", () => {
    let assessor: PortabilityAssessor;

    beforeEach(() => {
      assessor = new PortabilityAssessor(createConfig());
    });

    describe("shellCommands detection", () => {
      const createContext = (
        sourceCode: string,
      ): Partial<AssessmentContext> => ({
        tools: [
          {
            name: "test-tool",
            description: "Test",
            inputSchema: { type: "object" as const },
          },
        ],
        sourceCodeFiles: new Map([["test.ts", sourceCode]]),
        config: { ...createConfig(), enableSourceCodeAnalysis: true },
      });

      it("should detect grep commands", async () => {
        const result = await assessor.assess(
          createContext('exec("grep -r pattern .")') as AssessmentContext,
        );

        expect(result.shellCommands).toBeDefined();
        const grepCmd = result.shellCommands?.find((c) => c.command === "grep");
        expect(grepCmd).toBeDefined();
        expect(grepCmd?.isPortable).toBe(false);
      });

      it("should detect curl commands", async () => {
        const result = await assessor.assess(
          createContext('run("curl https://example.com")') as AssessmentContext,
        );

        expect(result.shellCommands).toBeDefined();
        const curlCmd = result.shellCommands?.find((c) => c.command === "curl");
        expect(curlCmd).toBeDefined();
        expect(curlCmd?.isPortable).toBe(false);
      });

      it("should suggest alternatives for non-portable commands", async () => {
        const result = await assessor.assess(
          createContext('exec("rm -rf temp/")') as AssessmentContext,
        );

        const rmCmd = result.shellCommands?.find((c) => c.command === "rm -rf");
        expect(rmCmd?.alternativeCommand).toBeDefined();
      });

      it("should return empty array when no shell commands found", async () => {
        const result = await assessor.assess(
          createContext("const x = 1 + 2;") as AssessmentContext,
        );

        expect(result.shellCommands).toEqual([]);
      });
    });

    describe("platformCoverage calculation", () => {
      // Access private method through type assertion for testing
      const analyzePlatformCoverage = (
        assessor: PortabilityAssessor,
        issues: PortabilityIssue[],
      ) => {
        return (
          assessor as unknown as {
            analyzePlatformCoverage: (issues: PortabilityIssue[]) => {
              supported: "all" | "windows" | "macos" | "linux";
              missing: string[];
            };
          }
        ).analyzePlatformCoverage(issues);
      };

      it("should report all platforms when no issues", () => {
        const result = analyzePlatformCoverage(assessor, []);

        expect(result.supported).toBe("all");
        expect(result.missing).toEqual([]);
      });

      it("should detect Windows-only code", () => {
        const issues: PortabilityIssue[] = [
          {
            type: "absolute_path",
            matchedText: "C:\\Users\\test",
            filePath: "test.ts",
            lineNumber: 1,
            severity: "MEDIUM",
            recommendation: "Use path.join() for cross-platform paths",
          },
        ];

        const result = analyzePlatformCoverage(assessor, issues);

        expect(result.supported).toBe("windows");
        expect(result.missing).toContain("macos");
        expect(result.missing).toContain("linux");
      });

      it("should detect Unix-only code", () => {
        const issues: PortabilityIssue[] = [
          {
            type: "absolute_path",
            matchedText: "/usr/local/bin",
            filePath: "test.ts",
            lineNumber: 1,
            severity: "MEDIUM",
            recommendation: "Use path.join() for cross-platform paths",
          },
        ];

        const result = analyzePlatformCoverage(assessor, issues);

        expect(result.supported).toBe("linux");
        expect(result.missing).toContain("windows");
      });

      it("should detect macOS-specific code", () => {
        const issues: PortabilityIssue[] = [
          {
            type: "platform_specific",
            matchedText: "process.platform === 'darwin'",
            filePath: "test.ts",
            lineNumber: 1,
            severity: "MEDIUM",
            recommendation: "Add fallbacks for other platforms",
          },
        ];

        const result = analyzePlatformCoverage(assessor, issues);

        expect(result.supported).toBe("macos");
        expect(result.missing).toContain("windows");
        expect(result.missing).toContain("linux");
      });

      it("should detect Linux-specific code", () => {
        const issues: PortabilityIssue[] = [
          {
            type: "platform_specific",
            matchedText: "platform === 'linux'",
            filePath: "test.ts",
            lineNumber: 1,
            severity: "MEDIUM",
            recommendation: "Add fallbacks for other platforms",
          },
        ];

        const result = analyzePlatformCoverage(assessor, issues);

        expect(result.supported).toBe("linux");
        expect(result.missing).toContain("windows");
        expect(result.missing).toContain("macos");
      });
    });
  });
});
