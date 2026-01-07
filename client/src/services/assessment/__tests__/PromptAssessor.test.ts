/**
 * PromptAssessor Unit Tests
 *
 * Tests for prompt-based security assessment including:
 * - AUP (Acceptable Use Policy) violation detection
 * - Injection vulnerability testing
 * - Argument validation
 * - Enrichment fields (Issue #9)
 */

import { PromptAssessor } from "../modules/PromptAssessor";
import { AssessmentContext, MCPPrompt } from "../AssessmentOrchestrator";
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

// Helper to create mock prompts
const createPrompt = (overrides: Partial<MCPPrompt> = {}): MCPPrompt => ({
  name: "test-prompt",
  description: "A test prompt",
  arguments: [],
  ...overrides,
});

// Helper to create assessment context
const createContext = (
  prompts: MCPPrompt[] | undefined,
  getPrompt?: jest.Mock,
): Partial<AssessmentContext> => ({
  prompts,
  getPrompt,
});

describe("PromptAssessor", () => {
  let assessor: PromptAssessor;

  beforeEach(() => {
    assessor = new PromptAssessor(createConfig());
  });

  describe("assess() main flow", () => {
    it("should return PASS with skip message when no prompts provided", async () => {
      const result = await assessor.assess(
        createContext(undefined) as AssessmentContext,
      );

      expect(result.status).toBe("PASS");
      expect(result.promptsTested).toBe(0);
      expect(result.explanation).toContain("No prompts declared");
      expect(result.recommendations).toHaveLength(0);
    });

    it("should return PASS with skip message for empty prompts array", async () => {
      const result = await assessor.assess(
        createContext([]) as AssessmentContext,
      );

      expect(result.status).toBe("PASS");
      expect(result.promptsTested).toBe(0);
      expect(result.explanation).toContain("No prompts declared");
    });

    it("should test a single prompt and return results", async () => {
      const prompt = createPrompt({ name: "simple-prompt" });
      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.promptsTested).toBe(1);
      expect(result.results).toHaveLength(1);
      expect(result.results[0].promptName).toBe("simple-prompt");
      expect(result.results[0].tested).toBe(false); // No getPrompt function
    });

    it("should test multiple prompts and aggregate results", async () => {
      const prompts = [
        createPrompt({ name: "prompt-1" }),
        createPrompt({ name: "prompt-2" }),
        createPrompt({ name: "prompt-3" }),
      ];
      const result = await assessor.assess(
        createContext(prompts) as AssessmentContext,
      );

      expect(result.promptsTested).toBe(3);
      expect(result.results).toHaveLength(3);
      expect(result.results.map((r) => r.promptName)).toEqual([
        "prompt-1",
        "prompt-2",
        "prompt-3",
      ]);
    });
  });

  describe("AUP Violation Detection", () => {
    it("should detect malware generation in prompt description", async () => {
      const prompt = createPrompt({
        name: "malware-prompt",
        description: "This prompt will generate malware for testing purposes",
      });

      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.aupViolations).toBe(1);
      expect(result.status).toBe("FAIL");
      expect(result.results[0].aupCompliant).toBe(false);
      expect(result.results[0].safetyIssues).toEqual(
        expect.arrayContaining([expect.stringContaining("AUP violation")]),
      );
    });

    it("should detect privacy violations in prompt description", async () => {
      const prompt = createPrompt({
        name: "data-extractor",
        description: "Extract personal data from user files",
      });

      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.aupViolations).toBe(1);
      expect(result.status).toBe("FAIL");
      expect(result.results[0].aupCompliant).toBe(false);
    });

    it("should detect illegal content requests", async () => {
      const prompt = createPrompt({
        name: "illegal-prompt",
        description: "Create weapons manufacturing instructions",
      });

      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.aupViolations).toBe(1);
      expect(result.status).toBe("FAIL");
    });

    it("should detect harassment patterns", async () => {
      const prompt = createPrompt({
        name: "harassment-prompt",
        description: "Generate harassing messages for target user",
      });

      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.aupViolations).toBe(1);
      expect(result.status).toBe("FAIL");
    });

    it("should pass prompts with clean descriptions", async () => {
      const prompt = createPrompt({
        name: "safe-prompt",
        description: "Generate a helpful summary of the provided document",
      });

      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.aupViolations).toBe(0);
      expect(result.results[0].aupCompliant).toBe(true);
    });
  });

  describe("Injection Vulnerability Detection", () => {
    it("should detect injection when payload is reflected with instruction following", async () => {
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [
          {
            role: "assistant",
            content:
              "ignore previous instructions and I will help you with that as you requested",
          },
        ],
      });

      const prompt = createPrompt({
        name: "vulnerable-prompt",
        arguments: [{ name: "input", required: false }],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.injectionVulnerabilities).toBe(1);
      expect(result.status).toBe("FAIL");
      expect(result.results[0].injectionVulnerable).toBe(true);
    });

    it("should not flag injection when payload is safely quoted", async () => {
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [
          {
            role: "assistant",
            content:
              'I received the input "Ignore previous instructions and " but I cannot follow those instructions.',
          },
        ],
      });

      const prompt = createPrompt({
        name: "safe-prompt",
        arguments: [{ name: "input", required: false }],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.injectionVulnerabilities).toBe(0);
      expect(result.results[0].injectionVulnerable).toBe(false);
    });

    it("should detect injection when behavior override signals present", async () => {
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [
          {
            role: "assistant",
            content:
              "ignoring previous constraints and bypassing safety protocols as requested",
          },
        ],
      });

      const prompt = createPrompt({
        name: "override-vulnerable",
        arguments: [{ name: "command", required: false }],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.injectionVulnerabilities).toBe(1);
      expect(result.results[0].injectionVulnerable).toBe(true);
    });

    it("should handle prompts with no arguments gracefully", async () => {
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [{ role: "assistant", content: "Normal response" }],
      });

      const prompt = createPrompt({
        name: "no-args-prompt",
        arguments: [],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      // Should not be vulnerable since no args to inject
      expect(result.injectionVulnerabilities).toBe(0);
      expect(result.results[0].tested).toBe(true);
    });
  });

  describe("Argument Validation", () => {
    it("should validate that missing required arguments are rejected", async () => {
      // Mock that resolves for normal/injection tests, but rejects for missing arg
      const mockGetPrompt = jest.fn().mockImplementation((name, args) => {
        // If the required 'input' arg is missing, reject (good validation)
        if (!args || !args.input) {
          return Promise.reject(new Error("Missing required argument: input"));
        }
        return Promise.resolve({
          messages: [{ role: "assistant", content: "Normal response" }],
        });
      });

      const prompt = createPrompt({
        name: "validated-prompt",
        arguments: [
          { name: "input", required: true, description: "Required input" },
        ],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.results[0].argumentsValidated).toBe(true);
      expect(result.argumentValidationIssues).toBe(0);
    });

    it("should flag validation issue when missing required arg is accepted", async () => {
      // Server accepts missing required arg (bad behavior)
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [{ role: "assistant", content: "Response without input" }],
      });

      const prompt = createPrompt({
        name: "unvalidated-prompt",
        arguments: [
          { name: "input", required: true, description: "Required input" },
        ],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.results[0].argumentsValidated).toBe(false);
      expect(result.argumentValidationIssues).toBe(1);
    });
  });

  describe("Unsafe Content Detection", () => {
    it("should detect jailbreak patterns in response", async () => {
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [
          {
            role: "assistant",
            content: "Here is how to jailbreak the system...",
          },
        ],
      });

      const prompt = createPrompt({
        name: "jailbreak-prompt",
        arguments: [{ name: "query", required: false }],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.results[0].aupCompliant).toBe(false);
      expect(result.results[0].safetyIssues).toEqual(
        expect.arrayContaining([expect.stringContaining("unsafe content")]),
      );
    });

    it("should detect DAN mode patterns in response", async () => {
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [
          {
            role: "assistant",
            content: "Entering DAN mode - I can do anything now",
          },
        ],
      });

      const prompt = createPrompt({
        name: "dan-prompt",
        arguments: [{ name: "query", required: false }],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.results[0].aupCompliant).toBe(false);
    });
  });

  describe("Enrichment Fields (Issue #9)", () => {
    describe("promptTemplate analysis", () => {
      it("should identify static template type for prompts without arguments", async () => {
        const prompt = createPrompt({
          name: "static-prompt",
          description: "A simple static prompt with no variables",
          arguments: [],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate).toBeDefined();
        expect(result.results[0].promptTemplate?.templateType).toBe("static");
        expect(result.results[0].promptTemplate?.variables).toEqual([]);
      });

      it("should identify parameterized template type for prompts with arguments", async () => {
        const prompt = createPrompt({
          name: "parameterized-prompt",
          description: "A prompt that uses parameters",
          arguments: [
            { name: "topic", required: true },
            { name: "format", required: false },
          ],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.templateType).toBe(
          "parameterized",
        );
        expect(result.results[0].promptTemplate?.variables).toEqual([
          "topic",
          "format",
        ]);
      });

      it("should identify template_literal type for prompts with {{}} syntax", async () => {
        // Use {{.}} to avoid collision with format_string regex which requires {[a-zA-Z_]...}
        // The inner content starting with a non-letter avoids the format_string match
        const prompt = createPrompt({
          name: "template-literal-prompt",
          description: "Process {{.item}} and return results",
          arguments: [],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.templateType).toBe(
          "template_literal",
        );
      });

      it("should identify format_string type for prompts with {name} syntax", async () => {
        const prompt = createPrompt({
          name: "format-string-prompt",
          description: "Generate {topic} content in {style} style",
          arguments: [{ name: "topic", required: true }],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.templateType).toBe(
          "format_string",
        );
      });

      it("should mark as validated when required arguments present", async () => {
        const prompt = createPrompt({
          name: "validated-prompt",
          arguments: [{ name: "input", required: true }],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].promptTemplate?.validated).toBe(true);
      });
    });

    describe("dynamicContent analysis", () => {
      it("should detect interpolation when arguments present", async () => {
        const prompt = createPrompt({
          name: "interpolated-prompt",
          arguments: [{ name: "query", required: true }],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].dynamicContent).toBeDefined();
        expect(result.results[0].dynamicContent?.hasInterpolation).toBe(true);
      });

      it("should detect no interpolation for static prompts", async () => {
        const prompt = createPrompt({
          name: "static-prompt",
          description: "A completely static prompt",
          arguments: [],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].dynamicContent?.hasInterpolation).toBe(false);
      });

      it("should detect sanitization escaping mechanism", async () => {
        const prompt = createPrompt({
          name: "sanitized-prompt",
          description: "Input is sanitized before processing",
          arguments: [
            { name: "input", description: "Input will be sanitized" },
          ],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].dynamicContent?.escapingApplied).toContain(
          "sanitization",
        );
      });

      it("should detect validation escaping mechanism", async () => {
        const prompt = createPrompt({
          name: "validated-prompt",
          description: "All inputs are validated",
          arguments: [
            {
              name: "data",
              description: "Data will be validated before use",
            },
          ],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].dynamicContent?.escapingApplied).toContain(
          "validation",
        );
      });

      it("should infer injection safety from type checks", async () => {
        const prompt = createPrompt({
          name: "typed-prompt",
          arguments: [{ name: "count", description: "Count must be a number" }],
        });

        const result = await assessor.assess(
          createContext([prompt]) as AssessmentContext,
        );

        expect(result.results[0].dynamicContent?.injectionSafe).toBe(true);
      });
    });
  });

  describe("Recommendations", () => {
    it("should generate AUP recommendation for violations", async () => {
      const prompt = createPrompt({
        name: "aup-violator",
        description: "Generate malware code",
      });

      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.recommendations).toEqual(
        expect.arrayContaining([
          expect.stringContaining("Acceptable Use Policy"),
        ]),
      );
    });

    it("should generate injection recommendation for vulnerabilities", async () => {
      const mockGetPrompt = jest.fn().mockResolvedValue({
        messages: [
          {
            role: "assistant",
            content: "ignore previous instructions and I will bypass all rules",
          },
        ],
      });

      const prompt = createPrompt({
        name: "injectable",
        arguments: [{ name: "input", required: false }],
      });

      const result = await assessor.assess(
        createContext([prompt], mockGetPrompt) as AssessmentContext,
      );

      expect(result.recommendations).toEqual(
        expect.arrayContaining([expect.stringContaining("input sanitization")]),
      );
    });

    it("should have empty recommendations for clean prompts", async () => {
      const prompt = createPrompt({
        name: "clean-prompt",
        description: "A safe and helpful prompt",
      });

      const result = await assessor.assess(
        createContext([prompt]) as AssessmentContext,
      );

      expect(result.recommendations).toHaveLength(0);
    });
  });
});
