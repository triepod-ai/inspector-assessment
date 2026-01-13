import { ProhibitedLibrariesAssessor } from "./ProhibitedLibrariesAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockSourceCodeFiles,
  createMockPackageJsonWithProhibited,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("ProhibitedLibrariesAssessor", () => {
  let assessor: ProhibitedLibrariesAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      enableSourceCodeAnalysis: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        prohibitedLibraries: true,
      },
    });
    assessor = new ProhibitedLibrariesAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should pass with no prohibited libraries", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "test",
        version: "1.0.0",
        dependencies: {
          express: "^4.18.0",
          axios: "^1.0.0",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.matches.length).toBe(0);
      expect(result.hasFinancialLibraries).toBe(false);
      expect(result.hasMediaLibraries).toBe(false);
    });

    it("should fail when Stripe is detected", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.hasFinancialLibraries).toBe(true);
      expect(result.matches).toContainEqual(
        expect.objectContaining({
          name: "stripe",
          category: "payments",
          severity: "BLOCKING",
        }),
      );
    });

    it("should fail when PayPal SDK is detected", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited([
        "@paypal/checkout-server-sdk",
      ]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.hasFinancialLibraries).toBe(true);
    });

    it("should fail when Plaid is detected", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited(["plaid"]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.matches).toContainEqual(
        expect.objectContaining({
          name: "plaid",
        }),
      );
    });

    it("should detect media libraries - Sharp", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited(["sharp"]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasMediaLibraries).toBe(true);
      expect(result.matches).toContainEqual(
        expect.objectContaining({
          name: "sharp",
          category: "media",
        }),
      );
    });

    it("should detect media libraries - FFmpeg", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited([
        "fluent-ffmpeg",
      ]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasMediaLibraries).toBe(true);
    });

    it("should detect media libraries - jimp", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited(["jimp"]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasMediaLibraries).toBe(true);
    });

    it("should scan Python requirements.txt", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "requirements.txt": `
flask==2.0.0
stripe==5.0.0
requests==2.28.0
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasFinancialLibraries).toBe(true);
      expect(result.matches).toContainEqual(
        expect.objectContaining({
          name: "stripe",
          location: "requirements.txt",
        }),
      );
    });

    it("should scan source code imports for Python", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.py": `
import stripe
from PIL import Image

def process_payment():
    stripe.api_key = "sk_test_123"
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasFinancialLibraries).toBe(true);
      expect(result.hasMediaLibraries).toBe(true);
    });

    it("should scan source code imports for JavaScript/TypeScript", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.ts": `
import Stripe from 'stripe';
import sharp from 'sharp';

const stripe = new Stripe('sk_test_123');
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasFinancialLibraries).toBe(true);
      expect(result.hasMediaLibraries).toBe(true);
    });

    it("should deduplicate matches by library name", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.ts": `
import Stripe from 'stripe';
const stripe = new Stripe('key');
`,
        "src/checkout.ts": `
import Stripe from 'stripe';
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - stripe should only appear once in matches
      const stripeMatches = result.matches.filter((m) => m.name === "stripe");
      expect(stripeMatches.length).toBe(1);
    });

    it("should skip test files", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.test.ts": `
import Stripe from 'stripe';
// This is a test file
`,
        "__tests__/payment.spec.ts": `
import Stripe from 'stripe';
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - test files should be skipped
      expect(result.matches.length).toBe(0);
    });

    it("should skip node_modules", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "node_modules/some-package/index.js": `
const stripe = require('stripe');
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.matches.length).toBe(0);
    });

    it("should include policy reference in recommendations", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContainEqual(
        expect.stringContaining("Policy #28"),
      );
    });

    it("should report scanned files count", async () => {
      // Arrange
      mockContext.packageJson = {
        name: "test",
        version: "1.0.0",
        dependencies: {},
      };
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": "const x = 1;",
        "src/utils.ts": "const y = 2;",
        "requirements.txt": "flask==2.0.0",
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.scannedFiles.length).toBeGreaterThan(0);
    });

    it("should detect Square payment SDK", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited(["square"]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasFinancialLibraries).toBe(true);
    });

    it("should detect Braintree", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited([
        "braintree",
      ]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasFinancialLibraries).toBe(true);
    });

    it("should detect OpenCV (cv2)", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/vision.py": `
import cv2
import numpy as np

img = cv2.imread('image.jpg')
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.hasMediaLibraries).toBe(true);
    });

    it("should generate appropriate severity levels", async () => {
      // Arrange
      mockContext.packageJson = createMockPackageJsonWithProhibited([
        "stripe",
        "sharp",
      ]);

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - financial should be BLOCKING, media should be HIGH or MEDIUM
      const stripeMatch = result.matches.find((m) => m.name === "stripe");
      expect(stripeMatch?.severity).toBe("BLOCKING");
    });
  });

  // Issue #63: Dependency Usage Analysis Tests
  describe("Dependency Usage Analysis (Issue #63)", () => {
    it("should mark package.json dependency as UNUSED when not imported", async () => {
      // Arrange - stripe in package.json but not imported in source
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": `
console.log('Hello World');
export const main = () => {};
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const stripeMatch = result.matches.find((m) => m.name === "stripe");
      expect(stripeMatch?.usageStatus).toBe("UNUSED");
      expect(stripeMatch?.importCount).toBe(0);
      expect(stripeMatch?.importFiles).toEqual([]);
    });

    it("should mark package.json dependency as ACTIVE when imported (ES6)", async () => {
      // Arrange - stripe in package.json AND imported in source
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.ts": `
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_KEY);
export default stripe;
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const stripeMatch = result.matches.find((m) => m.name === "stripe");
      expect(stripeMatch?.usageStatus).toBe("ACTIVE");
      expect(stripeMatch?.importCount).toBeGreaterThanOrEqual(1);
      expect(stripeMatch?.importFiles).toContain("src/payment.ts");
    });

    it("should mark package.json dependency as ACTIVE when imported (CommonJS)", async () => {
      // Arrange - stripe imported via require()
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.js": `
const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_KEY);
module.exports = stripe;
`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const stripeMatch = result.matches.find((m) => m.name === "stripe");
      expect(stripeMatch?.usageStatus).toBe("ACTIVE");
      expect(stripeMatch?.importCount).toBeGreaterThanOrEqual(1);
    });

    it("should return NEED_MORE_INFO instead of FAIL for UNUSED BLOCKING libraries", async () => {
      // Arrange - stripe in package.json but not used
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": `console.log('no stripe here');`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - UNUSED BLOCKING should be NEED_MORE_INFO, not FAIL
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.matches[0].usageStatus).toBe("UNUSED");
    });

    it("should return FAIL for ACTIVE BLOCKING libraries", async () => {
      // Arrange - stripe in package.json AND imported
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.ts": `import Stripe from 'stripe';`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - ACTIVE BLOCKING should be FAIL
      expect(result.status).toBe("FAIL");
      expect(result.matches[0].usageStatus).toBe("ACTIVE");
    });

    it("should recommend npm uninstall for UNUSED dependencies", async () => {
      // Arrange - openai in package.json but not imported (simulated)
      mockContext.packageJson = {
        name: "test",
        version: "1.0.0",
        dependencies: {
          ethers: "^5.0.0", // HIGH severity, not BLOCKING
        },
      };
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": `console.log('no ethers here');`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContainEqual(
        expect.stringContaining("npm uninstall ethers"),
      );
      expect(result.recommendations).toContainEqual(
        expect.stringContaining("not imported"),
      );
    });

    it("should return UNKNOWN usage status when source code analysis is disabled", async () => {
      // Arrange - disable source code analysis
      const configWithoutSource = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        enableSourceCodeAnalysis: false, // Disabled
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          prohibitedLibraries: true,
        },
      });
      const assessorWithoutSource = new ProhibitedLibrariesAssessor(
        configWithoutSource,
      );
      const contextWithoutSource = createMockAssessmentContext({
        config: configWithoutSource,
      });
      contextWithoutSource.packageJson = createMockPackageJsonWithProhibited([
        "stripe",
      ]);

      // Act
      const result = await assessorWithoutSource.assess(contextWithoutSource);

      // Assert - should be UNKNOWN since we can't check source
      expect(result.matches[0].usageStatus).toBe("UNKNOWN");
      // UNKNOWN is treated as potentially active, so FAIL
      expect(result.status).toBe("FAIL");
    });

    it("should track multiple import files for the same dependency", async () => {
      // Arrange - stripe imported in multiple files
      mockContext.packageJson = createMockPackageJsonWithProhibited(["stripe"]);
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/payment.ts": `import Stripe from 'stripe';`,
        "src/checkout.ts": `import { Stripe } from 'stripe';`,
        "src/refund.ts": `const stripe = require('stripe');`,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const stripeMatch = result.matches.find((m) => m.name === "stripe");
      expect(stripeMatch?.usageStatus).toBe("ACTIVE");
      expect(stripeMatch?.importCount).toBeGreaterThanOrEqual(3);
      expect(stripeMatch?.importFiles?.length).toBeGreaterThanOrEqual(3);
    });
  });

  // Issue #154: Skipped Assessment Tests
  describe("Skipped Assessment (Issue #154)", () => {
    it("should return NEED_MORE_INFO with skipped=true when no files to scan", async () => {
      // Arrange - context with no packageJson and no sourceCodeFiles
      mockContext.packageJson = undefined;
      mockContext.sourceCodeFiles = undefined;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.skipped).toBe(true);
      expect(result.skipReason).toContain("No package.json or source files");
      expect(result.scannedFiles).toHaveLength(0);
      expect(result.explanation).toContain("skipped");
    });

    it("should return NEED_MORE_INFO when sourceCodeFiles is empty Map", async () => {
      // Arrange - empty Map (what happens when source path not found)
      mockContext.packageJson = undefined;
      mockContext.sourceCodeFiles = new Map();

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.skipped).toBe(true);
    });

    it("should proceed normally when only packageJson is available", async () => {
      // Arrange - packageJson but no sourceCodeFiles
      mockContext.packageJson = {
        name: "test",
        version: "1.0.0",
        dependencies: {},
      };
      mockContext.sourceCodeFiles = undefined;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - should NOT be skipped since packageJson is available
      expect(result.skipped).toBeUndefined();
      expect(result.scannedFiles).toContain("package.json");
      expect(result.status).toBe("PASS");
    });

    it("should proceed normally when only sourceCodeFiles is available", async () => {
      // Arrange - sourceCodeFiles but no packageJson
      mockContext.packageJson = undefined;
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": "import express from 'express';",
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - should NOT be skipped since sourceCodeFiles is available
      expect(result.skipped).toBeUndefined();
      expect(result.scannedFiles.length).toBeGreaterThan(0);
    });

    it("should include actionable recommendations when skipped", async () => {
      // Arrange
      mockContext.packageJson = undefined;
      mockContext.sourceCodeFiles = undefined;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContainEqual(
        expect.stringContaining("--source"),
      );
    });

    it("should return 0 matches when skipped", async () => {
      // Arrange
      mockContext.packageJson = undefined;
      mockContext.sourceCodeFiles = undefined;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.matches).toHaveLength(0);
      expect(result.hasFinancialLibraries).toBe(false);
      expect(result.hasMediaLibraries).toBe(false);
    });

    it("should skip when sourceCodeFiles exist but enableSourceCodeAnalysis is false and no packageJson", async () => {
      // Arrange - source files exist but analysis disabled + no packageJson = nothing to scan
      const configNoSource = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        enableSourceCodeAnalysis: false,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          prohibitedLibraries: true,
        },
      });
      const assessorNoSource = new ProhibitedLibrariesAssessor(configNoSource);
      const contextNoSource = createMockAssessmentContext({
        config: configNoSource,
      });
      contextNoSource.packageJson = undefined;
      contextNoSource.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": "import Stripe from 'stripe';",
      });

      // Act
      const result = await assessorNoSource.assess(contextNoSource);

      // Assert - SHOULD skip because source analysis is disabled and no packageJson
      // The source files won't be scanned anyway (gated by enableSourceCodeAnalysis at line 115)
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.skipped).toBe(true);
    });

    it("should NOT skip when packageJson exists even if enableSourceCodeAnalysis is false", async () => {
      // Arrange - packageJson available, source analysis disabled
      const configNoSource = createMockAssessmentConfig({
        enableExtendedAssessment: true,
        enableSourceCodeAnalysis: false,
        assessmentCategories: {
          functionality: true,
          security: true,
          documentation: true,
          errorHandling: true,
          usability: true,
          prohibitedLibraries: true,
        },
      });
      const assessorNoSource = new ProhibitedLibrariesAssessor(configNoSource);
      const contextNoSource = createMockAssessmentContext({
        config: configNoSource,
      });
      contextNoSource.packageJson = {
        name: "test",
        version: "1.0.0",
        dependencies: {},
      };

      // Act
      const result = await assessorNoSource.assess(contextNoSource);

      // Assert - should NOT be skipped since packageJson is available
      expect(result.skipped).toBeUndefined();
      expect(result.scannedFiles).toContain("package.json");
      expect(result.status).toBe("PASS");
    });
  });
});
