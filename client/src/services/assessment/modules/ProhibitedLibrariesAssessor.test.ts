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
});
