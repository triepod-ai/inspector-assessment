import { PrivacyComplianceAssessor } from "./PrivacyComplianceAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("PrivacyComplianceAssessor", () => {
  let assessor: PrivacyComplianceAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new PrivacyComplianceAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess privacy compliance with clean data handling", async () => {
      // Arrange
      const tool = createMockTool({
        name: "privacy-compliant-tool",
        description: "A tool that handles data with proper privacy controls",
      });
      mockContext.tools = [tool];
      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(
          createMockCallToolResponse("Data processed with consent", false),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.category).toBe("privacy");
      expect(result.status).toBe("PASS");
      expect(result.score).toBeGreaterThan(80);
      expect(result.piiDetection.found).toBe(false);
      expect(result.gdprCompliance.score).toBeGreaterThan(80);
      expect(result.ccpaCompliance.score).toBeGreaterThan(80);
    });

    it("should detect PII in tool responses", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        // Simulate tool responses containing PII
        const responses = [
          "User email: john.doe@example.com",
          "Phone: +1-555-123-4567",
          "SSN: 123-45-6789",
          "Credit Card: 4532-1234-5678-9012",
          "IP Address: 192.168.1.100",
        ];

        const randomResponse =
          responses[Math.floor(Math.random() * responses.length)];
        return createMockCallToolResponse(randomResponse, false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.piiDetection.found).toBe(true);
      expect(result.piiDetection.types).toContain("email");
      expect(result.piiDetection.types).toContain("phone");
      expect(result.piiDetection.types).toContain("ssn");
      expect(
        result.piiDetection.classification.sensitive.length,
      ).toBeGreaterThan(0);
      expect(result.criticalFindings).toContain(
        "PII detected in tool responses",
      );
      expect(result.status).toBe("FAIL");
    });

    it("should assess GDPR compliance mechanisms", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "test-server",
        privacyPolicy: {
          consentMechanism: "explicit",
          dataPortability: true,
          rightToErasure: true,
          privacyByDesign: true,
          dataMinimization: true,
          legalBasis: "consent",
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.gdprCompliance.consentMechanism).toBe(true);
      expect(result.gdprCompliance.dataPortability).toBe(true);
      expect(result.gdprCompliance.rightToErasure).toBe(true);
      expect(result.gdprCompliance.privacyByDesign).toBe(true);
      expect(result.gdprCompliance.dataMinimization).toBe(true);
      expect(result.gdprCompliance.score).toBeGreaterThan(90);
    });

    it("should assess CCPA compliance mechanisms", async () => {
      // Arrange
      mockContext.serverInfo = {
        name: "test-server",
        privacyPolicy: {
          optOutMechanism: true,
          dataDisclosure: true,
          nonDiscrimination: true,
          verifiableRequests: true,
          californiaResident: true,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.ccpaCompliance.optOutMechanism).toBe(true);
      expect(result.ccpaCompliance.dataDisclosure).toBe(true);
      expect(result.ccpaCompliance.nonDiscrimination).toBe(true);
      expect(result.ccpaCompliance.verifiableRequests).toBe(true);
      expect(result.ccpaCompliance.score).toBeGreaterThan(90);
    });

    it("should detect data retention policy violations", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return createMockCallToolResponse(
          "Storing user data indefinitely",
          false,
        );
      });

      mockContext.serverInfo = {
        name: "test-server",
        dataRetention: {
          policyExists: false,
          automaticDeletion: false,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.dataRetention.policyExists).toBe(false);
      expect(result.dataRetention.automaticDeletion).toBe(false);
      expect(result.criticalFindings).toContain("No data retention policy");
      expect(result.criticalFindings).toContain(
        "Indefinite data storage detected",
      );
      expect(result.status).toBe("FAIL");
    });

    it("should assess encryption implementation", async () => {
      // Arrange
      mockContext.serverInfo = {
        encryption: {
          atRest: true,
          inTransit: true,
          keyManagement: true,
          algorithms: ["AES-256", "RSA-2048", "SHA-256"],
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.encryption.atRest).toBe(true);
      expect(result.encryption.inTransit).toBe(true);
      expect(result.encryption.keyManagement).toBe(true);
      expect(result.encryption.algorithms).toContain("AES-256");
      expect(result.score).toBeGreaterThan(85);
    });

    it("should detect weak encryption practices", async () => {
      // Arrange
      mockContext.serverInfo = {
        encryption: {
          atRest: false,
          inTransit: false,
          keyManagement: false,
          algorithms: ["MD5", "DES", "RC4"], // Weak algorithms
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.encryption.atRest).toBe(false);
      expect(result.encryption.inTransit).toBe(false);
      expect(result.encryption.keyManagement).toBe(false);
      expect(result.criticalFindings).toContain("Weak encryption algorithms");
      expect(result.criticalFindings).toContain("Data not encrypted at rest");
      expect(result.criticalFindings).toContain(
        "Data not encrypted in transit",
      );
      expect(result.status).toBe("FAIL");
    });

    it("should classify PII sensitivity levels", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        const piiExamples = [
          "SSN: 123-45-6789", // Sensitive
          "Email: user@example.com", // Quasi-identifier
          "Name: John Smith", // Quasi-identifier
          "Age: 25", // Quasi-identifier
          "City: New York", // Public
          "Zipcode: 10001", // Quasi-identifier
        ];

        const randomPII =
          piiExamples[Math.floor(Math.random() * piiExamples.length)];
        return createMockCallToolResponse(randomPII, false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(
        result.piiDetection.classification.sensitive.length,
      ).toBeGreaterThan(0);
      expect(
        result.piiDetection.classification.quasiIdentifiers.length,
      ).toBeGreaterThan(0);
      expect(result.piiDetection.classification.public.length).toBeGreaterThan(
        0,
      );
      expect(result.criticalFindings).toContain("Sensitive PII detected");
    });

    it("should detect cross-border data transfer issues", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        return createMockCallToolResponse(
          "Transferring data to server in non-adequate country",
          false,
        );
      });

      mockContext.serverInfo = {
        dataTransfer: {
          crossBorder: true,
          adequacyDecision: false,
          safeguards: false,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain(
        "Cross-border data transfer violations",
      );
      expect(result.gdprCompliance.score).toBeLessThan(60);
      expect(result.status).toBe("FAIL");
    });

    it("should assess consent granularity", async () => {
      // Arrange
      mockContext.serverInfo = {
        consent: {
          granular: true,
          purpose_specific: true,
          informed: true,
          freely_given: true,
          unambiguous: true,
          withdrawable: true,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.gdprCompliance.consentMechanism).toBe(true);
      expect(result.gdprCompliance.score).toBeGreaterThan(85);
      expect(result.recommendations).toContain("Maintain granular consent");
    });

    it("should detect privacy policy adequacy", async () => {
      // Arrange
      mockContext.privacyPolicy = {
        exists: true,
        lastUpdated: "2024-01-01",
        language: "plain",
        completeness: 90,
        covers: [
          "data collection",
          "data usage",
          "data sharing",
          "user rights",
          "contact information",
        ],
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).not.toContain("Missing privacy policy");
      expect(result.score).toBeGreaterThan(75);
    });

    it("should assess children data protection (COPPA)", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (params.age && parseInt(params.age) < 13) {
          return createMockCallToolResponse("Parental consent required", false);
        }
        return createMockCallToolResponse("Standard processing", false);
      });

      mockContext.serverInfo = {
        coppaCompliance: {
          parentalConsent: true,
          ageVerification: true,
          dataMinimization: true,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).not.toContain("COPPA violations");
      expect(result.recommendations).toContain("Maintain COPPA compliance");
    });

    it("should detect anonymization and pseudonymization", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        const responses = [
          "User ID: user_12345 (anonymized)",
          "Hash: 8d7b7c8e3f4a9b2c (pseudonymized)",
          "Raw email: john.doe@example.com (not anonymized)",
        ];

        const randomResponse =
          responses[Math.floor(Math.random() * responses.length)];
        return createMockCallToolResponse(randomResponse, false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(
        result.piiDetection.types.some(
          (type) =>
            type.includes("anonymized") || type.includes("pseudonymized"),
        ),
      ).toBe(true);

      if (result.piiDetection.types.includes("raw_email")) {
        expect(result.criticalFindings).toContain(
          "Non-anonymized PII detected",
        );
      }
    });

    it("should assess data subject rights implementation", async () => {
      // Arrange
      mockContext.serverInfo = {
        dataSubjectRights: {
          access: true,
          rectification: true,
          erasure: true,
          portability: true,
          restriction: true,
          objection: true,
          automated_decision_making: false,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.gdprCompliance.dataPortability).toBe(true);
      expect(result.gdprCompliance.rightToErasure).toBe(true);
      expect(result.recommendations).toContain(
        "All data subject rights implemented",
      );
    });

    it("should calculate comprehensive privacy score", async () => {
      // Arrange - mixed privacy compliance
      mockContext.serverInfo = {
        privacyPolicy: { exists: true, completeness: 70 },
        encryption: { atRest: true, inTransit: false },
        consent: { granular: true, withdrawable: false },
        dataRetention: { policyExists: false },
      };

      mockContext.callTool = jest.fn().mockImplementation(() => {
        return createMockCallToolResponse(
          "Email: user@example.com stored",
          false,
        );
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.score).toBeGreaterThan(40);
      expect(result.score).toBeLessThan(70);
      expect(result.status).toBe("NEED_MORE_INFO");
      expect(result.piiDetection.found).toBe(true);
    });

    it("should provide privacy enhancement recommendations", async () => {
      // Arrange
      mockContext.serverInfo = {
        encryption: { atRest: false },
        dataRetention: { policyExists: false },
        consent: { granular: false },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations).toContain("Implement encryption at rest");
      expect(result.recommendations).toContain("Create data retention policy");
      expect(result.recommendations).toContain("Implement granular consent");
      expect(result.recommendations).toContain(
        "Regular privacy impact assessments",
      );
      expect(result.recommendations.length).toBeGreaterThan(3);
    });

    it("should handle tools with no privacy implications", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({
          name: "math-calculator",
          description:
            "Performs mathematical calculations with no data storage",
        }),
      ];

      mockContext.callTool = jest
        .fn()
        .mockResolvedValue(createMockCallToolResponse("2 + 2 = 4", false));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.piiDetection.found).toBe(false);
      expect(result.status).toBe("PASS");
      expect(result.score).toBeGreaterThan(90);
      expect(result.explanation).toContain("No privacy risks detected");
    });
  });

  describe("edge cases", () => {
    it("should handle missing privacy policy", async () => {
      // Arrange
      mockContext.privacyPolicy = undefined;
      mockContext.serverInfo = {};

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain("No privacy policy found");
      expect(result.status).toBe("FAIL");
      expect(result.score).toBeLessThan(50);
    });

    it("should detect PII in error messages", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation(() => {
        throw new Error(
          "Database error for user john.doe@example.com: Connection failed",
        );
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.piiDetection.found).toBe(true);
      expect(result.piiDetection.locations).toContain("error messages");
      expect(result.criticalFindings).toContain("PII in error messages");
    });

    it("should handle malformed privacy configurations", async () => {
      // Arrange
      mockContext.serverInfo = {
        encryption: "invalid_config",
        consent: null,
        dataRetention: undefined,
      } as any;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.criticalFindings).toContain(
        "Malformed privacy configuration",
      );
    });

    it("should detect international privacy law conflicts", async () => {
      // Arrange
      mockContext.serverInfo = {
        jurisdiction: ["US", "EU", "APAC"],
        dataLocalization: {
          required: true,
          implemented: false,
        },
      };

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.criticalFindings).toContain("Privacy law conflicts");
      expect(result.criticalFindings).toContain(
        "Data localization requirements",
      );
    });
  });
});
