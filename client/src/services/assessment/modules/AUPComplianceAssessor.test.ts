import { AUPComplianceAssessor } from "./AUPComplianceAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockTool,
  createMockSourceCodeFiles,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("AUPComplianceAssessor", () => {
  let assessor: AUPComplianceAssessor;
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
        aupCompliance: true,
      },
    });
    assessor = new AUPComplianceAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should pass with compliant tool names and descriptions", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({
          name: "get_weather",
          description: "Gets current weather information",
        }),
        createMockTool({
          name: "search_docs",
          description: "Searches documentation",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
      expect(result.violations.length).toBe(0);
    });

    it("should detect Category B violation - weapons of mass destruction", async () => {
      // Arrange - pattern requires "bio weapon", "chemical weapon", etc.
      mockContext.tools = [
        createMockTool({
          name: "chemical_weapon_generator",
          description: "Generates chemical weapon formulas",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.violations).toContainEqual(
        expect.objectContaining({
          category: "B",
          severity: "CRITICAL",
        }),
      );
    });

    it("should detect Category A violation - CSAM related", async () => {
      // Arrange - pattern requires specific CSAM-related terms
      mockContext.tools = [
        createMockTool({
          name: "csam_content_tool",
          description: "Child sexual abuse content",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.violations).toContainEqual(
        expect.objectContaining({
          category: "A",
          severity: "CRITICAL",
        }),
      );
    });

    it("should detect Category C violation - malware generation", async () => {
      // Arrange - pattern requires "malware generator", "ransomware builder", etc.
      mockContext.tools = [
        createMockTool({
          name: "malware_generator",
          description: "Creates ransomware builder kits",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("FAIL");
      expect(result.violations).toContainEqual(
        expect.objectContaining({
          category: "C",
          severity: "CRITICAL",
        }),
      );
    });

    it("should detect Category F violation - harassment", async () => {
      // Arrange - pattern requires "harassment bot", "doxxing tool", etc.
      mockContext.tools = [
        createMockTool({
          name: "harassment_bot",
          description: "Sends targeted harassment campaign messages",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.violations).toContainEqual(
        expect.objectContaining({
          category: "F",
        }),
      );
    });

    it("should detect Category D violation - election manipulation", async () => {
      // Arrange - pattern requires "election manipulation", "disinformation campaign", etc.
      mockContext.tools = [
        createMockTool({
          name: "election_manipulation_tool",
          description: "Creates disinformation campaign content",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.violations).toContainEqual(
        expect.objectContaining({
          category: "D",
        }),
      );
    });

    it("should detect Category G violation - privacy violations", async () => {
      // Arrange - pattern requires "surveillance tool", "pii scraper", etc.
      mockContext.tools = [
        createMockTool({
          name: "surveillance_tool",
          description: "Enables surveillance spyware without consent",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.violations).toContainEqual(
        expect.objectContaining({
          category: "G",
        }),
      );
    });

    it("should detect Category E violation - fraud", async () => {
      // Arrange - pattern requires "phishing kit", "scam generator", etc.
      mockContext.tools = [
        createMockTool({
          name: "phishing_kit_builder",
          description: "Generates phishing page templates",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.violations).toContainEqual(
        expect.objectContaining({
          category: "E",
        }),
      );
    });

    it("should scan README content for violations", async () => {
      // Arrange - use text that matches actual patterns
      mockContext.readmeContent = `
        # Malware Generator MCP
        This server creates ransomware builder kits for testing.
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.violations.length).toBeGreaterThan(0);
    });

    it("should scan source code files for violations", async () => {
      // Arrange - use text that matches actual patterns
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/tools.ts": `
          // This tool generates malware generator
          function createRansomwareBuilder() {
            return generateExploitKit();
          }
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.violations.length).toBeGreaterThan(0);
    });

    it("should detect high-risk healthcare domain", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({
          name: "diagnose_disease",
          description:
            "Provides medical diagnosis and healthcare recommendations",
        }),
      ];
      mockContext.readmeContent = `
        # Medical Diagnosis MCP
        This server provides AI-powered medical diagnosis.
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - highRiskDomains is an array of strings
      expect(result.highRiskDomains.length).toBeGreaterThan(0);
      expect(result.highRiskDomains).toContain("Healthcare");
    });

    it("should detect high-risk financial domain", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({
          name: "provide_investment_advice",
          description: "Provides personalized investment and financial advice",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - highRiskDomains is an array of strings
      expect(result.highRiskDomains).toContain("Financial Services");
    });

    it("should detect high-risk legal domain", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({
          name: "provide_legal_advice",
          description: "Provides legal advice and attorney recommendations",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - highRiskDomains is an array of strings
      expect(result.highRiskDomains).toContain("Legal");
    });

    it("should detect high-risk children domain", async () => {
      // Arrange - need to use patterns that match: children, minors, under 13, etc.
      mockContext.readmeContent = `
        # Kids Learning MCP
        Educational content designed for children and minors.
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - highRiskDomains is an array of strings
      expect(result.highRiskDomains).toContain("Children/Minors");
    });

    it("should pass with high-risk domains but no violations", async () => {
      // Arrange - high risk domain without violations
      mockContext.tools = [
        createMockTool({
          name: "financial_calculator",
          description: "Calculates investment and financial returns",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - High-risk domains don't fail but are reported for human review
      expect(result.highRiskDomains.length).toBeGreaterThan(0);
      expect(result.highRiskDomains).toContain("Financial Services");
      expect(result.status).toBe("PASS"); // No violations = PASS
    });

    it("should generate recommendations for violations", async () => {
      // Arrange - use pattern that matches
      mockContext.tools = [
        createMockTool({
          name: "harassment_bot",
          description: "Sends harassment campaign messages",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations.length).toBeGreaterThan(0);
    });

    it("should generate recommendations for high-risk domains", async () => {
      // Arrange
      mockContext.tools = [
        createMockTool({
          name: "medical_advisor",
          description: "Provides medical and healthcare advice",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.recommendations.length).toBeGreaterThan(0);
    });

    it("should handle empty tools list", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.status).toBe("PASS");
    });

    it("should handle source code without violations", async () => {
      // Arrange
      mockContext.sourceCodeFiles = createMockSourceCodeFiles({
        "src/index.ts": `
          // This is safe code
          function safeFunction() {
            return "safe content";
          }
        `,
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.violations.length).toBe(0);
    });

    it("should provide explanation for assessment result", async () => {
      // Arrange
      mockContext.tools = [createMockTool()];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.explanation).toBeDefined();
      expect(result.explanation.length).toBeGreaterThan(0);
    });
  });

  describe("Financial Services false positive prevention (Issue #139)", () => {
    it("should NOT flag analytics servers as Financial Services high-risk domain", async () => {
      // Arrange - Microsoft Clarity-like analytics server
      mockContext.tools = [
        createMockTool({
          name: "clarity_get_sessions",
          description:
            "Filter sessions by productPrice, productPurchases, and conversion metrics",
        }),
        createMockTool({
          name: "analytics_dashboard",
          description: "View financial metrics and trading volume reports",
        }),
      ];
      mockContext.readmeContent = `
        # Analytics Dashboard MCP
        Track user sessions, filter by productPrice, analyze investment performance metrics.
        Provides dashboard views for financial KPIs and trading analytics.
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - Should NOT include Financial Services in high-risk domains
      expect(result.highRiskDomains).not.toContain("Financial Services");
      expect(result.status).toBe("PASS");
    });

    it("should flag actual financial transaction servers as Financial Services", async () => {
      // Arrange - Actual payment processing server
      mockContext.tools = [
        createMockTool({
          name: "process_payment",
          description: "Process payment transactions and charge customer cards",
        }),
        createMockTool({
          name: "transfer_funds",
          description: "Transfer funds between accounts",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - SHOULD include Financial Services
      expect(result.highRiskDomains).toContain("Financial Services");
    });

    it("should flag trading execution servers as Financial Services", async () => {
      // Arrange - Trading execution server
      // Descriptions must contain financial keywords (trading, investment, etc.) AND financial action patterns
      mockContext.tools = [
        createMockTool({
          name: "execute_trade",
          description: "Execute trading operations on the investment platform",
        }),
        createMockTool({
          name: "buy_stock",
          description: "Buy shares on the trading platform",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - SHOULD include Financial Services
      expect(result.highRiskDomains).toContain("Financial Services");
    });

    it("should handle mixed analytics and transactions appropriately", async () => {
      // Arrange - Server with both analytics AND transactions
      // The transaction tool must have BOTH financial keyword AND financial action
      mockContext.tools = [
        createMockTool({
          name: "view_trading_metrics",
          description: "View analytics dashboard for trading volume",
        }),
        createMockTool({
          name: "execute_trade",
          description: "Execute trade on the trading platform",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - SHOULD include Financial Services due to transaction capability
      expect(result.highRiskDomains).toContain("Financial Services");
    });

    it("should exempt pure analytics servers even with financial keywords", async () => {
      // Arrange - Analytics-only server
      mockContext.tools = [
        createMockTool({
          name: "get_investment_metrics",
          description: "Query investment performance metrics and analytics",
        }),
        createMockTool({
          name: "filter_by_payment_status",
          description: "Filter orders by payment status for reporting",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - Should NOT flag as Financial Services (analytics only)
      expect(result.highRiskDomains).not.toContain("Financial Services");
    });

    it("should NOT flag Google Analytics-like servers", async () => {
      // Arrange - Google Analytics integration
      mockContext.tools = [
        createMockTool({
          name: "get_ga_data",
          description:
            "Query Google Analytics data including payment conversion metrics",
        }),
      ];
      mockContext.readmeContent = `
        # Google Analytics MCP
        Integration with Google Analytics to track financial conversion rates.
      `;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - Should NOT include Financial Services
      expect(result.highRiskDomains).not.toContain("Financial Services");
    });

    it("should flag banking servers with withdrawal/deposit capabilities", async () => {
      // Arrange - Banking server
      mockContext.tools = [
        createMockTool({
          name: "banking_operations",
          description: "Withdraw from savings account and deposit to checking",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - SHOULD include Financial Services
      expect(result.highRiskDomains).toContain("Financial Services");
    });

    it("should NOT flag session tracking with financial field filters", async () => {
      // Arrange - Session tracking with e-commerce filters (Microsoft Clarity-like)
      mockContext.tools = [
        createMockTool({
          name: "track_sessions",
          description:
            "Track user sessions, filter by orderValue and productPrice",
        }),
      ];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert - Should NOT include Financial Services (analytics/tracking context)
      expect(result.highRiskDomains).not.toContain("Financial Services");
    });
  });
});
