import {
  isAnalyticsContext,
  hasFinancialActions,
  isFinancialServicesContext,
  checkTextForHighRiskDomains,
} from "../aupPatterns";

describe("aupPatterns - Financial Services context detection (Issue #139)", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("isAnalyticsContext", () => {
    it.each([
      "Microsoft Clarity analytics dashboard",
      "filter by productPrice",
      "trading volume metrics",
      "investment performance report",
      "session recording and heatmaps",
      "conversion rate tracking",
      "google analytics integration",
      "mixpanel event tracking",
      "amplitude user analytics",
      "hotjar session replay",
      "query user sessions",
      "monitor website traffic",
      "search for products",
      "filter by transactionCount",
      "orderValue metrics",
      "sales data report",
      "revenue metric dashboard",
    ])('isAnalyticsContext("%s") should be true', (text) => {
      expect(isAnalyticsContext(text)).toBe(true);
    });

    it.each([
      "process payment transaction",
      "transfer funds to account",
      "execute trade order",
      "withdraw from savings",
      "deposit into checking",
      "buy stock shares",
      "sell cryptocurrency",
      "charge customer card",
      "wire transfer service",
    ])(
      'isAnalyticsContext("%s") should be false (no analytics context)',
      (text) => {
        expect(isAnalyticsContext(text)).toBe(false);
      },
    );
  });

  describe("hasFinancialActions", () => {
    it.each([
      "process payment",
      "submit payment",
      "initiate transaction",
      "charge customer card",
      "charge account",
      "create payment",
      "create invoice",
      "transfer funds",
      "transfer money",
      "send money",
      "wire transfer",
      "withdrawal from account",
      "deposit funds",
      "debit account",
      "credit account balance",
      "execute trade",
      "place order",
      "submit trade",
      "buy stock",
      "buy shares",
      "buy crypto",
      "sell stock",
      "sell asset",
      "market order",
      "limit order",
      "invest in bonds",
      "allocate funds",
      "allocate capital",
      "rebalance portfolio",
      "mint token",
      "mint nft",
      "swap token",
      "swap crypto",
      "stake tokens",
    ])('hasFinancialActions("%s") should be true', (text) => {
      expect(hasFinancialActions(text)).toBe(true);
    });

    it.each([
      "view payment metrics",
      "filter by trading volume",
      "investment analytics dashboard",
      "track transactions",
      "report on payments",
      "banking sector analysis",
      "financial data visualization",
    ])(
      'hasFinancialActions("%s") should be false (no financial actions)',
      (text) => {
        expect(hasFinancialActions(text)).toBe(false);
      },
    );
  });

  describe("isFinancialServicesContext", () => {
    it("should return false for analytics server with financial keywords", () => {
      const text =
        "Analytics dashboard for trading metrics and investment performance";
      expect(isFinancialServicesContext(text)).toBe(false);
    });

    it("should return true for payment processing server", () => {
      const text = "Process payment transactions and transfer funds";
      expect(isFinancialServicesContext(text)).toBe(true);
    });

    it("should return true for trading execution server", () => {
      const text = "Execute trade orders on the investment platform";
      expect(isFinancialServicesContext(text)).toBe(true);
    });

    it("should return false for text without financial keywords", () => {
      const text = "Weather data and calendar management";
      expect(isFinancialServicesContext(text)).toBe(false);
    });

    it("should return true for mixed analytics and transactions (conservative)", () => {
      const text = "View trading analytics and execute trade orders";
      expect(isFinancialServicesContext(text)).toBe(true);
    });

    it("should return false for Microsoft Clarity-like analytics", () => {
      const text =
        "Filter sessions by productPrice and productPurchases. Track conversion metrics.";
      expect(isFinancialServicesContext(text)).toBe(false);
    });

    it("should return true for generic financial keywords without clear context", () => {
      // No analytics patterns, no action patterns - default to true (conservative)
      const text = "Financial system integration";
      expect(isFinancialServicesContext(text)).toBe(true);
    });

    it("should return false for analytics platform mentions", () => {
      const text = "Google Analytics financial metrics tracking";
      expect(isFinancialServicesContext(text)).toBe(false);
    });

    it("should return true for banking API with actions", () => {
      const text = "Banking API to withdraw and deposit funds";
      expect(isFinancialServicesContext(text)).toBe(true);
    });

    it("should return false for investment dashboard", () => {
      const text = "Investment dashboard with portfolio metrics and insights";
      expect(isFinancialServicesContext(text)).toBe(false);
    });
  });

  describe("checkTextForHighRiskDomains - Financial Services exemption", () => {
    it("should NOT flag Microsoft Clarity-like analytics text", () => {
      const text =
        "Filter sessions by productPrice and productPurchases. Track conversion metrics.";
      const matches = checkTextForHighRiskDomains(text);
      const financialMatch = matches.find(
        (m) => m.domain === "Financial Services",
      );
      expect(financialMatch).toBeUndefined();
    });

    it("should NOT flag analytics dashboard with trading metrics", () => {
      const text =
        "Analytics dashboard showing trading volume and investment performance metrics";
      const matches = checkTextForHighRiskDomains(text);
      const financialMatch = matches.find(
        (m) => m.domain === "Financial Services",
      );
      expect(financialMatch).toBeUndefined();
    });

    it("should flag actual payment processing text", () => {
      const text = "Process payment transactions and charge cards";
      const matches = checkTextForHighRiskDomains(text);
      const financialMatch = matches.find(
        (m) => m.domain === "Financial Services",
      );
      expect(financialMatch).toBeDefined();
      expect(financialMatch?.matchedText).toMatch(/payment/i);
    });

    it("should flag trading execution server", () => {
      // Text must contain a financial keyword (trading, investment, etc.) AND a financial action
      const text = "Execute trade orders on the trading platform";
      const matches = checkTextForHighRiskDomains(text);
      const financialMatch = matches.find(
        (m) => m.domain === "Financial Services",
      );
      expect(financialMatch).toBeDefined();
    });

    it("should flag fund transfer capabilities", () => {
      const text = "Banking service to transfer funds between accounts";
      const matches = checkTextForHighRiskDomains(text);
      const financialMatch = matches.find(
        (m) => m.domain === "Financial Services",
      );
      expect(financialMatch).toBeDefined();
    });

    it("should still detect other high-risk domains normally", () => {
      const text = "Medical diagnosis for patient healthcare";
      const matches = checkTextForHighRiskDomains(text);
      const healthcareMatch = matches.find((m) => m.domain === "Healthcare");
      expect(healthcareMatch).toBeDefined();
    });

    it("should detect legal domain normally", () => {
      const text = "Legal document processing for attorney clients";
      const matches = checkTextForHighRiskDomains(text);
      const legalMatch = matches.find((m) => m.domain === "Legal");
      expect(legalMatch).toBeDefined();
    });

    it("should detect government domain normally", () => {
      const text = "Government classified data access system";
      const matches = checkTextForHighRiskDomains(text);
      const govMatch = matches.find((m) => m.domain === "Government/Defense");
      expect(govMatch).toBeDefined();
    });

    it("should NOT flag text without any high-risk domain keywords", () => {
      const text = "Weather forecast and calendar scheduling tool";
      const matches = checkTextForHighRiskDomains(text);
      expect(matches.length).toBe(0);
    });

    it("should flag mixed analytics and transactions (conservative)", () => {
      const text =
        "Dashboard with trading analytics and ability to execute trade orders";
      const matches = checkTextForHighRiskDomains(text);
      const financialMatch = matches.find(
        (m) => m.domain === "Financial Services",
      );
      expect(financialMatch).toBeDefined();
    });
  });

  describe("Edge cases for Financial Services detection", () => {
    it("should handle empty string", () => {
      expect(isFinancialServicesContext("")).toBe(false);
      expect(checkTextForHighRiskDomains("").length).toBe(0);
    });

    it("should be case-insensitive for analytics patterns", () => {
      expect(isAnalyticsContext("ANALYTICS DASHBOARD")).toBe(true);
      expect(isAnalyticsContext("Analytics Dashboard")).toBe(true);
      expect(isAnalyticsContext("analytics dashboard")).toBe(true);
    });

    it("should be case-insensitive for financial action patterns", () => {
      expect(hasFinancialActions("PROCESS PAYMENT")).toBe(true);
      expect(hasFinancialActions("Process Payment")).toBe(true);
      expect(hasFinancialActions("process payment")).toBe(true);
    });

    it("should handle partial word matches correctly (word boundaries)", () => {
      // "financial" should match, but not "unfinancial" embedded in words
      expect(isFinancialServicesContext("financial")).toBe(true);
      // Analytics patterns use word boundaries too
      expect(isAnalyticsContext("preanalytics")).toBe(false);
      expect(isAnalyticsContext("analytics")).toBe(true);
    });
  });
});
