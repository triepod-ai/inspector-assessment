/**
 * Privacy Compliance Assessor Module
 * Evaluates PII handling, GDPR/CCPA compliance, and data protection measures
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentStatus } from "@/lib/assessmentTypes";

export interface PrivacyComplianceAssessment {
  category: "privacy";
  status: AssessmentStatus;
  score: number;
  piiDetection: {
    found: boolean;
    types: string[];
    locations: string[];
    classification: {
      sensitive: string[];
      quasiIdentifiers: string[];
      public: string[];
    };
  };
  gdprCompliance: {
    consentMechanism: boolean;
    dataPortability: boolean;
    rightToErasure: boolean;
    privacyByDesign: boolean;
    dataMinimization: boolean;
    score: number;
  };
  ccpaCompliance: {
    optOutMechanism: boolean;
    dataDisclosure: boolean;
    nonDiscrimination: boolean;
    verifiableRequests: boolean;
    score: number;
  };
  dataRetention: {
    policyExists: boolean;
    retentionPeriods: { [key: string]: string };
    automaticDeletion: boolean;
  };
  encryption: {
    atRest: boolean;
    inTransit: boolean;
    keyManagement: boolean;
    algorithms: string[];
  };
  criticalFindings: string[];
  recommendations: string[];
  explanation: string;
}

interface PIIPattern {
  type: string;
  pattern: RegExp;
  classification: "sensitive" | "quasi" | "public";
}

export class PrivacyComplianceAssessor extends BaseAssessor {
  private piiPatterns: PIIPattern[] = [
    // Sensitive PII
    {
      type: "SSN",
      pattern: /\b\d{3}-\d{2}-\d{4}\b/,
      classification: "sensitive",
    },
    {
      type: "Credit Card",
      pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,
      classification: "sensitive",
    },
    {
      type: "Bank Account",
      pattern: /\b\d{8,17}\b/,
      classification: "sensitive",
    },
    {
      type: "Passport",
      pattern: /\b[A-Z]{1,2}\d{6,9}\b/,
      classification: "sensitive",
    },
    {
      type: "Driver License",
      pattern: /\b[A-Z]{1,2}\d{6,8}\b/,
      classification: "sensitive",
    },
    {
      type: "Health Record",
      pattern: /\b(diagnosis|medication|treatment|medical)\b/i,
      classification: "sensitive",
    },

    // Quasi-identifiers
    {
      type: "Email",
      pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
      classification: "quasi",
    },
    {
      type: "Phone",
      pattern: /\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/,
      classification: "quasi",
    },
    {
      type: "Date of Birth",
      pattern:
        /\b(0[1-9]|1[0-2])[\/\-](0[1-9]|[12]\d|3[01])[\/\-](19|20)\d{2}\b/,
      classification: "quasi",
    },
    {
      type: "ZIP Code",
      pattern: /\b\d{5}(-\d{4})?\b/,
      classification: "quasi",
    },
    {
      type: "IP Address",
      pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
      classification: "quasi",
    },

    // Public (but still tracked)
    {
      type: "Name",
      pattern: /\b[A-Z][a-z]+ [A-Z][a-z]+\b/,
      classification: "public",
    },
    {
      type: "Address",
      pattern:
        /\b\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b/i,
      classification: "public",
    },
  ];

  async assess(
    context: AssessmentContext,
  ): Promise<PrivacyComplianceAssessment> {
    this.log("Starting privacy compliance assessment");

    const piiDetection = await this.detectPII(context);
    const gdprCompliance = await this.assessGDPRCompliance(context);
    const ccpaCompliance = await this.assessCCPACompliance(context);
    const dataRetention = await this.assessDataRetention(context);
    const encryption = await this.assessEncryption(context);

    const score = this.calculatePrivacyScore(
      piiDetection,
      gdprCompliance,
      ccpaCompliance,
      dataRetention,
      encryption,
    );

    const status = this.determineStatus(score, 100, 70);

    const criticalFindings = this.identifyCriticalFindings(
      piiDetection,
      gdprCompliance,
      ccpaCompliance,
      dataRetention,
      encryption,
    );

    const recommendations = this.generateRecommendations(
      piiDetection,
      gdprCompliance,
      ccpaCompliance,
      dataRetention,
      encryption,
    );

    const explanation = this.generateExplanation(
      piiDetection,
      gdprCompliance,
      ccpaCompliance,
      encryption,
    );

    return {
      category: "privacy",
      status,
      score,
      piiDetection,
      gdprCompliance,
      ccpaCompliance,
      dataRetention,
      encryption,
      criticalFindings,
      recommendations,
      explanation,
    };
  }

  private async detectPII(context: AssessmentContext): Promise<{
    found: boolean;
    types: string[];
    locations: string[];
    classification: {
      sensitive: string[];
      quasiIdentifiers: string[];
      public: string[];
    };
  }> {
    this.log("Detecting PII in tool responses");

    const types: Set<string> = new Set();
    const locations: Set<string> = new Set();
    const classification = {
      sensitive: [] as string[],
      quasiIdentifiers: [] as string[],
      public: [] as string[],
    };

    // Test each tool for PII exposure
    for (const tool of context.tools) {
      try {
        // Skip tools without output
        if (!tool.inputSchema?.properties) continue;

        // Create test input
        const testInput = this.createPIITestInput(tool);
        const result = await context.callTool(tool.name, testInput);

        if (result && typeof result === "object") {
          const resultStr = JSON.stringify(result);

          // Check for PII patterns
          for (const piiPattern of this.piiPatterns) {
            if (piiPattern.pattern.test(resultStr)) {
              types.add(piiPattern.type);
              locations.add(tool.name);

              switch (piiPattern.classification) {
                case "sensitive":
                  if (!classification.sensitive.includes(piiPattern.type)) {
                    classification.sensitive.push(piiPattern.type);
                  }
                  break;
                case "quasi":
                  if (
                    !classification.quasiIdentifiers.includes(piiPattern.type)
                  ) {
                    classification.quasiIdentifiers.push(piiPattern.type);
                  }
                  break;
                case "public":
                  if (!classification.public.includes(piiPattern.type)) {
                    classification.public.push(piiPattern.type);
                  }
                  break;
              }
            }
          }
        }
      } catch (error) {
        // Silent catch for PII detection
      }
    }

    return {
      found: types.size > 0,
      types: Array.from(types),
      locations: Array.from(locations),
      classification,
    };
  }

  private async assessGDPRCompliance(context: AssessmentContext): Promise<{
    consentMechanism: boolean;
    dataPortability: boolean;
    rightToErasure: boolean;
    privacyByDesign: boolean;
    dataMinimization: boolean;
    score: number;
  }> {
    this.log("Assessing GDPR compliance");

    const compliance = {
      consentMechanism: false,
      dataPortability: false,
      rightToErasure: false,
      privacyByDesign: false,
      dataMinimization: false,
      score: 0,
    };

    // Check for GDPR-related functionality in tools
    for (const tool of context.tools) {
      const name = tool.name.toLowerCase();
      const desc = tool.description?.toLowerCase() || "";

      // Check for consent mechanisms
      if (
        name.includes("consent") ||
        desc.includes("consent") ||
        name.includes("permission") ||
        desc.includes("permission")
      ) {
        compliance.consentMechanism = true;
      }

      // Check for data portability
      if (
        name.includes("export") ||
        desc.includes("export") ||
        name.includes("download") ||
        desc.includes("download")
      ) {
        compliance.dataPortability = true;
      }

      // Check for right to erasure
      if (
        name.includes("delete") ||
        desc.includes("delete") ||
        name.includes("erase") ||
        desc.includes("remove")
      ) {
        compliance.rightToErasure = true;
      }

      // Check for privacy by design indicators
      if (
        desc.includes("privacy") ||
        desc.includes("encryption") ||
        desc.includes("anonymiz") ||
        desc.includes("pseudonymiz")
      ) {
        compliance.privacyByDesign = true;
      }

      // Check for data minimization
      if (
        desc.includes("minimal") ||
        desc.includes("necessary") ||
        desc.includes("limited")
      ) {
        compliance.dataMinimization = true;
      }
    }

    // Calculate GDPR compliance score
    let score = 0;
    if (compliance.consentMechanism) score += 20;
    if (compliance.dataPortability) score += 20;
    if (compliance.rightToErasure) score += 20;
    if (compliance.privacyByDesign) score += 20;
    if (compliance.dataMinimization) score += 20;

    compliance.score = score;

    return compliance;
  }

  private async assessCCPACompliance(context: AssessmentContext): Promise<{
    optOutMechanism: boolean;
    dataDisclosure: boolean;
    nonDiscrimination: boolean;
    verifiableRequests: boolean;
    score: number;
  }> {
    this.log("Assessing CCPA compliance");

    const compliance = {
      optOutMechanism: false,
      dataDisclosure: false,
      nonDiscrimination: false,
      verifiableRequests: false,
      score: 0,
    };

    // Check for CCPA-related functionality
    for (const tool of context.tools) {
      const name = tool.name.toLowerCase();
      const desc = tool.description?.toLowerCase() || "";

      // Check for opt-out mechanism
      if (
        name.includes("opt") ||
        desc.includes("opt-out") ||
        desc.includes("do not sell")
      ) {
        compliance.optOutMechanism = true;
      }

      // Check for data disclosure
      if (
        name.includes("disclosure") ||
        desc.includes("disclose") ||
        desc.includes("categories")
      ) {
        compliance.dataDisclosure = true;
      }

      // Check for non-discrimination
      if (desc.includes("discriminat") || desc.includes("equal")) {
        compliance.nonDiscrimination = true;
      }

      // Check for verifiable requests
      if (
        name.includes("verif") ||
        desc.includes("verif") ||
        desc.includes("authenticat")
      ) {
        compliance.verifiableRequests = true;
      }
    }

    // Calculate CCPA compliance score
    let score = 0;
    if (compliance.optOutMechanism) score += 25;
    if (compliance.dataDisclosure) score += 25;
    if (compliance.nonDiscrimination) score += 25;
    if (compliance.verifiableRequests) score += 25;

    compliance.score = score;

    return compliance;
  }

  private async assessDataRetention(context: AssessmentContext): Promise<{
    policyExists: boolean;
    retentionPeriods: { [key: string]: string };
    automaticDeletion: boolean;
  }> {
    this.log("Assessing data retention policies");

    const retention = {
      policyExists: false,
      retentionPeriods: {} as { [key: string]: string },
      automaticDeletion: false,
    };

    // Check for retention-related functionality
    for (const tool of context.tools) {
      const desc = tool.description?.toLowerCase() || "";

      if (
        desc.includes("retention") ||
        desc.includes("expire") ||
        desc.includes("ttl") ||
        desc.includes("lifecycle")
      ) {
        retention.policyExists = true;

        // Try to extract retention periods
        const periodMatch = desc.match(/(\d+)\s*(day|week|month|year)/i);
        if (periodMatch) {
          retention.retentionPeriods[tool.name] =
            `${periodMatch[1]} ${periodMatch[2]}(s)`;
        }
      }

      if (
        desc.includes("automatic") &&
        (desc.includes("delet") || desc.includes("remov"))
      ) {
        retention.automaticDeletion = true;
      }
    }

    // Set default retention periods if policy exists but no specific periods found
    if (
      retention.policyExists &&
      Object.keys(retention.retentionPeriods).length === 0
    ) {
      retention.retentionPeriods["default"] = "Not specified";
    }

    return retention;
  }

  private async assessEncryption(context: AssessmentContext): Promise<{
    atRest: boolean;
    inTransit: boolean;
    keyManagement: boolean;
    algorithms: string[];
  }> {
    this.log("Assessing encryption implementation");

    const encryption = {
      atRest: false,
      inTransit: false,
      keyManagement: false,
      algorithms: [] as string[],
    };

    const knownAlgorithms = [
      "AES",
      "RSA",
      "SHA-256",
      "SHA-512",
      "ECDSA",
      "ECDH",
      "ChaCha20",
      "Poly1305",
      "TLS",
      "SSL",
      "HTTPS",
    ];

    // Check server info and tools for encryption indicators
    const serverStr = JSON.stringify(context.serverInfo || {}).toLowerCase();

    // Check for encryption at rest
    if (
      serverStr.includes("encrypt") &&
      (serverStr.includes("storage") ||
        serverStr.includes("database") ||
        serverStr.includes("disk"))
    ) {
      encryption.atRest = true;
    }

    // Check for encryption in transit
    if (
      serverStr.includes("https") ||
      serverStr.includes("tls") ||
      serverStr.includes("ssl") ||
      serverStr.includes("secure")
    ) {
      encryption.inTransit = true;
    }

    // Check for key management
    if (
      serverStr.includes("key") &&
      (serverStr.includes("management") ||
        serverStr.includes("rotation") ||
        serverStr.includes("vault"))
    ) {
      encryption.keyManagement = true;
    }

    // Detect encryption algorithms
    for (const algo of knownAlgorithms) {
      if (serverStr.includes(algo.toLowerCase())) {
        if (!encryption.algorithms.includes(algo)) {
          encryption.algorithms.push(algo);
        }
      }
    }

    // Also check tools
    for (const tool of context.tools) {
      const toolStr = (tool.name + " " + tool.description).toLowerCase();

      if (toolStr.includes("encrypt")) {
        if (toolStr.includes("rest") || toolStr.includes("storage")) {
          encryption.atRest = true;
        }
        if (toolStr.includes("transit") || toolStr.includes("transfer")) {
          encryption.inTransit = true;
        }
      }

      for (const algo of knownAlgorithms) {
        if (toolStr.includes(algo.toLowerCase())) {
          if (!encryption.algorithms.includes(algo)) {
            encryption.algorithms.push(algo);
          }
        }
      }
    }

    return encryption;
  }

  private createPIITestInput(tool: any): any {
    const input: any = {};

    if (tool.inputSchema?.properties) {
      for (const [key, schema] of Object.entries(tool.inputSchema.properties)) {
        const schemaType = (schema as any).type;

        // Create test data that might reveal PII handling
        if (schemaType === "string") {
          input[key] = "John Doe, SSN: 123-45-6789, Email: john@example.com";
        } else if (schemaType === "object") {
          input[key] = {
            name: "Jane Smith",
            email: "jane@example.com",
            phone: "555-123-4567",
            ssn: "987-65-4321",
          };
        } else {
          input[key] = this.getDefaultValue(schema as any);
        }
      }
    }

    return input;
  }

  private getDefaultValue(schema: any): any {
    switch (schema.type) {
      case "string":
        return "";
      case "number":
        return 0;
      case "boolean":
        return false;
      case "array":
        return [];
      case "object":
        return {};
      default:
        return null;
    }
  }

  private calculatePrivacyScore(
    piiDetection: any,
    gdprCompliance: any,
    ccpaCompliance: any,
    dataRetention: any,
    encryption: any,
  ): number {
    let score = 100;

    // Deduct for PII exposure (max -30)
    if (piiDetection.found) {
      score -= 10;
      score -= Math.min(piiDetection.classification.sensitive.length * 5, 20);
    }

    // Deduct for GDPR non-compliance (max -20)
    score -= (100 - gdprCompliance.score) * 0.2;

    // Deduct for CCPA non-compliance (max -15)
    score -= (100 - ccpaCompliance.score) * 0.15;

    // Deduct for missing data retention policy (max -15)
    if (!dataRetention.policyExists) score -= 10;
    if (!dataRetention.automaticDeletion) score -= 5;

    // Deduct for missing encryption (max -20)
    if (!encryption.atRest) score -= 10;
    if (!encryption.inTransit) score -= 10;

    return Math.max(0, Math.round(score));
  }

  private identifyCriticalFindings(
    piiDetection: any,
    gdprCompliance: any,
    ccpaCompliance: any,
    dataRetention: any,
    encryption: any,
  ): string[] {
    const findings: string[] = [];

    if (piiDetection.classification.sensitive.length > 0) {
      findings.push(
        `CRITICAL: Sensitive PII detected (${piiDetection.classification.sensitive.join(", ")})`,
      );
    }

    if (!encryption.atRest || !encryption.inTransit) {
      findings.push("Missing critical encryption implementation");
    }

    if (gdprCompliance.score < 50) {
      findings.push("Significant GDPR compliance gaps");
    }

    if (ccpaCompliance.score < 50) {
      findings.push("Significant CCPA compliance gaps");
    }

    if (!dataRetention.policyExists) {
      findings.push("No data retention policy detected");
    }

    return findings;
  }

  private generateRecommendations(
    piiDetection: any,
    gdprCompliance: any,
    ccpaCompliance: any,
    dataRetention: any,
    encryption: any,
  ): string[] {
    const recommendations: string[] = [];

    if (piiDetection.found) {
      recommendations.push("Implement PII detection and masking mechanisms");
      recommendations.push(
        "Use tokenization or pseudonymization for sensitive data",
      );
    }

    if (!gdprCompliance.consentMechanism) {
      recommendations.push("Implement explicit consent collection mechanisms");
    }

    if (!gdprCompliance.rightToErasure) {
      recommendations.push("Add data deletion/erasure functionality");
    }

    if (!ccpaCompliance.optOutMechanism) {
      recommendations.push("Implement opt-out mechanism for data sale");
    }

    if (!dataRetention.automaticDeletion) {
      recommendations.push(
        "Implement automatic data deletion based on retention policy",
      );
    }

    if (!encryption.atRest) {
      recommendations.push("Implement encryption for data at rest");
    }

    if (!encryption.inTransit) {
      recommendations.push("Implement TLS/HTTPS for data in transit");
    }

    recommendations.push("Conduct regular privacy impact assessments");
    recommendations.push("Maintain comprehensive data processing records");

    return recommendations;
  }

  private generateExplanation(
    piiDetection: any,
    gdprCompliance: any,
    ccpaCompliance: any,
    encryption: any,
  ): string {
    const parts: string[] = [];

    if (piiDetection.found) {
      parts.push(
        `Detected ${piiDetection.types.length} types of PII across ${piiDetection.locations.length} locations.`,
      );
    } else {
      parts.push("No PII exposure detected.");
    }

    parts.push(`GDPR compliance: ${gdprCompliance.score}%.`);
    parts.push(`CCPA compliance: ${ccpaCompliance.score}%.`);

    if (encryption.algorithms.length > 0) {
      parts.push(
        `Encryption algorithms detected: ${encryption.algorithms.join(", ")}.`,
      );
    }

    return parts.join(" ");
  }
}
