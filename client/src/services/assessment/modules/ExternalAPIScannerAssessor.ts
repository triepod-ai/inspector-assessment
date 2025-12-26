/**
 * External API Scanner Assessor
 *
 * Scans source code for external API dependencies and checks for affiliation.
 * Helps identify:
 * - External services used (GitHub, Slack, AWS, etc.)
 * - Hardcoded URLs that may need privacy policy disclosure
 * - Server names that suggest affiliation without verification
 *
 * Part of Priority 2 gap-closing features.
 */

import { BaseAssessor } from "./BaseAssessor";
import type { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  DetectedAPI,
  ExternalAPIScannerAssessment,
  AssessmentStatus,
} from "@/lib/assessmentTypes";

/**
 * Known external services and their URL patterns
 */
const KNOWN_SERVICES: Record<string, RegExp[]> = {
  github: [/api\.github\.com/i, /github\.com\/[^/]+\/[^/]+/i],
  gitlab: [/gitlab\.com/i, /api\.gitlab\.com/i],
  slack: [/slack\.com\/api/i, /api\.slack\.com/i, /hooks\.slack\.com/i],
  discord: [/discord\.com\/api/i, /discordapp\.com/i],
  aws: [/\.amazonaws\.com/i, /\.aws\.amazon\.com/i],
  azure: [/\.azure\.com/i, /\.microsoft\.com/i],
  gcp: [/\.googleapis\.com/i, /\.google\.com\/.*api/i],
  openai: [/api\.openai\.com/i],
  anthropic: [/api\.anthropic\.com/i],
  huggingface: [/huggingface\.co/i, /api\.huggingface\.co/i],
  stripe: [/api\.stripe\.com/i],
  twilio: [/api\.twilio\.com/i],
  sendgrid: [/api\.sendgrid\.com/i],
  firebase: [/firebaseio\.com/i, /firebase\.google\.com/i],
  supabase: [/supabase\.co/i],
  notion: [/api\.notion\.com/i],
  airtable: [/api\.airtable\.com/i],
  dropbox: [/api\.dropbox\.com/i, /dropboxapi\.com/i],
  jira: [/atlassian\.net/i, /jira\.com/i],
  linear: [/api\.linear\.app/i],
  asana: [/api\.asana\.com/i],
};

/**
 * URL patterns to skip (not external APIs)
 */
const SKIP_URL_PATTERNS = [
  /localhost/i,
  /127\.0\.0\.1/i,
  /0\.0\.0\.0/i,
  /example\.com/i,
  /test\.com/i,
  /\.local\//i,
  /schema\.org/i,
  /w3\.org/i,
  /json-schema\.org/i,
  /npmjs\.com/i,
  /unpkg\.com/i,
  /cdn\./i,
  /fonts\.googleapis\.com/i,
];

/**
 * File patterns to skip during scanning
 */
const SKIP_FILE_PATTERNS = [
  /node_modules/i,
  /\.test\.(ts|js|tsx|jsx)$/i,
  /\.spec\.(ts|js|tsx|jsx)$/i,
  /\.d\.ts$/i,
  /package-lock\.json$/i,
  /yarn\.lock$/i,
  /\.map$/i,
  /README\.md$/i,
  /CHANGELOG\.md$/i,
  /LICENSE/i,
  /\.git\//i,
  /dist\//i,
  /build\//i,
];

export class ExternalAPIScannerAssessor extends BaseAssessor {
  async assess(
    context: AssessmentContext,
  ): Promise<ExternalAPIScannerAssessment> {
    this.log("Starting external API scanner assessment");
    this.resetTestCount();

    const detectedAPIs: DetectedAPI[] = [];
    let scannedFiles = 0;

    // Check if source code analysis is enabled
    if (!context.sourceCodeFiles || !context.config.enableSourceCodeAnalysis) {
      this.log("Source code analysis not enabled, skipping external API scan");
      return this.createNoSourceResult();
    }

    // Scan each source file
    for (const [filePath, content] of context.sourceCodeFiles) {
      if (this.shouldSkipFile(filePath)) continue;

      this.testCount++;
      scannedFiles++;

      const fileAPIs = this.scanFileForAPIs(filePath, content);
      detectedAPIs.push(...fileAPIs);
    }

    // Extract unique services
    const uniqueServices = [...new Set(detectedAPIs.map((api) => api.service))];

    // Check for affiliation concerns
    const affiliationWarning = this.checkAffiliation(
      context.serverName,
      uniqueServices,
    );

    // Determine status
    const status = this.computeStatus(detectedAPIs, affiliationWarning);
    const explanation = this.generateExplanation(
      detectedAPIs,
      uniqueServices,
      affiliationWarning,
      scannedFiles,
    );
    const recommendations = this.generateRecommendations(
      uniqueServices,
      affiliationWarning,
    );

    this.log(
      `External API scan complete: ${detectedAPIs.length} APIs found in ${scannedFiles} files`,
    );

    return {
      detectedAPIs,
      uniqueServices,
      affiliationWarning,
      scannedFiles,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Check if file should be skipped
   */
  private shouldSkipFile(filePath: string): boolean {
    return SKIP_FILE_PATTERNS.some((pattern) => pattern.test(filePath));
  }

  /**
   * Scan a file for external API URLs
   */
  private scanFileForAPIs(filePath: string, content: string): DetectedAPI[] {
    const apis: DetectedAPI[] = [];
    const urlPattern = /https?:\/\/[^\s'"`)}\]><]+/g;

    const matches = content.match(urlPattern) || [];

    for (const url of matches) {
      // Skip non-API URLs
      if (this.shouldSkipUrl(url)) continue;

      // Identify the service
      const service = this.identifyService(url);

      // Avoid duplicates in the same file
      if (!apis.some((api) => api.url === url && api.filePath === filePath)) {
        apis.push({
          url: this.cleanUrl(url),
          service,
          filePath,
        });
      }
    }

    return apis;
  }

  /**
   * Check if URL should be skipped
   */
  private shouldSkipUrl(url: string): boolean {
    return SKIP_URL_PATTERNS.some((pattern) => pattern.test(url));
  }

  /**
   * Clean URL by removing trailing punctuation
   */
  private cleanUrl(url: string): string {
    return url.replace(/[.,;:!?'")\]}>]+$/, "");
  }

  /**
   * Identify which service a URL belongs to
   */
  private identifyService(url: string): string {
    for (const [service, patterns] of Object.entries(KNOWN_SERVICES)) {
      if (patterns.some((pattern) => pattern.test(url))) {
        return service;
      }
    }
    return "unknown";
  }

  /**
   * Check if server name suggests affiliation that needs verification
   */
  private checkAffiliation(
    serverName: string,
    detectedServices: string[],
  ): string | undefined {
    const nameLower = serverName.toLowerCase();
    const nameParts = nameLower.split(/[-_\s]/);

    // Check if server name contains a known service name
    for (const service of Object.keys(KNOWN_SERVICES)) {
      if (nameParts.includes(service) || nameLower.includes(service)) {
        // Server claims this service - check if actually uses it
        if (detectedServices.includes(service)) {
          return `Server name "${serverName}" suggests affiliation with ${service}. Verify the author is officially affiliated before approving.`;
        } else {
          return `Server name "${serverName}" suggests affiliation with ${service}, but no ${service} API calls detected. This may be misleading.`;
        }
      }
    }

    return undefined;
  }

  /**
   * Compute assessment status based on scan results
   */
  private computeStatus(
    apis: DetectedAPI[],
    affiliationWarning?: string,
  ): AssessmentStatus {
    if (affiliationWarning) {
      return "NEED_MORE_INFO";
    }
    if (apis.length === 0) {
      return "PASS";
    }
    // Having external APIs isn't a failure, just informational
    return "PASS";
  }

  /**
   * Generate explanation text
   */
  private generateExplanation(
    apis: DetectedAPI[],
    services: string[],
    affiliationWarning: string | undefined,
    scannedFiles: number,
  ): string {
    const parts: string[] = [];

    parts.push(`Scanned ${scannedFiles} source files.`);

    if (apis.length === 0) {
      parts.push("No external API dependencies detected.");
    } else {
      parts.push(
        `Found ${apis.length} external API URL(s) across ${services.length} service(s): ${services.join(", ")}.`,
      );
    }

    if (affiliationWarning) {
      parts.push(`ATTENTION: ${affiliationWarning}`);
    }

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    services: string[],
    affiliationWarning?: string,
  ): string[] {
    const recommendations: string[] = [];

    if (affiliationWarning) {
      recommendations.push(
        "Verify author affiliation with claimed service before directory approval",
      );
    }

    if (services.length > 0 && !services.every((s) => s === "unknown")) {
      recommendations.push(
        `Ensure privacy policies are declared for external services: ${services.filter((s) => s !== "unknown").join(", ")}`,
      );
    }

    if (services.includes("unknown")) {
      recommendations.push(
        "Review unrecognized external URLs for security and privacy implications",
      );
    }

    return recommendations;
  }

  /**
   * Create result when source code analysis is not available
   */
  private createNoSourceResult(): ExternalAPIScannerAssessment {
    return {
      detectedAPIs: [],
      uniqueServices: [],
      scannedFiles: 0,
      status: "NEED_MORE_INFO",
      explanation:
        "External API scanning requires source code analysis. Enable with --source flag.",
      recommendations: [
        "Re-run assessment with --source <path> to enable external API scanning",
      ],
    };
  }
}
