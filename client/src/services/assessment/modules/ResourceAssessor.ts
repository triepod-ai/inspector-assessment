/**
 * Resource Assessor Module
 * Tests MCP server resources for accessibility, security, and compliance
 *
 * Tests include:
 * - Resource accessibility (can read declared resources)
 * - Path traversal vulnerabilities in resource URIs
 * - Sensitive data exposure detection
 * - URI validation and format compliance
 */

import {
  ResourceAssessment,
  ResourceTestResult,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";

// Sensitive file patterns that shouldn't be exposed
const SENSITIVE_PATTERNS = [
  /\.env$/i,
  /\.pem$/i,
  /\.key$/i,
  /id_rsa/i,
  /id_dsa/i,
  /\.crt$/i,
  /password/i,
  /secret/i,
  /credential/i,
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\.ssh\//i,
  /aws_access_key/i,
  /api[_-]?key/i,
  /\.htpasswd/i,
  /\.git\/config/i,
];

// Path traversal patterns to test
const PATH_TRAVERSAL_PAYLOADS = [
  "../../../etc/passwd",
  "..\\..\\..\\windows\\system32\\config\\sam",
  "....//....//....//etc/passwd",
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
  "..%252f..%252f..%252fetc/passwd",
];

// Sensitive content patterns in resource content
const SENSITIVE_CONTENT_PATTERNS = [
  /-----BEGIN.*PRIVATE KEY-----/i,
  /-----BEGIN RSA PRIVATE KEY-----/i,
  /sk-[a-zA-Z0-9]{32,}/i, // OpenAI-style API keys
  /ghp_[a-zA-Z0-9]{36}/i, // GitHub tokens
  /glpat-[a-zA-Z0-9-_]{20}/i, // GitLab tokens
  /xox[baprs]-[a-zA-Z0-9-]+/i, // Slack tokens
  /AKIA[A-Z0-9]{16}/i, // AWS access keys
  /password\s*[:=]\s*['"][^'"]+['"]/i,
  /secret\s*[:=]\s*['"][^'"]+['"]/i,
];

export class ResourceAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<ResourceAssessment> {
    const results: ResourceTestResult[] = [];

    // Check if resources are provided
    if (!context.resources && !context.resourceTemplates) {
      return this.createNoResourcesResponse();
    }

    const resources = context.resources || [];
    const templates = context.resourceTemplates || [];

    this.log(
      `Testing ${resources.length} resources and ${templates.length} resource templates`,
    );

    // Test each resource
    for (const resource of resources) {
      this.testCount++;
      const result = await this.testResource(resource, context);
      results.push(result);
    }

    // Test resource templates with path traversal payloads
    for (const template of templates) {
      this.testCount++;
      const templateResults = await this.testResourceTemplate(
        template,
        context,
      );
      results.push(...templateResults);
    }

    // Calculate metrics
    const accessibleResources = results.filter((r) => r.accessible).length;
    const securityIssuesFound = results.filter(
      (r) => r.securityIssues.length > 0,
    ).length;
    const pathTraversalVulnerabilities = results.filter(
      (r) => r.pathTraversalVulnerable,
    ).length;
    const sensitiveDataExposures = results.filter(
      (r) => r.sensitiveDataExposed,
    ).length;

    // Determine status
    const status = this.determineResourceStatus(
      pathTraversalVulnerabilities,
      sensitiveDataExposures,
      securityIssuesFound,
      results.length,
    );

    // Generate explanation and recommendations
    const explanation = this.generateExplanation(
      results,
      pathTraversalVulnerabilities,
      sensitiveDataExposures,
    );
    const recommendations = this.generateRecommendations(results);

    return {
      resourcesTested: resources.length,
      resourceTemplatesTested: templates.length,
      accessibleResources,
      securityIssuesFound,
      pathTraversalVulnerabilities,
      sensitiveDataExposures,
      results,
      status,
      explanation,
      recommendations,
    };
  }

  private createNoResourcesResponse(): ResourceAssessment {
    return {
      resourcesTested: 0,
      resourceTemplatesTested: 0,
      accessibleResources: 0,
      securityIssuesFound: 0,
      pathTraversalVulnerabilities: 0,
      sensitiveDataExposures: 0,
      results: [],
      status: "PASS",
      explanation:
        "No resources declared by server. Resource assessment skipped.",
      recommendations: [],
    };
  }

  private async testResource(
    resource: { uri: string; name?: string; mimeType?: string },
    context: AssessmentContext,
  ): Promise<ResourceTestResult> {
    const result: ResourceTestResult = {
      resourceUri: resource.uri,
      resourceName: resource.name,
      mimeType: resource.mimeType,
      tested: true,
      accessible: false,
      securityIssues: [],
      pathTraversalVulnerable: false,
      sensitiveDataExposed: false,
      validUri: this.isValidUri(resource.uri),
    };

    // Check URI for sensitive patterns
    if (this.isSensitiveUri(resource.uri)) {
      result.securityIssues.push(
        `Resource URI matches sensitive file pattern: ${resource.uri}`,
      );
      result.sensitiveDataExposed = true;
    }

    // Try to read the resource if readResource function is provided
    if (context.readResource) {
      try {
        const startTime = Date.now();
        const content = await this.executeWithTimeout(
          context.readResource(resource.uri),
          5000,
        );
        result.readTime = Date.now() - startTime;
        result.accessible = true;
        result.contentSizeBytes = content?.length || 0;

        // Check content for sensitive data
        if (content && this.containsSensitiveContent(content)) {
          result.securityIssues.push(
            "Resource content contains sensitive data patterns (credentials, keys, etc.)",
          );
          result.sensitiveDataExposed = true;
        }
      } catch (error) {
        result.error = this.extractErrorMessage(error);
        result.accessible = false;
      }
    } else {
      result.tested = false;
      result.error = "readResource function not provided - skipping read test";
    }

    return result;
  }

  private async testResourceTemplate(
    template: { uriTemplate: string; name?: string; mimeType?: string },
    context: AssessmentContext,
  ): Promise<ResourceTestResult[]> {
    const results: ResourceTestResult[] = [];

    // Test the template itself
    const templateResult: ResourceTestResult = {
      resourceUri: template.uriTemplate,
      resourceName: template.name,
      mimeType: template.mimeType,
      tested: true,
      accessible: false,
      securityIssues: [],
      pathTraversalVulnerable: false,
      sensitiveDataExposed: false,
      validUri: this.isValidUriTemplate(template.uriTemplate),
    };

    // Check template for sensitive patterns
    if (this.isSensitiveUri(template.uriTemplate)) {
      templateResult.securityIssues.push(
        `Resource template matches sensitive file pattern: ${template.uriTemplate}`,
      );
      templateResult.sensitiveDataExposed = true;
    }

    results.push(templateResult);

    // Test path traversal vulnerabilities if readResource is available
    if (context.readResource) {
      for (const payload of PATH_TRAVERSAL_PAYLOADS) {
        this.testCount++;
        const testUri = this.injectPayloadIntoTemplate(
          template.uriTemplate,
          payload,
        );

        const traversalResult: ResourceTestResult = {
          resourceUri: testUri,
          resourceName: `${template.name} (path traversal test)`,
          tested: true,
          accessible: false,
          securityIssues: [],
          pathTraversalVulnerable: false,
          sensitiveDataExposed: false,
          validUri: false,
        };

        try {
          const content = await this.executeWithTimeout(
            context.readResource(testUri),
            3000,
          );

          // If we got content with a path traversal payload, it's vulnerable
          if (
            content &&
            (content.includes("root:") || content.includes("[fonts]"))
          ) {
            traversalResult.pathTraversalVulnerable = true;
            traversalResult.accessible = true;
            traversalResult.securityIssues.push(
              `Path traversal vulnerability: successfully accessed ${testUri}`,
            );
          }
        } catch {
          // Expected - path traversal should be rejected
          traversalResult.accessible = false;
        }

        results.push(traversalResult);
      }
    }

    return results;
  }

  private isValidUri(uri: string): boolean {
    try {
      // Check for common URI schemes
      if (
        uri.startsWith("file://") ||
        uri.startsWith("http://") ||
        uri.startsWith("https://") ||
        uri.startsWith("resource://") ||
        uri.match(/^[a-z][a-z0-9+.-]*:/i)
      ) {
        return true;
      }
      // Allow relative paths
      return !uri.includes("..") || uri.startsWith("/");
    } catch {
      return false;
    }
  }

  private isValidUriTemplate(template: string): boolean {
    // URI templates can contain {variable} placeholders
    const withoutPlaceholders = template.replace(/\{[^}]+\}/g, "placeholder");
    return this.isValidUri(withoutPlaceholders);
  }

  private isSensitiveUri(uri: string): boolean {
    return SENSITIVE_PATTERNS.some((pattern) => pattern.test(uri));
  }

  private containsSensitiveContent(content: string): boolean {
    return SENSITIVE_CONTENT_PATTERNS.some((pattern) => pattern.test(content));
  }

  private injectPayloadIntoTemplate(template: string, payload: string): string {
    // Replace template variables with payload
    const result = template.replace(/\{[^}]+\}/g, payload);

    // If no variables, append payload
    if (result === template) {
      return template + "/" + payload;
    }

    return result;
  }

  private determineResourceStatus(
    pathTraversalVulnerabilities: number,
    sensitiveDataExposures: number,
    securityIssuesFound: number,
    totalResources: number,
  ): AssessmentStatus {
    // Critical failures
    if (pathTraversalVulnerabilities > 0) return "FAIL";
    if (sensitiveDataExposures > 0) return "FAIL";

    // Moderate issues
    if (securityIssuesFound > 0) return "NEED_MORE_INFO";

    // No resources tested
    if (totalResources === 0) return "PASS";

    return "PASS";
  }

  private generateExplanation(
    results: ResourceTestResult[],
    pathTraversalVulnerabilities: number,
    sensitiveDataExposures: number,
  ): string {
    const parts: string[] = [];

    parts.push(`Tested ${results.length} resource(s).`);

    if (pathTraversalVulnerabilities > 0) {
      parts.push(
        `CRITICAL: ${pathTraversalVulnerabilities} path traversal vulnerability(ies) detected.`,
      );
    }

    if (sensitiveDataExposures > 0) {
      parts.push(
        `WARNING: ${sensitiveDataExposures} resource(s) may expose sensitive data.`,
      );
    }

    const accessibleCount = results.filter((r) => r.accessible).length;
    if (accessibleCount > 0) {
      parts.push(`${accessibleCount} resource(s) are accessible.`);
    }

    return parts.join(" ");
  }

  private generateRecommendations(results: ResourceTestResult[]): string[] {
    const recommendations: string[] = [];

    // Path traversal recommendations
    const pathTraversalResults = results.filter(
      (r) => r.pathTraversalVulnerable,
    );
    if (pathTraversalResults.length > 0) {
      recommendations.push(
        "CRITICAL: Implement path validation to prevent path traversal attacks. Normalize paths and validate against allowed directories.",
      );
    }

    // Sensitive data recommendations
    const sensitiveResults = results.filter((r) => r.sensitiveDataExposed);
    if (sensitiveResults.length > 0) {
      recommendations.push(
        "Review resources for sensitive data exposure. Remove or restrict access to resources containing credentials, keys, or sensitive configuration.",
      );
    }

    // Invalid URI recommendations
    const invalidUriResults = results.filter((r) => !r.validUri);
    if (invalidUriResults.length > 0) {
      recommendations.push(
        "Fix invalid resource URIs to ensure proper URI format compliance.",
      );
    }

    // Inaccessible resource recommendations
    const inaccessibleResults = results.filter(
      (r) => r.tested && !r.accessible && !r.pathTraversalVulnerable,
    );
    if (inaccessibleResults.length > 0) {
      recommendations.push(
        `${inaccessibleResults.length} declared resource(s) are not accessible. Verify resource paths and permissions.`,
      );
    }

    return recommendations;
  }
}
