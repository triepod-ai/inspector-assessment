/**
 * Resource URI Validator Module
 *
 * Provides URI validation and inference functions for resource assessment.
 * Includes URI format validation, access control inference, and data classification.
 *
 * @module assessment/resources/uriValidator
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

import { SENSITIVE_PATTERNS } from "./ResourcePatterns";

/**
 * Access control inference result
 */
export interface AccessControlInference {
  requiresAuth: boolean;
  authType?: string;
}

/**
 * Data classification levels
 */
export type DataClassification =
  | "public"
  | "internal"
  | "confidential"
  | "restricted";

/**
 * Validate if a string is a valid URI
 */
export function isValidUri(uri: string): boolean {
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

/**
 * Validate if a string is a valid URI template
 */
export function isValidUriTemplate(template: string): boolean {
  // URI templates can contain {variable} placeholders
  const withoutPlaceholders = template.replace(/\{[^}]+\}/g, "placeholder");
  return isValidUri(withoutPlaceholders);
}

/**
 * Check if a URI matches sensitive file patterns
 */
export function isSensitiveUri(uri: string): boolean {
  return SENSITIVE_PATTERNS.some((pattern) => pattern.test(uri));
}

/**
 * Infer access controls from resource URI (Issue #9)
 */
export function inferAccessControls(uri: string): AccessControlInference {
  // Check for protected/private paths
  if (/\/private\/|\/protected\/|\/secure\/|\/admin\//i.test(uri)) {
    return { requiresAuth: true, authType: "unknown" };
  }

  // Check for auth indicators in URI
  if (/auth|oauth|token|bearer/i.test(uri)) {
    return { requiresAuth: true, authType: "oauth" };
  }

  // Check for API key indicators
  if (/api[_-]?key|apikey/i.test(uri)) {
    return { requiresAuth: true, authType: "api_key" };
  }

  // Check for public paths
  if (/\/public\/|\/static\/|\/assets\//i.test(uri)) {
    return { requiresAuth: false };
  }

  // Default: unknown
  return { requiresAuth: false };
}

/**
 * Infer data classification from resource URI (Issue #9)
 */
export function inferDataClassification(uri: string): DataClassification {
  // Restricted: highly sensitive
  if (/secret|credential|key|password|token|\.pem|\.key|id_rsa/i.test(uri)) {
    return "restricted";
  }

  // Confidential: sensitive business data
  if (/private|confidential|sensitive|\.env|config/i.test(uri)) {
    return "confidential";
  }

  // Public: explicitly public
  if (/\/public\/|\/static\/|\/assets\/|\/docs\//i.test(uri)) {
    return "public";
  }

  // Internal: default for most resources
  return "internal";
}

/**
 * Inject a payload into a URI template by replacing placeholders
 */
export function injectPayloadIntoTemplate(
  template: string,
  payload: string,
): string {
  // Replace template variables with payload
  const result = template.replace(/\{[^}]+\}/g, payload);

  // If no variables, append payload
  if (result === template) {
    return template + "/" + payload;
  }

  return result;
}
