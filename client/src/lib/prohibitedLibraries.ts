/**
 * Prohibited Libraries Detection
 * Based on Anthropic MCP Directory Policy #28-30
 *
 * MCP servers should NOT include:
 * - Financial transaction processing libraries (Policy #28)
 * - Payment processing libraries (Policy #29)
 * - Media processing libraries without justification (Policy #30)
 *
 * Reference: https://support.claude.com/en/articles/11697096-anthropic-mcp-directory-policy
 */

import type { ProhibitedLibraryCategory } from "./assessmentTypes";

export interface ProhibitedLibrary {
  name: string;
  patterns: RegExp[];
  category: ProhibitedLibraryCategory;
  severity: "BLOCKING" | "HIGH" | "MEDIUM";
  policyReference: string;
  reason: string;
  alternatives?: string;
}

/**
 * Financial/Payment Processing Libraries - BLOCKING
 * These libraries handle real money transactions and should not be in MCP servers
 */
export const FINANCIAL_LIBRARIES: ProhibitedLibrary[] = [
  // Payment Processors
  {
    name: "stripe",
    patterns: [/\bstripe\b/i, /@stripe\//i],
    category: "payments",
    severity: "BLOCKING",
    policyReference: "Policy #28",
    reason:
      "Stripe SDK enables payment processing which violates directory policy",
    alternatives: "Use Stripe's webhook-based approach outside of MCP context",
  },
  {
    name: "paypal",
    patterns: [/\bpaypal\b/i, /@paypal\//i, /paypal-rest-sdk/i],
    category: "payments",
    severity: "BLOCKING",
    policyReference: "Policy #28",
    reason: "PayPal SDK enables payment processing",
    alternatives: "Process payments outside of MCP server",
  },
  {
    name: "square",
    patterns: [/\bsquare\b/i, /@square\//i, /square-connect/i],
    category: "payments",
    severity: "BLOCKING",
    policyReference: "Policy #28",
    reason: "Square SDK enables payment processing",
  },
  {
    name: "braintree",
    patterns: [/\bbraintree\b/i],
    category: "payments",
    severity: "BLOCKING",
    policyReference: "Policy #28",
    reason: "Braintree SDK enables payment processing",
  },
  {
    name: "adyen",
    patterns: [/\badyen\b/i, /@adyen\//i],
    category: "payments",
    severity: "BLOCKING",
    policyReference: "Policy #28",
    reason: "Adyen SDK enables payment processing",
  },

  // Banking/Financial Data
  {
    name: "plaid",
    patterns: [/\bplaid\b/i, /plaid-node/i, /@plaid\//i],
    category: "banking",
    severity: "BLOCKING",
    policyReference: "Policy #29",
    reason:
      "Plaid connects to bank accounts which poses significant security risk",
  },
  {
    name: "yodlee",
    patterns: [/\byodlee\b/i],
    category: "banking",
    severity: "BLOCKING",
    policyReference: "Policy #29",
    reason: "Yodlee accesses financial account data",
  },
  {
    name: "finicity",
    patterns: [/\bfinicity\b/i],
    category: "banking",
    severity: "BLOCKING",
    policyReference: "Policy #29",
    reason: "Finicity accesses financial account data",
  },
  {
    name: "mx",
    patterns: [/\bmx-platform\b/i, /@mx\//i],
    category: "banking",
    severity: "BLOCKING",
    policyReference: "Policy #29",
    reason: "MX Platform accesses financial account data",
  },

  // Cryptocurrency
  {
    name: "coinbase",
    patterns: [/\bcoinbase\b/i, /coinbase-commerce/i, /@coinbase\//i],
    category: "financial",
    severity: "BLOCKING",
    policyReference: "Policy #28",
    reason: "Coinbase SDK enables cryptocurrency transactions",
  },
  {
    name: "binance",
    patterns: [/\bbinance\b/i, /node-binance-api/i],
    category: "financial",
    severity: "BLOCKING",
    policyReference: "Policy #28",
    reason: "Binance SDK enables cryptocurrency trading",
  },
  {
    name: "ethers",
    patterns: [/\bethers\b/i, /ethers\.js/i],
    category: "financial",
    severity: "HIGH",
    policyReference: "Policy #28",
    reason:
      "Ethers.js enables Ethereum transactions (review blockchain read-only use)",
    alternatives: "May be acceptable for read-only blockchain queries",
  },
  {
    name: "web3",
    patterns: [/\bweb3\b/i, /web3\.js/i],
    category: "financial",
    severity: "HIGH",
    policyReference: "Policy #28",
    reason: "Web3.js enables blockchain transactions (review read-only use)",
    alternatives: "May be acceptable for read-only blockchain queries",
  },
];

/**
 * Media Processing Libraries - HIGH (requires justification)
 * These libraries should only be included with clear justification
 */
export const MEDIA_LIBRARIES: ProhibitedLibrary[] = [
  // Image Processing
  {
    name: "pillow",
    patterns: [/\bpillow\b/i, /\bpil\b/i, /from\s+PIL\s+import/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason:
      "PIL/Pillow enables image manipulation - requires justification for MCP server use",
    alternatives:
      "Consider if image processing is necessary for MCP functionality",
  },
  {
    name: "opencv",
    patterns: [/\bopencv\b/i, /cv2/i, /opencv-python/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason:
      "OpenCV enables computer vision/image processing - requires justification",
  },
  {
    name: "sharp",
    patterns: [/\bsharp\b/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason:
      "Sharp enables image processing in Node.js - requires justification",
    alternatives:
      "Consider if image transformation is core to MCP functionality",
  },
  {
    name: "jimp",
    patterns: [/\bjimp\b/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason:
      "Jimp enables image manipulation in JavaScript - requires justification",
  },
  {
    name: "imagemagick",
    patterns: [/\bimagemagick\b/i, /\bmagick\b/i, /gm\b/],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason: "ImageMagick enables image processing - requires justification",
  },
  {
    name: "node-canvas",
    patterns: [/\bnode-canvas\b/i, /\bcanvas\b/],
    category: "media",
    severity: "MEDIUM",
    policyReference: "Policy #30",
    reason:
      "Canvas enables image generation - may be acceptable for visualization",
  },

  // Video/Audio Processing
  {
    name: "ffmpeg",
    patterns: [/\bffmpeg\b/i, /fluent-ffmpeg/i, /ffmpeg-static/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason:
      "FFmpeg enables video/audio processing - requires strong justification",
  },
  {
    name: "moviepy",
    patterns: [/\bmoviepy\b/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason: "MoviePy enables video editing - requires justification",
  },
  {
    name: "pydub",
    patterns: [/\bpydub\b/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason: "PyDub enables audio manipulation - requires justification",
  },
  {
    name: "sox",
    patterns: [/\bsox\b/i, /python-sox/i],
    category: "media",
    severity: "HIGH",
    policyReference: "Policy #30",
    reason: "SoX enables audio processing - requires justification",
  },

  // PDF Processing (often legitimate)
  {
    name: "pdf-lib",
    patterns: [/\bpdf-lib\b/i],
    category: "media",
    severity: "MEDIUM",
    policyReference: "Policy #30",
    reason:
      "PDF-lib enables PDF manipulation - often legitimate for document tools",
  },
  {
    name: "pypdf",
    patterns: [/\bpypdf\b/i, /pypdf2/i],
    category: "media",
    severity: "MEDIUM",
    policyReference: "Policy #30",
    reason:
      "PyPDF enables PDF manipulation - often legitimate for document tools",
  },
];

/**
 * All prohibited libraries combined
 */
export const ALL_PROHIBITED_LIBRARIES: ProhibitedLibrary[] = [
  ...FINANCIAL_LIBRARIES,
  ...MEDIA_LIBRARIES,
];

/**
 * Check a dependency name against prohibited libraries
 */
export function checkDependency(depName: string): ProhibitedLibrary | null {
  for (const lib of ALL_PROHIBITED_LIBRARIES) {
    for (const pattern of lib.patterns) {
      if (pattern.test(depName)) {
        return lib;
      }
    }
  }
  return null;
}

/**
 * Check source code imports for prohibited libraries
 */
export function checkSourceImports(sourceCode: string): Array<{
  library: ProhibitedLibrary;
  matchedText: string;
  lineNumber?: number;
}> {
  const matches: Array<{
    library: ProhibitedLibrary;
    matchedText: string;
    lineNumber?: number;
  }> = [];

  const lines = sourceCode.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Check import statements
    const importPatterns = [
      /import\s+.*from\s+['"]([^'"]+)['"]/g, // ES6 import
      /require\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // CommonJS require
      /from\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+import/g, // Python import
      /import\s+([a-zA-Z_][a-zA-Z0-9_]*)/g, // Python import
    ];

    for (const importPattern of importPatterns) {
      let match;
      while ((match = importPattern.exec(line)) !== null) {
        const importedModule = match[1];

        for (const lib of ALL_PROHIBITED_LIBRARIES) {
          for (const pattern of lib.patterns) {
            if (pattern.test(importedModule) || pattern.test(line)) {
              matches.push({
                library: lib,
                matchedText: match[0],
                lineNumber: i + 1,
              });
            }
          }
        }
      }
    }
  }

  // De-duplicate matches by library name and line
  const seen = new Set<string>();
  return matches.filter((m) => {
    const key = `${m.library.name}:${m.lineNumber}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Check package.json dependencies for prohibited libraries
 */
export function checkPackageJsonDependencies(packageJson: {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}): Array<{
  library: ProhibitedLibrary;
  dependencyType: "dependencies" | "devDependencies" | "peerDependencies";
  version: string;
}> {
  const matches: Array<{
    library: ProhibitedLibrary;
    dependencyType: "dependencies" | "devDependencies" | "peerDependencies";
    version: string;
  }> = [];

  const depTypes = [
    "dependencies",
    "devDependencies",
    "peerDependencies",
  ] as const;

  for (const depType of depTypes) {
    const deps = packageJson[depType];
    if (!deps) continue;

    for (const [depName, version] of Object.entries(deps)) {
      const prohibitedLib = checkDependency(depName);
      if (prohibitedLib) {
        matches.push({
          library: prohibitedLib,
          dependencyType: depType,
          version,
        });
      }
    }
  }

  return matches;
}

/**
 * Check Python requirements.txt for prohibited libraries
 */
export function checkRequirementsTxt(content: string): Array<{
  library: ProhibitedLibrary;
  matchedText: string;
  lineNumber: number;
}> {
  const matches: Array<{
    library: ProhibitedLibrary;
    matchedText: string;
    lineNumber: number;
  }> = [];

  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Skip comments and empty lines
    if (!line || line.startsWith("#")) continue;

    // Extract package name (before any version specifier)
    const packageMatch = line.match(/^([a-zA-Z0-9_-]+)/);
    if (!packageMatch) continue;

    const packageName = packageMatch[1];
    const prohibitedLib = checkDependency(packageName);

    if (prohibitedLib) {
      matches.push({
        library: prohibitedLib,
        matchedText: line,
        lineNumber: i + 1,
      });
    }
  }

  return matches;
}

/**
 * Check if a dependency is actually imported in source code (Issue #63)
 *
 * Used to distinguish between dependencies that are:
 * - ACTIVE: Listed AND imported (actual usage)
 * - UNUSED: Listed but NOT imported (can be removed)
 * - UNKNOWN: Unable to determine (source code not available)
 */
export function checkDependencyUsage(
  dependencyName: string,
  sourceCodeFiles: Map<string, string>,
): {
  status: "ACTIVE" | "UNUSED" | "UNKNOWN";
  importCount: number;
  files: string[];
} {
  if (!sourceCodeFiles || sourceCodeFiles.size === 0) {
    return { status: "UNKNOWN", importCount: 0, files: [] };
  }

  // Escape special regex characters in dependency name
  const escapedName = dependencyName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // Build regex patterns for the specific dependency
  const importPatterns = [
    // ES6: import X from 'dep' or import { X } from 'dep'
    new RegExp(`import\\s+.*from\\s+['"\`]${escapedName}['"\`]`, "g"),
    // ES6: import 'dep' (side effect import)
    new RegExp(`import\\s+['"\`]${escapedName}['"\`]`, "g"),
    // CommonJS: require('dep')
    new RegExp(`require\\s*\\(\\s*['"\`]${escapedName}['"\`]\\s*\\)`, "g"),
    // Python: from dep import X
    new RegExp(`from\\s+${escapedName}\\s+import`, "g"),
    // Python: import dep
    new RegExp(`^import\\s+${escapedName}\\b`, "gm"),
    // Handle scoped packages: import X from '@scope/dep' or '@scope/dep/subpath'
    new RegExp(`import\\s+.*from\\s+['"\`]${escapedName}/`, "g"),
    new RegExp(`require\\s*\\(\\s*['"\`]${escapedName}/`, "g"),
  ];

  const matchingFiles: string[] = [];
  let totalMatches = 0;

  for (const [filePath, content] of sourceCodeFiles) {
    // Skip non-source files
    if (!isSourceFileForUsageCheck(filePath)) continue;

    for (const pattern of importPatterns) {
      // Reset lastIndex for global regex
      pattern.lastIndex = 0;
      const matches = content.match(pattern);
      if (matches) {
        totalMatches += matches.length;
        if (!matchingFiles.includes(filePath)) {
          matchingFiles.push(filePath);
        }
      }
    }
  }

  return {
    status: totalMatches > 0 ? "ACTIVE" : "UNUSED",
    importCount: totalMatches,
    files: matchingFiles,
  };
}

/**
 * Check if file is a source file for usage analysis
 */
function isSourceFileForUsageCheck(filePath: string): boolean {
  const sourceExtensions = [
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".py",
    ".rs",
    ".go",
  ];

  // Skip test files and node_modules
  if (
    filePath.includes("node_modules") ||
    filePath.includes(".test.") ||
    filePath.includes(".spec.") ||
    filePath.includes("__tests__")
  ) {
    return false;
  }

  return sourceExtensions.some((ext) => filePath.endsWith(ext));
}

/**
 * Get libraries by severity level
 */
export function getLibrariesBySeverity(
  severity: "BLOCKING" | "HIGH" | "MEDIUM",
): ProhibitedLibrary[] {
  return ALL_PROHIBITED_LIBRARIES.filter((lib) => lib.severity === severity);
}

/**
 * Get libraries by category
 */
export function getLibrariesByCategory(
  category: ProhibitedLibraryCategory,
): ProhibitedLibrary[] {
  return ALL_PROHIBITED_LIBRARIES.filter((lib) => lib.category === category);
}
