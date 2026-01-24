/**
 * Static Annotation Scanner
 *
 * Scans source code files for tool annotations using AST parsing.
 * Detects annotations nested inside tool definition objects/arrays
 * in ES module syntax that regex-based scanning would miss.
 *
 * Fixes Issue #192: Static annotation scanner misses nested annotations
 * in ES module syntax like:
 *   const TOOLS = [{ name: 'x', annotations: { readOnlyHint: true } }];
 *
 * @module helpers/StaticAnnotationScanner
 */

import * as acorn from "acorn";
import * as walk from "acorn-walk";

/**
 * Evidence from static annotation scanning
 */
export interface StaticAnnotationEvidence {
  /** File path where annotation was found */
  filePath: string;
  /** Tool name associated with the annotation */
  toolName: string;
  /** Confidence level */
  confidence: "high" | "medium" | "low";
  /** Description of how the annotation was found */
  detail: string;
  /** Line number in source file */
  lineNumber?: number;
}

/**
 * Extracted annotation from source code
 */
export interface StaticAnnotation {
  toolName: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

/**
 * Result of static annotation scanning
 */
export interface StaticAnnotationScanResult {
  /** Map of tool name to extracted annotations */
  annotations: Map<string, StaticAnnotation>;
  /** Overall confidence of the scan */
  confidence: "high" | "medium" | "low";
  /** Evidence collected during scanning */
  evidence: StaticAnnotationEvidence[];
  /** Whether source code was scanned */
  sourceCodeScanned: boolean;
  /** Count of tools with annotations found */
  annotatedToolCount: number;
  /** Files that were scanned */
  scannedFiles: string[];
  /** Errors encountered during parsing */
  parseErrors: Array<{ file: string; error: string }>;
}

// Type definitions for acorn AST nodes we use
interface AcornNode {
  type: string;
  start: number;
  end: number;
  loc?: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
}

interface PropertyNode extends AcornNode {
  type: "Property";
  key: IdentifierNode | LiteralNode;
  value: AcornNode;
  kind: "init" | "get" | "set";
  computed: boolean;
  shorthand: boolean;
}

interface IdentifierNode extends AcornNode {
  type: "Identifier";
  name: string;
}

interface LiteralNode extends AcornNode {
  type: "Literal";
  value: string | number | boolean | null;
  raw: string;
}

interface ObjectExpressionNode extends AcornNode {
  type: "ObjectExpression";
  properties: (PropertyNode | SpreadElementNode)[];
}

interface SpreadElementNode extends AcornNode {
  type: "SpreadElement";
  argument: AcornNode;
}

/**
 * Scans source code for tool annotations using AST parsing.
 *
 * Detection approach:
 * 1. Parse JS/TS files with acorn (ecmaVersion 2022, module syntax)
 * 2. Walk AST looking for Property nodes with key 'annotations'
 * 3. Extract annotation values (readOnlyHint, destructiveHint, etc.)
 * 4. Find associated tool name from sibling 'name' property in parent object
 *
 * @public
 */
export class StaticAnnotationScanner {
  /**
   * File patterns to skip during source code scanning
   * (same patterns as StdioTransportDetector for consistency)
   */
  private readonly SKIP_FILE_PATTERNS: RegExp[] = [
    /node_modules/i,
    /\.test\.(ts|js|tsx|jsx|py)$/i,
    /\.spec\.(ts|js|tsx|jsx|py)$/i,
    /\.d\.ts$/i,
    /package-lock\.json$/i,
    /yarn\.lock$/i,
    /\.map$/i,
    /\.git\//i,
    /dist\//i,
    /build\//i,
    /__tests__\//i,
    /__mocks__\//i,
    /__pycache__\//i,
    /\.pytest_cache\//i,
  ];

  /** Maximum file size for source scanning (500KB) */
  private readonly MAX_FILE_SIZE = 500_000;

  /** File extensions to scan */
  private readonly SCANNABLE_EXTENSIONS = [".js", ".ts", ".mjs", ".cjs"];

  /**
   * Scan source files for tool annotations.
   *
   * @param sourceCodeFiles - Map of file paths to content
   * @returns Static annotation scan results
   */
  scan(sourceCodeFiles?: Map<string, string>): StaticAnnotationScanResult {
    const annotations = new Map<string, StaticAnnotation>();
    const evidence: StaticAnnotationEvidence[] = [];
    const scannedFiles: string[] = [];
    const parseErrors: Array<{ file: string; error: string }> = [];

    if (!sourceCodeFiles || sourceCodeFiles.size === 0) {
      return {
        annotations,
        confidence: "low",
        evidence,
        sourceCodeScanned: false,
        annotatedToolCount: 0,
        scannedFiles,
        parseErrors,
      };
    }

    sourceCodeFiles.forEach((content, filePath) => {
      // Skip files that shouldn't be scanned
      if (this.shouldSkipFile(filePath)) return;

      // Skip oversized files
      if (content.length > this.MAX_FILE_SIZE) return;

      // Only scan JS/TS files
      if (!this.isScannableFile(filePath)) return;

      scannedFiles.push(filePath);

      try {
        const fileAnnotations = this.parseFile(filePath, content);

        for (const ann of fileAnnotations) {
          // Store annotation (later occurrences override earlier)
          annotations.set(ann.toolName, ann);

          // Record evidence
          evidence.push({
            filePath,
            toolName: ann.toolName,
            confidence: "high",
            detail: `Found annotations object in tool definition`,
            lineNumber: ann.lineNumber,
          });
        }
      } catch (error) {
        parseErrors.push({
          file: filePath,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    });

    const confidence = this.computeConfidence(evidence);

    return {
      annotations,
      confidence,
      evidence,
      sourceCodeScanned: scannedFiles.length > 0,
      annotatedToolCount: annotations.size,
      scannedFiles,
      parseErrors,
    };
  }

  /**
   * Parse a single file for tool annotations.
   *
   * @param filePath - File path for error reporting
   * @param content - File content to parse
   * @returns Array of extracted annotations with line numbers
   */
  private parseFile(
    filePath: string,
    content: string,
  ): Array<StaticAnnotation & { lineNumber?: number }> {
    const results: Array<StaticAnnotation & { lineNumber?: number }> = [];

    // Try to parse as ES module first, fall back to script
    let ast: acorn.Node;
    try {
      ast = acorn.parse(content, {
        ecmaVersion: 2022,
        sourceType: "module",
        locations: true,
      });
    } catch {
      // Try as script (CommonJS)
      try {
        ast = acorn.parse(content, {
          ecmaVersion: 2022,
          sourceType: "script",
          locations: true,
        });
      } catch (scriptError) {
        // For TypeScript files, try stripping type annotations
        // (basic approach - strip common TS patterns)
        const strippedContent = this.stripTypeScript(content);
        try {
          ast = acorn.parse(strippedContent, {
            ecmaVersion: 2022,
            sourceType: "module",
            locations: true,
          });
        } catch {
          throw new Error(
            `Failed to parse ${filePath}: ${scriptError instanceof Error ? scriptError.message : String(scriptError)}`,
          );
        }
      }
    }

    // Walk the AST with ancestor tracking
    walk.ancestor(ast as acorn.Node, {
      Property: (node: acorn.Node, ancestors: acorn.Node[]) => {
        const prop = node as unknown as PropertyNode;

        // Check if this is an 'annotations' property
        if (!this.isAnnotationsProperty(prop)) return;

        // Value must be an object expression
        if (prop.value.type !== "ObjectExpression") return;

        const annotationValues = this.extractAnnotationValues(
          prop.value as unknown as ObjectExpressionNode,
        );
        if (!annotationValues) return;

        // Find the tool name from parent context
        const toolName = this.findToolNameFromContext(ancestors);
        if (!toolName) return;

        results.push({
          toolName,
          ...annotationValues,
          lineNumber: prop.loc?.start.line,
        });
      },
    });

    return results;
  }

  /**
   * Check if a property node is an 'annotations' property.
   */
  private isAnnotationsProperty(prop: PropertyNode): boolean {
    // Handle Identifier key: annotations: {...}
    if (prop.key.type === "Identifier") {
      return prop.key.name === "annotations";
    }
    // Handle Literal key: 'annotations': {...} or "annotations": {...}
    if (prop.key.type === "Literal") {
      return prop.key.value === "annotations";
    }
    return false;
  }

  /**
   * Extract annotation values from an ObjectExpression node.
   */
  private extractAnnotationValues(
    obj: ObjectExpressionNode,
  ): Omit<StaticAnnotation, "toolName"> | null {
    const result: Omit<StaticAnnotation, "toolName"> = {};
    let hasAnyAnnotation = false;

    for (const prop of obj.properties) {
      if (prop.type !== "Property") continue;

      const propNode = prop as PropertyNode;
      const keyName = this.getPropertyKeyName(propNode);
      if (!keyName) continue;

      // Only extract boolean values
      if (propNode.value.type !== "Literal") continue;
      const literalValue = (propNode.value as LiteralNode).value;
      if (typeof literalValue !== "boolean") continue;

      // Map property names (handle both *Hint and non-suffixed)
      switch (keyName) {
        case "readOnlyHint":
        case "readOnly":
          result.readOnlyHint = literalValue;
          hasAnyAnnotation = true;
          break;
        case "destructiveHint":
        case "destructive":
          result.destructiveHint = literalValue;
          hasAnyAnnotation = true;
          break;
        case "idempotentHint":
        case "idempotent":
          result.idempotentHint = literalValue;
          hasAnyAnnotation = true;
          break;
        case "openWorldHint":
        case "openWorld":
          result.openWorldHint = literalValue;
          hasAnyAnnotation = true;
          break;
      }
    }

    return hasAnyAnnotation ? result : null;
  }

  /**
   * Get the string name of a property key.
   */
  private getPropertyKeyName(prop: PropertyNode): string | null {
    if (prop.key.type === "Identifier") {
      return prop.key.name;
    }
    if (prop.key.type === "Literal" && typeof prop.key.value === "string") {
      return prop.key.value;
    }
    return null;
  }

  /**
   * Find the tool name from ancestor context.
   * Looks for a sibling 'name' property in the parent ObjectExpression.
   */
  private findToolNameFromContext(ancestors: acorn.Node[]): string | null {
    // Walk up ancestors looking for ObjectExpression (the tool definition)
    for (let i = ancestors.length - 1; i >= 0; i--) {
      const ancestor = ancestors[i] as AcornNode;

      if (ancestor.type === "ObjectExpression") {
        const objNode = ancestor as unknown as ObjectExpressionNode;

        // Look for sibling 'name' property
        for (const prop of objNode.properties) {
          if (prop.type !== "Property") continue;

          const propNode = prop as PropertyNode;
          const keyName = this.getPropertyKeyName(propNode);

          if (keyName === "name" && propNode.value.type === "Literal") {
            const nameValue = (propNode.value as LiteralNode).value;
            if (typeof nameValue === "string") {
              return nameValue;
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Strip common TypeScript syntax for basic parsing.
   * This is a simple approach - just removes type annotations to allow JS parsing.
   */
  private stripTypeScript(content: string): string {
    return (
      content
        // Remove type imports: import type { X } from 'y'
        .replace(/import\s+type\s+\{[^}]*\}\s+from\s+['"][^'"]+['"];?/g, "")
        // Remove type annotations: : Type
        .replace(/:\s*[A-Z][a-zA-Z0-9<>[\],\s|&]*(?=[\s,;)=\]}])/g, "")
        // Remove interface declarations
        .replace(/interface\s+\w+\s*(\{[^}]*\}|\{[\s\S]*?\n\})/g, "")
        // Remove type declarations
        .replace(/type\s+\w+\s*=\s*[^;]+;/g, "")
        // Remove as Type assertions
        .replace(/\s+as\s+[A-Z][a-zA-Z0-9<>[\],\s|&]*/g, "")
        // Remove generic parameters on function calls
        .replace(/<[A-Z][a-zA-Z0-9<>[\],\s|&]*>(?=\()/g, "")
    );
  }

  /**
   * Check if file should be skipped during scanning.
   */
  private shouldSkipFile(filePath: string): boolean {
    return this.SKIP_FILE_PATTERNS.some((pattern) => pattern.test(filePath));
  }

  /**
   * Check if file has a scannable extension.
   */
  private isScannableFile(filePath: string): boolean {
    return this.SCANNABLE_EXTENSIONS.some((ext) =>
      filePath.toLowerCase().endsWith(ext),
    );
  }

  /**
   * Compute overall confidence from collected evidence.
   *
   * Confidence rules:
   * - High: 2+ annotations found with explicit 'annotations' objects
   * - Medium: 1 annotation found
   * - Low: No annotations found
   */
  private computeConfidence(
    evidence: StaticAnnotationEvidence[],
  ): "high" | "medium" | "low" {
    if (evidence.length === 0) {
      return "low";
    }

    // Count high-confidence evidence
    const highConfCount = evidence.filter(
      (e) => e.confidence === "high",
    ).length;

    if (highConfCount >= 2) {
      return "high";
    }

    if (highConfCount >= 1) {
      return "medium";
    }

    return "low";
  }
}
