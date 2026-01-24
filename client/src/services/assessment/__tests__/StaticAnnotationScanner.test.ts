/**
 * Tests for StaticAnnotationScanner
 * Issue #192: Static annotation scanner misses nested annotations in ES module syntax
 */

import { StaticAnnotationScanner } from "../helpers/StaticAnnotationScanner";

describe("StaticAnnotationScanner", () => {
  let scanner: StaticAnnotationScanner;

  beforeEach(() => {
    scanner = new StaticAnnotationScanner();
  });

  describe("ES module annotation patterns", () => {
    it("should detect annotations in const array definitions", () => {
      const sourceCode = `
const TOOLS = [
  {
    name: 'search_documents',
    description: 'Search documents',
    inputSchema: { type: 'object' },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false
    }
  }
];
`;
      const files = new Map([["server/index.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(1);
      expect(result.annotations.has("search_documents")).toBe(true);

      const ann = result.annotations.get("search_documents")!;
      expect(ann.readOnlyHint).toBe(true);
      expect(ann.destructiveHint).toBe(false);
    });

    it("should detect annotations in export const arrays", () => {
      const sourceCode = `
export const tools = [
  {
    name: 'get_user',
    description: 'Get user by ID',
    annotations: {
      readOnlyHint: true
    }
  },
  {
    name: 'delete_user',
    description: 'Delete user',
    annotations: {
      destructiveHint: true
    }
  }
];
`;
      const files = new Map([["src/tools.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(2);
      expect(result.annotations.get("get_user")?.readOnlyHint).toBe(true);
      expect(result.annotations.get("delete_user")?.destructiveHint).toBe(true);
    });

    it("should detect annotations in direct object exports", () => {
      const sourceCode = `
export const myTool = {
  name: 'fetch_data',
  description: 'Fetch data from API',
  annotations: {
    readOnlyHint: true,
    openWorldHint: true
  }
};
`;
      const files = new Map([["tools/fetch.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(1);

      const ann = result.annotations.get("fetch_data")!;
      expect(ann.readOnlyHint).toBe(true);
      expect(ann.openWorldHint).toBe(true);
    });

    it("should handle nested tool definitions in objects", () => {
      const sourceCode = `
const server = {
  tools: [
    {
      name: 'list_items',
      annotations: { readOnlyHint: true }
    }
  ]
};
`;
      const files = new Map([["server.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(1);
      expect(result.annotations.get("list_items")?.readOnlyHint).toBe(true);
    });

    it("should detect annotations in default export arrays", () => {
      const sourceCode = `
export default [
  {
    name: 'tool_one',
    annotations: { idempotentHint: true }
  }
];
`;
      const files = new Map([["tools.mjs", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(1);
      expect(result.annotations.get("tool_one")?.idempotentHint).toBe(true);
    });
  });

  describe("tool name association", () => {
    it("should associate annotation with sibling name property", () => {
      const sourceCode = `
const tool = {
  name: 'my_tool',
  description: 'A tool',
  annotations: {
    readOnlyHint: true
  }
};
`;
      const files = new Map([["tool.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("my_tool")).toBe(true);
    });

    it("should handle tools without name property (skipped)", () => {
      const sourceCode = `
const tool = {
  description: 'Anonymous tool',
  annotations: {
    readOnlyHint: true
  }
};
`;
      const files = new Map([["tool.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(0);
    });

    it("should handle string literal keys for name", () => {
      const sourceCode = `
const tool = {
  'name': 'quoted_name_tool',
  annotations: { readOnlyHint: true }
};
`;
      const files = new Map([["tool.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("quoted_name_tool")).toBe(true);
    });
  });

  describe("annotation value extraction", () => {
    it("should extract readOnlyHint boolean values", () => {
      const sourceCode = `
const tool = { name: 't1', annotations: { readOnlyHint: true } };
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.get("t1")?.readOnlyHint).toBe(true);
    });

    it("should extract destructiveHint boolean values", () => {
      const sourceCode = `
const tool = { name: 't2', annotations: { destructiveHint: true } };
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.get("t2")?.destructiveHint).toBe(true);
    });

    it("should extract idempotentHint boolean values", () => {
      const sourceCode = `
const tool = { name: 't3', annotations: { idempotentHint: false } };
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.get("t3")?.idempotentHint).toBe(false);
    });

    it("should extract openWorldHint boolean values", () => {
      const sourceCode = `
const tool = { name: 't4', annotations: { openWorldHint: true } };
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.get("t4")?.openWorldHint).toBe(true);
    });

    it("should extract all four annotation types together", () => {
      const sourceCode = `
const tool = {
  name: 'full_tool',
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false
  }
};
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      const ann = result.annotations.get("full_tool")!;
      expect(ann.readOnlyHint).toBe(true);
      expect(ann.destructiveHint).toBe(false);
      expect(ann.idempotentHint).toBe(true);
      expect(ann.openWorldHint).toBe(false);
    });

    it("should handle non-suffixed property names (readOnly instead of readOnlyHint)", () => {
      const sourceCode = `
const tool = { name: 'legacy', annotations: { readOnly: true, destructive: false } };
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      const ann = result.annotations.get("legacy")!;
      expect(ann.readOnlyHint).toBe(true);
      expect(ann.destructiveHint).toBe(false);
    });

    it("should ignore non-boolean annotation values", () => {
      const sourceCode = `
const tool = {
  name: 'stringy',
  annotations: {
    readOnlyHint: 'yes',
    destructiveHint: 1,
    idempotentHint: true
  }
};
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      const ann = result.annotations.get("stringy")!;
      expect(ann.readOnlyHint).toBeUndefined();
      expect(ann.destructiveHint).toBeUndefined();
      expect(ann.idempotentHint).toBe(true);
    });
  });

  describe("file handling", () => {
    it("should skip test files", () => {
      const sourceCode = `
const tool = { name: 'test_tool', annotations: { readOnlyHint: true } };
`;
      const files = new Map([["tools.test.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(0);
      expect(result.scannedFiles).toHaveLength(0);
    });

    it("should skip spec files", () => {
      const sourceCode = `
const tool = { name: 'spec_tool', annotations: { readOnlyHint: true } };
`;
      const files = new Map([["tools.spec.ts", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(0);
    });

    it("should skip node_modules", () => {
      const sourceCode = `
const tool = { name: 'dep_tool', annotations: { readOnlyHint: true } };
`;
      const files = new Map([["node_modules/lib/index.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(0);
    });

    it("should skip declaration files (.d.ts)", () => {
      const sourceCode = `
const tool = { name: 'type_tool', annotations: { readOnlyHint: true } };
`;
      const files = new Map([["types.d.ts", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(0);
    });

    it("should handle parse errors gracefully", () => {
      const invalidCode = `
const tool = {
  name: 'broken',
  annotations: { readOnlyHint: true }
// missing closing braces - syntax error
`;
      const files = new Map([["broken.js", invalidCode]]);
      const result = scanner.scan(files);

      expect(result.parseErrors.length).toBeGreaterThan(0);
      expect(result.annotatedToolCount).toBe(0);
    });

    it("should support .js files", () => {
      const sourceCode = `
const tool = { name: 'js_tool', annotations: { readOnlyHint: true } };
`;
      const files = new Map([["tool.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("js_tool")).toBe(true);
    });

    it("should support .mjs files", () => {
      const sourceCode = `
export const tool = { name: 'mjs_tool', annotations: { readOnlyHint: true } };
`;
      const files = new Map([["tool.mjs", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("mjs_tool")).toBe(true);
    });

    it("should support .cjs files", () => {
      const sourceCode = `
const tool = { name: 'cjs_tool', annotations: { readOnlyHint: true } };
module.exports = tool;
`;
      const files = new Map([["tool.cjs", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("cjs_tool")).toBe(true);
    });

    it("should skip non-JS/TS files", () => {
      const sourceCode = `
tool = { name: 'py_tool', annotations: { readOnlyHint: True } }
`;
      const files = new Map([["tool.py", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.scannedFiles).toHaveLength(0);
    });

    it("should scan multiple files", () => {
      const files = new Map([
        [
          "tools/read.js",
          `const tool = { name: 'read_tool', annotations: { readOnlyHint: true } };`,
        ],
        [
          "tools/write.js",
          `const tool = { name: 'write_tool', annotations: { destructiveHint: true } };`,
        ],
      ]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(2);
      expect(result.scannedFiles).toHaveLength(2);
    });
  });

  describe("confidence levels", () => {
    it("should report high confidence for multiple annotations", () => {
      const files = new Map([
        [
          "a.js",
          `const t1 = { name: 'tool1', annotations: { readOnlyHint: true } };`,
        ],
        [
          "b.js",
          `const t2 = { name: 'tool2', annotations: { readOnlyHint: true } };`,
        ],
      ]);
      const result = scanner.scan(files);

      expect(result.confidence).toBe("high");
    });

    it("should report medium confidence for single annotation", () => {
      const files = new Map([
        [
          "a.js",
          `const t = { name: 'tool', annotations: { readOnlyHint: true } };`,
        ],
      ]);
      const result = scanner.scan(files);

      expect(result.confidence).toBe("medium");
    });

    it("should report low confidence when no annotations found", () => {
      const files = new Map([["a.js", `const x = 1;`]]);
      const result = scanner.scan(files);

      expect(result.confidence).toBe("low");
    });

    it("should report low confidence for empty input", () => {
      const result = scanner.scan(new Map());

      expect(result.confidence).toBe("low");
      expect(result.sourceCodeScanned).toBe(false);
    });

    it("should report low confidence for undefined input", () => {
      const result = scanner.scan(undefined);

      expect(result.confidence).toBe("low");
      expect(result.sourceCodeScanned).toBe(false);
    });
  });

  describe("evidence tracking", () => {
    it("should record evidence for each found annotation", () => {
      const sourceCode = `
const tools = [
  { name: 'tool_a', annotations: { readOnlyHint: true } },
  { name: 'tool_b', annotations: { destructiveHint: true } }
];
`;
      const files = new Map([["tools.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.evidence).toHaveLength(2);
      expect(result.evidence[0].toolName).toBe("tool_a");
      expect(result.evidence[1].toolName).toBe("tool_b");
      expect(result.evidence[0].filePath).toBe("tools.js");
    });

    it("should include line numbers in evidence", () => {
      const sourceCode = `const tool = {
  name: 'lined_tool',
  annotations: {
    readOnlyHint: true
  }
};`;
      const files = new Map([["tool.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.evidence[0].lineNumber).toBeDefined();
      expect(result.evidence[0].lineNumber).toBeGreaterThan(0);
    });
  });

  describe("TypeScript support", () => {
    it("should handle basic TypeScript files", () => {
      const sourceCode = `
const tool = {
  name: 'ts_tool',
  description: 'A TypeScript tool',
  annotations: {
    readOnlyHint: true
  }
};

export default tool;
`;
      const files = new Map([["tool.ts", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("ts_tool")).toBe(true);
    });

    it("should handle TypeScript with type annotations stripped", () => {
      // Note: Complex TS syntax may fail, but basic cases should work
      const sourceCode = `
const tools = [
  {
    name: 'typed_tool',
    annotations: {
      readOnlyHint: true
    }
  }
];
`;
      const files = new Map([["tools.ts", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("typed_tool")).toBe(true);
    });
  });

  describe("edge cases", () => {
    it("should handle empty annotations object", () => {
      const sourceCode = `
const tool = { name: 'empty_ann', annotations: {} };
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      // Empty annotations should not be recorded
      expect(result.annotatedToolCount).toBe(0);
    });

    it("should handle annotations with only unknown properties", () => {
      const sourceCode = `
const tool = { name: 'unknown_ann', annotations: { customProp: true } };
`;
      const files = new Map([["t.js", sourceCode]]);
      const result = scanner.scan(files);

      // Unknown properties are ignored, so no valid annotations
      expect(result.annotatedToolCount).toBe(0);
    });

    it("should handle multiple tools in single file", () => {
      const sourceCode = `
const tools = [
  { name: 'tool1', annotations: { readOnlyHint: true } },
  { name: 'tool2', annotations: { readOnlyHint: false } },
  { name: 'tool3', annotations: { destructiveHint: true } }
];
`;
      const files = new Map([["tools.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(3);
    });

    it("should handle deeply nested structures", () => {
      const sourceCode = `
const config = {
  server: {
    mcp: {
      tools: [
        {
          name: 'deep_tool',
          annotations: { readOnlyHint: true }
        }
      ]
    }
  }
};
`;
      const files = new Map([["config.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotations.has("deep_tool")).toBe(true);
    });
  });

  describe("real-world patterns from Issue #192", () => {
    it("should detect the exact pattern from the issue", () => {
      // This is the exact pattern from Issue #192 that was being missed
      const sourceCode = `
const TOOLS = [
  {
    name: 'tool_name',
    description: '...',
    inputSchema: { type: 'object' },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false
    }
  }
];
`;
      const files = new Map([["server/index.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(1);
      expect(result.annotations.has("tool_name")).toBe(true);

      const ann = result.annotations.get("tool_name")!;
      expect(ann.readOnlyHint).toBe(true);
      expect(ann.destructiveHint).toBe(false);
    });

    it("should handle the WB server pattern with title in annotations", () => {
      // Pattern from the issue evidence showing title alongside hint annotations
      const sourceCode = `
const tools = [
  {
    name: 'search_documents',
    description: 'Search for documents',
    inputSchema: { type: 'object' },
    annotations: {
      title: 'Search Documents',
      readOnlyHint: true,
      destructiveHint: false
    }
  }
];
`;
      const files = new Map([["server/index.js", sourceCode]]);
      const result = scanner.scan(files);

      expect(result.annotatedToolCount).toBe(1);
      const ann = result.annotations.get("search_documents")!;
      expect(ann.readOnlyHint).toBe(true);
      expect(ann.destructiveHint).toBe(false);
      // title is not extracted (not a standard hint annotation)
    });
  });
});
