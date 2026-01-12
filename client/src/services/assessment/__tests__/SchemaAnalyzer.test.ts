/**
 * Tests for SchemaAnalyzer
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 */

import {
  analyzeInputSchema,
  analyzeOutputSchema,
  hasBulkOperationIndicators,
  hasPaginationParameters,
  hasForceFlags,
  type JSONSchema,
} from "../modules/annotations/SchemaAnalyzer";

describe("SchemaAnalyzer", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("analyzeInputSchema", () => {
    describe("read-only detection", () => {
      it("should detect id-only parameter as read-only", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            id: { type: "string", description: "The resource ID" },
          },
          required: ["id"],
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(true);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(70);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("ID-only param")]),
        );
      });

      it("should detect pagination parameters as read-only", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            limit: { type: "number", description: "Max results to return" },
            offset: { type: "number", description: "Starting offset" },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("Pagination param")]),
        );
      });

      it("should detect query parameter as read-only", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            query: { type: "string", description: "Search query" },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(80);
      });

      it("should detect filter parameter as read-only", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            filter: {
              type: "object",
              description: "Filter criteria",
              properties: {
                status: { type: "string" },
              },
            },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(true);
      });

      it("should detect sort parameter as read-only", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            sortBy: { type: "string" },
            order: { type: "string", enum: ["asc", "desc"] },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(true);
      });
    });

    describe("destructive detection", () => {
      it("should detect force flag as destructive", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            id: { type: "string" },
            force: { type: "boolean", description: "Force deletion" },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("Force flag")]),
        );
      });

      it("should detect confirm flag as destructive", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            confirm: { type: "boolean" },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedDestructive).toBe(true);
      });

      it("should detect hard_delete parameter as destructive", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            id: { type: "string" },
            hard_delete: { type: "boolean" },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(95);
      });

      it("should detect cascade parameter as destructive", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            id: { type: "string" },
            cascade: { type: "boolean" },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedDestructive).toBe(true);
      });
    });

    describe("write detection", () => {
      it("should detect data payload as write operation", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            data: {
              type: "object",
              properties: {
                name: { type: "string" },
                value: { type: "number" },
              },
            },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(false);
        expect(result.expectedDestructive).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(70);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("Data payload")]),
        );
      });

      it("should detect payload parameter as write operation", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            payload: {
              type: "object",
            },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(false);
      });

      it("should detect update parameter as write operation", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            id: { type: "string" },
            update: {
              type: "object",
              properties: {
                name: { type: "string" },
              },
            },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(80);
      });

      it("should detect object payload parameter as write operation", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            record: {
              type: "object",
              properties: {
                field1: { type: "string" },
                field2: { type: "number" },
              },
            },
          },
        };

        const result = analyzeInputSchema(schema);

        expect(result.expectedReadOnly).toBe(false);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("Object payload")]),
        );
      });
    });

    describe("edge cases", () => {
      it("should handle empty schema", () => {
        const result = analyzeInputSchema({} as JSONSchema);

        expect(result.confidence).toBe(0);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("No input schema")]),
        );
      });

      it("should handle null schema", () => {
        const result = analyzeInputSchema(null as unknown as JSONSchema);

        expect(result.confidence).toBe(0);
      });

      it("should handle schema without properties", () => {
        const schema: JSONSchema = {
          type: "object",
        };

        const result = analyzeInputSchema(schema);

        expect(result.confidence).toBe(0);
      });

      it("should handle mixed signals (pagination + data)", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            limit: { type: "number" },
            data: { type: "object" },
          },
        };

        const result = analyzeInputSchema(schema);

        // Should recognize both signals
        expect(result.evidence.length).toBeGreaterThan(1);
      });
    });
  });

  describe("analyzeOutputSchema", () => {
    describe("read-only detection", () => {
      it("should detect array return type as read-only", () => {
        const schema: JSONSchema = {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string" },
              name: { type: "string" },
            },
          },
        };

        const result = analyzeOutputSchema(schema);

        expect(result.expectedReadOnly).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(85);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("Returns array")]),
        );
      });

      it("should detect results/items fields as read-only", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            items: { type: "array" },
            total: { type: "number" },
          },
        };

        const result = analyzeOutputSchema(schema);

        expect(result.expectedReadOnly).toBe(true);
        expect(result.evidence).toEqual(
          expect.arrayContaining([
            expect.stringContaining("read-only field patterns"),
          ]),
        );
      });
    });

    describe("destructive detection", () => {
      it("should detect deleted flag as destructive", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            deleted: { type: "boolean" },
            id: { type: "string" },
          },
        };

        const result = analyzeOutputSchema(schema);

        expect(result.expectedDestructive).toBe(true);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("deleted flag")]),
        );
      });

      it("should detect deletedCount as destructive", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            deletedCount: { type: "number" },
          },
        };

        const result = analyzeOutputSchema(schema);

        expect(result.expectedDestructive).toBe(true);
      });

      it("should detect void/null return as possible side-effect", () => {
        const schema: JSONSchema = {
          type: "null",
        };

        const result = analyzeOutputSchema(schema);

        // Void alone is a weak signal
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("void/empty")]),
        );
      });

      it("should detect empty object return as possible side-effect", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {},
        };

        const result = analyzeOutputSchema(schema);

        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("void/empty")]),
        );
      });
    });

    describe("write detection", () => {
      it("should detect created object with id and timestamp", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            id: { type: "string" },
            name: { type: "string" },
            createdAt: { type: "string", format: "date-time" },
          },
        };

        const result = analyzeOutputSchema(schema);

        expect(result.expectedReadOnly).toBe(false);
        expect(result.confidence).toBeGreaterThanOrEqual(90);
        expect(result.evidence).toEqual(
          expect.arrayContaining([
            expect.stringContaining("created timestamp"),
          ]),
        );
      });

      it("should detect created_at timestamp pattern", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            id: { type: "string" },
            created_at: { type: "string" },
          },
        };

        const result = analyzeOutputSchema(schema);

        expect(result.evidence).toEqual(
          expect.arrayContaining([
            expect.stringContaining("created timestamp"),
          ]),
        );
      });
    });

    describe("edge cases", () => {
      it("should handle null schema", () => {
        const result = analyzeOutputSchema(null as unknown as JSONSchema);

        expect(result.confidence).toBe(0);
        expect(result.evidence).toEqual(
          expect.arrayContaining([expect.stringContaining("No output schema")]),
        );
      });

      it("should handle schema with unrecognized patterns", () => {
        const schema: JSONSchema = {
          type: "object",
          properties: {
            foo: { type: "string" },
            bar: { type: "number" },
          },
        };

        const result = analyzeOutputSchema(schema);

        // May have weak signal from single object with id-like patterns
        expect(result.evidence.length).toBeGreaterThan(0);
      });
    });
  });

  describe("hasBulkOperationIndicators", () => {
    it("should return true for array parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          items: {
            type: "array",
            items: { type: "object" },
          },
        },
      };

      expect(hasBulkOperationIndicators(schema)).toBe(true);
    });

    it("should return true for ids parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          ids: { type: "array", items: { type: "string" } },
        },
      };

      expect(hasBulkOperationIndicators(schema)).toBe(true);
    });

    it("should return true for batch parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          batch: { type: "array" },
        },
      };

      expect(hasBulkOperationIndicators(schema)).toBe(true);
    });

    it("should return false for non-bulk schema", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          id: { type: "string" },
          name: { type: "string" },
        },
      };

      expect(hasBulkOperationIndicators(schema)).toBe(false);
    });

    it("should return false for empty schema", () => {
      expect(hasBulkOperationIndicators({} as JSONSchema)).toBe(false);
    });
  });

  describe("hasPaginationParameters", () => {
    it("should return true for limit parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          limit: { type: "number" },
        },
      };

      expect(hasPaginationParameters(schema)).toBe(true);
    });

    it("should return true for page parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          page: { type: "number" },
        },
      };

      expect(hasPaginationParameters(schema)).toBe(true);
    });

    it("should return true for cursor parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          cursor: { type: "string" },
        },
      };

      expect(hasPaginationParameters(schema)).toBe(true);
    });

    it("should return false for non-pagination schema", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          name: { type: "string" },
        },
      };

      expect(hasPaginationParameters(schema)).toBe(false);
    });
  });

  describe("hasForceFlags", () => {
    it("should return true for force parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          force: { type: "boolean" },
        },
      };

      expect(hasForceFlags(schema)).toBe(true);
    });

    it("should return true for confirm parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          confirm: { type: "boolean" },
        },
      };

      expect(hasForceFlags(schema)).toBe(true);
    });

    it("should return true for cascade parameter", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          cascade: { type: "boolean" },
        },
      };

      expect(hasForceFlags(schema)).toBe(true);
    });

    it("should return false for non-force schema", () => {
      const schema: JSONSchema = {
        type: "object",
        properties: {
          data: { type: "object" },
        },
      };

      expect(hasForceFlags(schema)).toBe(false);
    });
  });
});
