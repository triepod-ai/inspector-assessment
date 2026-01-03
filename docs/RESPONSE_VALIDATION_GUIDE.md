# Response Validation Guide

> **Note**: This guide has been split into focused documents for easier navigation.

## Quick Links

- [Response Validation Core](RESPONSE_VALIDATION_CORE.md) - Validation logic, business error detection, confidence scoring, integration
- [Response Validation Extension](RESPONSE_VALIDATION_EXTENSION.md) - Adding rules, best practices, troubleshooting, API reference

## Overview

The ResponseValidator determines whether tool responses indicate actual functionality versus broken/non-functional tools. It provides sophisticated analysis with particular focus on distinguishing between genuine tool failures and business logic validation errors.

**Key Capabilities:**

- **Response Validation** - Classify tool functionality (fully_working, partially_working, broken, etc.)
- **Business Logic Error Detection** - Distinguish "User not found" (working) from "TypeError" (broken)
- **Confidence Scoring** - Multi-factor weighted confidence calculation
- **Metadata Extraction** - Track content types, output schema validation, MCP features

**Location**: `/client/src/services/assessment/ResponseValidator.ts`

---

_For the complete documentation index, see [docs/README.md](README.md)._
