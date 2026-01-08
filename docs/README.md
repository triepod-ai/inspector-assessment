# MCP Inspector Documentation

This directory contains comprehensive documentation for the MCP Inspector assessment tool.

---

## Quick Start

| Document                                          | Purpose                                               |
| ------------------------------------------------- | ----------------------------------------------------- |
| [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md)   | Three CLI modes, configuration, CI/CD integration     |
| [Architecture & Value](ARCHITECTURE_AND_VALUE.md) | What inspector-assessment provides and why it matters |

---

## Programmatic API

Integration documentation for using the npm package programmatically.

| Document                                                    | Purpose                                          |
| ----------------------------------------------------------- | ------------------------------------------------ |
| [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md)         | Step-by-step guide for AssessmentOrchestrator    |
| [API Reference](API_REFERENCE.md)                           | Complete API documentation and method signatures |
| [Integration Guide](INTEGRATION_GUIDE.md)                   | Practical patterns for multi-server, CI/CD, etc. |
| [Type Reference](TYPE_REFERENCE.md)                         | Complete TypeScript type reference               |
| [Assessment Types Import](ASSESSMENT_TYPES_IMPORT_GUIDE.md) | Modular structure, import patterns, tree-shaking |

---

## Logging & Diagnostics

| Document                                        | Purpose                                             |
| ----------------------------------------------- | --------------------------------------------------- |
| [Logging Guide](LOGGING_GUIDE.md)               | Structured logging configuration, CLI flags, levels |
| [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md) | Logging section with output examples                |

---

## Core Assessment

### Assessment Modules

| Document                                                                      | Purpose                                                      |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------ |
| [Assessment Catalog](ASSESSMENT_CATALOG.md)                                   | Complete assessment module reference and tier organization   |
| [Assessment Module Developer Guide](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md)     | Creating and extending assessment modules                    |
| [Scoring Algorithm Guide](SCORING_ALGORITHM_GUIDE.md)                         | Module weights, thresholds, calculations                     |
| [Protocol Conformance Assessor Guide](PROTOCOL_CONFORMANCE_ASSESSOR_GUIDE.md) | Module #18: Protocol compliance, event emission, integration |

### Test Data Generation

| Document                                            | Purpose                                       |
| --------------------------------------------------- | --------------------------------------------- |
| [Test Data Architecture](TEST_DATA_ARCHITECTURE.md) | Core architecture, field handlers, boundaries |
| [Test Data Scenarios](TEST_DATA_SCENARIOS.md)       | Scenario categories, tool-aware generation    |
| [Test Data Extension](TEST_DATA_EXTENSION.md)       | Adding handlers, debugging, integration       |

### Response Validation

| Document                                                          | Purpose                                      |
| ----------------------------------------------------------------- | -------------------------------------------- |
| [Response Validation Core](RESPONSE_VALIDATION_CORE.md)           | Validation logic, business error detection   |
| [Response Validation Extension](RESPONSE_VALIDATION_EXTENSION.md) | Adding rules, troubleshooting, API reference |

### Progressive Testing

| Document                                                        | Purpose                  |
| --------------------------------------------------------------- | ------------------------ |
| [Progressive Complexity Guide](PROGRESSIVE_COMPLEXITY_GUIDE.md) | 2-level testing approach |

---

## JSONL Events API

Real-time progress streaming for CLI/auditor integration.

| Document                                               | Purpose                                   |
| ------------------------------------------------------ | ----------------------------------------- |
| [Event Reference](JSONL_EVENTS_REFERENCE.md)           | All 13 event types and schema definitions |
| [Algorithms](JSONL_EVENTS_ALGORITHMS.md)               | EventBatcher and AUP enrichment           |
| [Integration](JSONL_EVENTS_INTEGRATION.md)             | Lifecycle examples, checklist, testing    |
| [Legacy Progress Output](REAL_TIME_PROGRESS_OUTPUT.md) | Legacy progress format (superseded)       |

---

## Security Testing

| Document                                                  | Purpose                                         |
| --------------------------------------------------------- | ----------------------------------------------- |
| [Security Patterns Catalog](SECURITY_PATTERNS_CATALOG.md) | Comprehensive attack patterns and payloads      |
| [Testbed Setup Guide](TESTBED_SETUP_GUIDE.md)             | A/B validation with vulnerable-mcp/hardened-mcp |
| [DVMCP Usage Guide](DVMCP_USAGE_GUIDE.md)                 | Damn Vulnerable MCP educational testbed         |
| [Security Audits](security/)                              | Security audit reports                          |

---

## UI & Specifications

| Document                                            | Purpose                            |
| --------------------------------------------------- | ---------------------------------- |
| [UI Component Reference](UI_COMPONENT_REFERENCE.md) | Assessment UI architecture         |
| [Manifest Requirements](MANIFEST_REQUIREMENTS.md)   | manifest_version 0.3 specification |
| [MCP Spec Reference](mcp_spec_06-2025.md)           | MCP specification notes            |

---

## Maintenance & Operations

### Deprecation Documentation (v1.25.2+)

Start with [Deprecation Index](DEPRECATION_INDEX.md) for navigation, then choose:

| Document                                                            | Purpose                                        |
| ------------------------------------------------------------------- | ---------------------------------------------- |
| [Deprecation Index](DEPRECATION_INDEX.md)                           | Navigation hub for all deprecation docs        |
| [Deprecation Guide](DEPRECATION_GUIDE.md)                           | What's deprecated, why, and migration timeline |
| [Deprecation API Reference](DEPRECATION_API_REFERENCE.md)           | Technical reference, warning formats, testing  |
| [Deprecation Migration Examples](DEPRECATION_MIGRATION_EXAMPLES.md) | Copy-paste ready code examples                 |

### General Maintenance

| Document                                            | Purpose                                |
| --------------------------------------------------- | -------------------------------------- |
| [Upstream Sync Workflow](UPSTREAM_SYNC_WORKFLOW.md) | Sync procedure with upstream inspector |

---

## Base Inspector Reference

Documentation for the underlying MCP Inspector that this assessment tool builds upon:

| Document                                            | Purpose                                           |
| --------------------------------------------------- | ------------------------------------------------- |
| [Base Inspector Guide](BASE_INSPECTOR_GUIDE.md)     | UI operation, Docker, auth, transports, config    |
| [Fork History](FORK_HISTORY.md)                     | Upstream relationship, sync status, what we added |
| [Upstream Sync Workflow](UPSTREAM_SYNC_WORKFLOW.md) | Sync procedure with upstream inspector            |

---

## Legacy Navigation Pages

These files have been split into focused documents and now serve as navigation pages:

- [TEST_DATA_GENERATION_GUIDE.md](TEST_DATA_GENERATION_GUIDE.md) → Test Data series
- [JSONL_EVENTS_API.md](JSONL_EVENTS_API.md) → JSONL Events series
- [RESPONSE_VALIDATION_GUIDE.md](RESPONSE_VALIDATION_GUIDE.md) → Response Validation series

---

## File Organization

```
docs/
├── README.md                               # This navigation hub
├── security/                               # Security audit reports
│   ├── README.md
│   ├── temporal_assessor_security_audit.md
│   └── temporal_assessor_security_summary.md
├── BASE_INSPECTOR_GUIDE.md                 # Base inspector UI/operations
├── FORK_HISTORY.md                         # Upstream relationship
├── CLI_ASSESSMENT_GUIDE.md                 # CLI modes and options
├── PROGRAMMATIC_API_GUIDE.md               # AssessmentOrchestrator usage
├── API_REFERENCE.md                        # Complete API documentation
├── INTEGRATION_GUIDE.md                    # Practical integration patterns
├── TYPE_REFERENCE.md                       # TypeScript type reference
├── LOGGING_GUIDE.md                        # Structured logging configuration
├── ASSESSMENT_TYPES_IMPORT_GUIDE.md        # Modular types, imports, tree-shaking
├── ASSESSMENT_CATALOG.md                   # Assessment module reference
├── SCORING_ALGORITHM_GUIDE.md              # Scoring details
├── ASSESSMENT_MODULE_DEVELOPER_GUIDE.md    # Module development
├── PROTOCOL_CONFORMANCE_ASSESSOR_GUIDE.md # Module #18 integration guide
├── TEST_DATA_ARCHITECTURE.md               # Test data core
├── TEST_DATA_SCENARIOS.md                  # Test scenarios
├── TEST_DATA_EXTENSION.md                  # Test data extension
├── RESPONSE_VALIDATION_CORE.md             # Validation core
├── RESPONSE_VALIDATION_EXTENSION.md        # Validation extension
├── JSONL_EVENTS_REFERENCE.md               # Event types
├── JSONL_EVENTS_ALGORITHMS.md              # Event algorithms
├── JSONL_EVENTS_INTEGRATION.md             # Event integration
├── SECURITY_PATTERNS_CATALOG.md            # Attack patterns
├── TESTBED_SETUP_GUIDE.md                  # Testbed setup
├── DVMCP_USAGE_GUIDE.md                    # DVMCP guide
├── PROGRESSIVE_COMPLEXITY_GUIDE.md         # Progressive testing
├── UI_COMPONENT_REFERENCE.md               # UI components (deprecated)
├── MANIFEST_REQUIREMENTS.md                # Manifest spec
├── DEPRECATION_INDEX.md                    # Deprecation documentation navigation hub
├── DEPRECATION_GUIDE.md                    # Deprecations & migration paths
├── DEPRECATION_API_REFERENCE.md            # Deprecation system technical reference
├── DEPRECATION_MIGRATION_EXAMPLES.md       # Migration code examples
├── UPSTREAM_SYNC_WORKFLOW.md               # Upstream sync
├── ARCHITECTURE_AND_VALUE.md               # Architecture overview
└── REAL_TIME_PROGRESS_OUTPUT.md            # Legacy progress
```

---

**Last Updated**: 2026-01-08
