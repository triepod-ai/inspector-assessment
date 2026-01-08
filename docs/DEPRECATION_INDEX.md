# Deprecation Documentation Index

**Version**: 1.25.2+
**Timeline**: Removal planned for v2.0.0 (Q2 2026)
**Status**: Comprehensive documentation system for migration planning

This index provides a quick navigation guide to all deprecation-related documentation.

## Quick Reference

**For different audiences:**

- **CLI Users**: No action needed - CLI handles all deprecations automatically
- **Library Users**: Follow [Deprecation Guide](DEPRECATION_GUIDE.md) starting with "Migration Checklist"
- **Custom Assessor Developers**: [Custom Assessor Examples](DEPRECATION_MIGRATION_EXAMPLES.md#custom-assessor-examples)
- **CI/CD Integration**: [Testing Examples](DEPRECATION_MIGRATION_EXAMPLES.md#testing-examples)

## Documentation Overview

### 1. [DEPRECATION_GUIDE.md](DEPRECATION_GUIDE.md) - Primary User Guide

**Length**: 875 lines | **Read Time**: 20-30 minutes
**Best for**: Understanding what's deprecated and why

**Contents**:

- Overview of deprecation system architecture
- 4 deprecated modules with replacements
- 2 deprecated config flags with migration paths
- 2 deprecated BaseAssessor methods with examples
- Migration checklist for different user types
- Deprecation timeline (v1.25.2 → v2.0.0)
- FAQ with answers to common questions
- Warning message reference

**Start here if you**:

- Are using the assessment system and need to update your code
- Want to understand the deprecation policy
- Need to plan your migration timeline

### 2. [DEPRECATION_API_REFERENCE.md](DEPRECATION_API_REFERENCE.md) - Technical Reference

**Length**: 846 lines | **Read Time**: 15-20 minutes
**Best for**: Understanding the deprecation system internals

**Contents**:

- Deprecation emission architecture (3 primary locations)
- Warning message formats with examples
- Implementation details for each deprecation type
- Programmatic handling and suppression
- Unit test examples
- Metrics and telemetry collection
- CI/CD integration patterns

**Start here if you**:

- Are implementing deprecation tracking in your code
- Need to understand warning formats programmatically
- Want to create deprecation tests
- Are building CI/CD pipelines with deprecation checks

### 3. [DEPRECATION_MIGRATION_EXAMPLES.md](DEPRECATION_MIGRATION_EXAMPLES.md) - Code Examples

**Length**: 954 lines | **Read Time**: 15-25 minutes
**Best for**: Copy-paste ready migration code

**Contents**:

- Configuration examples (basic, extended, presets, CLI)
- Module migration examples (direct instantiation, conditionals)
- Custom assessor examples (logging updates, error handling)
- Complete application examples (before/after)
- Testing examples (config, modules, methods)
- Migration checklist (tracking tool)

**Start here if you**:

- Want copy-paste code examples for your situation
- Are migrating multiple parts of your codebase
- Need before/after code comparisons
- Are writing tests for deprecated APIs

## Deprecation Categories at a Glance

### Assessment Modules (4 modules)

| Module                        | Replacement                   | Status                               |
| ----------------------------- | ----------------------------- | ------------------------------------ |
| `DocumentationAssessor`       | `DeveloperExperienceAssessor` | Warning in v1.25.2, remove in v2.0.0 |
| `UsabilityAssessor`           | `DeveloperExperienceAssessor` | Warning in v1.25.2, remove in v2.0.0 |
| `MCPSpecComplianceAssessor`   | `ProtocolComplianceAssessor`  | Warning in v1.25.2, remove in v2.0.0 |
| `ProtocolConformanceAssessor` | `ProtocolComplianceAssessor`  | Warning in v1.25.2, remove in v2.0.0 |

**Guide**: [DEPRECATION_GUIDE.md#assessment-modules-migration](DEPRECATION_GUIDE.md#assessment-modules-migration)
**Examples**: [DEPRECATION_MIGRATION_EXAMPLES.md#module-migration-examples](DEPRECATION_MIGRATION_EXAMPLES.md#module-migration-examples)

### Config Flags (2 flags)

| Flag                                       | Replacement                               | Status                               |
| ------------------------------------------ | ----------------------------------------- | ------------------------------------ |
| `assessmentCategories.mcpSpecCompliance`   | `assessmentCategories.protocolCompliance` | Warning in v1.25.2, remove in v2.0.0 |
| `assessmentCategories.protocolConformance` | `assessmentCategories.protocolCompliance` | Warning in v1.25.2, remove in v2.0.0 |

**Guide**: [DEPRECATION_GUIDE.md#configuration-flags-migration](DEPRECATION_GUIDE.md#configuration-flags-migration)
**Examples**: [DEPRECATION_MIGRATION_EXAMPLES.md#configuration-examples](DEPRECATION_MIGRATION_EXAMPLES.md#configuration-examples)

### BaseAssessor Methods (2 methods)

| Method                                            | Replacement                            | Status                                            |
| ------------------------------------------------- | -------------------------------------- | ------------------------------------------------- |
| `this.log(message: string)`                       | `this.logger.info(message)`            | Warning on first use in v1.25.2, remove in v2.0.0 |
| `this.logError(message: string, error?: unknown)` | `this.logger.error(message, context?)` | Warning on first use in v1.25.2, remove in v2.0.0 |

**Guide**: [DEPRECATION_GUIDE.md#baseassessor-method-migration](DEPRECATION_GUIDE.md#baseassessor-method-migration)
**Examples**: [DEPRECATION_MIGRATION_EXAMPLES.md#custom-assessor-examples](DEPRECATION_MIGRATION_EXAMPLES.md#custom-assessor-examples)

## Migration Paths by Use Case

### Use Case 1: CLI User (e.g., `npx mcp-assess-full`)

**Impact**: None
**Action Required**: None

The CLI automatically handles all deprecations internally. Your assessment results are unchanged.

**Related**: [Deprecation Guide - For CLI Users](DEPRECATION_GUIDE.md#for-cli-users-no-action-needed)

### Use Case 2: Configuration File User

**Impact**: Moderate (2 flags to update)
**Time**: 5 minutes

**Steps**:

1. Find your config files with `mcpSpecCompliance` or `protocolConformance`
2. Replace with `protocolCompliance: true`
3. Run assessment to verify

**Example**:

```typescript
// Before
{
  assessmentCategories: {
    mcpSpecCompliance: true;
  }
}

// After
{
  assessmentCategories: {
    protocolCompliance: true;
  }
}
```

**Detailed Guide**: [Configuration Examples](DEPRECATION_MIGRATION_EXAMPLES.md#configuration-examples)

### Use Case 3: Direct Module Instantiation

**Impact**: High (4 module imports to update)
**Time**: 15 minutes

**Steps**:

1. Find all imports of deprecated modules
2. Replace with new modules (2 new imports cover 4 old ones)
3. Update instantiation code
4. Run tests to verify

**Example**:

```typescript
// Before
import { DocumentationAssessor, UsabilityAssessor } from "...";

// After
import { DeveloperExperienceAssessor } from "...";
```

**Detailed Guide**: [Module Migration Examples](DEPRECATION_MIGRATION_EXAMPLES.md#module-migration-examples)

### Use Case 4: Custom Assessor with Deprecated Methods

**Impact**: High (multiple method calls to update)
**Time**: 30 minutes

**Steps**:

1. Search for `this.log(` and `this.logError(` in your assessor code
2. Replace with `this.logger.info(` and `this.logger.error(`
3. Add structured context to all logging calls
4. Consider using `this.handleError()` for error cases
5. Run tests and verify logging output

**Example**:

```typescript
// Before
this.log("Assessment started");

// After
this.logger.info("Assessment started", {
  serverName: context.serverName,
  toolCount: context.tools.length,
});
```

**Detailed Guide**: [Custom Assessor Examples](DEPRECATION_MIGRATION_EXAMPLES.md#custom-assessor-examples)

## Timeline & Roadmap

### v1.25.2 (Current)

- Deprecation warnings active
- All deprecated code fully functional
- No breaking changes
- Recommended: Start planning migration

**Actions**:

- Read [Deprecation Guide](DEPRECATION_GUIDE.md)
- Review your codebase for deprecated usage
- Plan migration timeline

### v1.26.0+ (Estimated Q1 2026)

- Warnings continue
- No API changes
- Recommended: Complete migration

**Actions**:

- Update configuration files
- Update module imports
- Update custom assessor code
- Run full test suite

### v2.0.0 (Estimated Q2 2026)

- **Breaking changes**: Deprecated items removed
- Migration is mandatory
- Code using old APIs will fail at runtime

**Mandatory actions**:

- Complete all migrations
- Update all configuration files
- Update all imports
- Update all custom code
- Run full test suite

## Warning Messages Quick Reference

### Module Warnings

```
DocumentationAssessor is deprecated. Use DeveloperExperienceAssessor instead.
This module will be removed in v2.0.0.

UsabilityAssessor is deprecated. Use DeveloperExperienceAssessor instead.
This module will be removed in v2.0.0.

MCPSpecComplianceAssessor is deprecated. Use ProtocolComplianceAssessor instead.
This module will be removed in v2.0.0.

ProtocolConformanceAssessor is deprecated. Use ProtocolComplianceAssessor instead.
This module will be removed in v2.0.0.
```

### Config Flag Warnings

```
Config flag 'mcpSpecCompliance' is deprecated. Use 'protocolCompliance' instead.
This flag will be removed in v2.0.0.

Config flag 'protocolConformance' is deprecated. Use 'protocolCompliance' instead.
This flag will be removed in v2.0.0.
```

### Method Warnings

```
BaseAssessor.log() is deprecated. Use this.logger.info() instead.
This method will be removed in v2.0.0.

BaseAssessor.logError() is deprecated. Use this.logger.error() instead.
This method will be removed in v2.0.0.
```

**Full reference**: [DEPRECATION_API_REFERENCE.md#warning-message-formats](DEPRECATION_API_REFERENCE.md#warning-message-formats)

## FAQ

**Q: Do I need to update my code right now?**
A: Not immediately. Your code works through v1.x. We recommend updating at your convenience to prepare for v2.0.0.

**Q: Will the new APIs have different behavior?**
A: No. The new modules and APIs preserve all existing functionality. These are API improvements only.

**Q: How long is the transition period?**
A: Approximately 6 months. Warnings start in v1.25.2, removal in v2.0.0 (estimated Q2 2026).

**Q: Can I migrate gradually?**
A: Yes. You can mix old and new APIs during the transition period.

**Q: What happens if I don't migrate before v2.0.0?**
A: Code using deprecated APIs will fail at runtime with "not found" or similar errors. Migration is mandatory after v2.0.0.

**Complete FAQ**: [DEPRECATION_GUIDE.md#faq](DEPRECATION_GUIDE.md#faq)

## Related Documentation

- [Assessment Module Developer Guide](ASSESSMENT_MODULE_DEVELOPER_GUIDE.md) - Creating custom assessors
- [Logging Guide](LOGGING_GUIDE.md) - Detailed logging API documentation
- [CLI Assessment Guide](CLI_ASSESSMENT_GUIDE.md) - CLI usage guide
- [Programmatic API Guide](PROGRAMMATIC_API_GUIDE.md) - AssessmentOrchestrator usage

## Issue Reference

**GitHub Issue**: #35 - Deprecation Warning System Implementation
**Status**: Closed ✓
**Implemented**: v1.25.2

See [PROJECT_STATUS.md](../PROJECT_STATUS.md) for implementation details and status updates.

## Quick Navigation

### I want to...

- **Understand what's deprecated**: [DEPRECATION_GUIDE.md](DEPRECATION_GUIDE.md)
- **Understand why changes are happening**: [DEPRECATION_GUIDE.md#overview](DEPRECATION_GUIDE.md#overview)
- **See code examples for migration**: [DEPRECATION_MIGRATION_EXAMPLES.md](DEPRECATION_MIGRATION_EXAMPLES.md)
- **Understand the technical implementation**: [DEPRECATION_API_REFERENCE.md](DEPRECATION_API_REFERENCE.md)
- **Write tests for deprecations**: [DEPRECATION_API_REFERENCE.md#testing-deprecations](DEPRECATION_API_REFERENCE.md#testing-deprecations)
- **Set up CI/CD deprecation checks**: [DEPRECATION_API_REFERENCE.md#integration-with-cicd](DEPRECATION_API_REFERENCE.md#integration-with-cicd)
- **Track my migration progress**: [DEPRECATION_MIGRATION_EXAMPLES.md#migration-checklist](DEPRECATION_MIGRATION_EXAMPLES.md#migration-checklist)

---

## Document Statistics

| Document                                                               | Lines     | Size    | Focus                  |
| ---------------------------------------------------------------------- | --------- | ------- | ---------------------- |
| [DEPRECATION_GUIDE.md](DEPRECATION_GUIDE.md)                           | 875       | 28K     | User guide & timelines |
| [DEPRECATION_API_REFERENCE.md](DEPRECATION_API_REFERENCE.md)           | 846       | 24K     | Technical reference    |
| [DEPRECATION_MIGRATION_EXAMPLES.md](DEPRECATION_MIGRATION_EXAMPLES.md) | 954       | 28K     | Code examples          |
| **Total**                                                              | **2,675** | **80K** | Complete system        |

---

**Last Updated**: 2026-01-08
**Maintained By**: API Documentation Team
**Contact**: For questions, see [docs/README.md](README.md)
