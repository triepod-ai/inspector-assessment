# Fork History & Upstream Relationship

This document describes the relationship between MCP Inspector Assessment and the original Anthropic MCP Inspector.

---

## About This Fork

MCP Inspector Assessment is an enhanced fork of [Anthropic's MCP Inspector](https://github.com/modelcontextprotocol/inspector) with significantly expanded assessment capabilities for MCP server validation and testing.

| Repository      | URL                                                                                                        |
| --------------- | ---------------------------------------------------------------------------------------------------------- |
| **Original**    | https://github.com/modelcontextprotocol/inspector                                                          |
| **This Fork**   | https://github.com/triepod-ai/inspector-assessment                                                         |
| **npm Package** | [@bryan-thompson/inspector-assessment](https://www.npmjs.com/package/@bryan-thompson/inspector-assessment) |

**Important**: This is a published fork with assessment enhancements. If you want the official Anthropic inspector without assessment features, use:

```bash
npx @modelcontextprotocol/inspector
```

---

## What We Added

We've built a comprehensive assessment framework on top of the original inspector that transforms it from a debugging tool into a full validation suite for MCP servers. Our enhancements focus on:

- **17 Assessment Modules** - Automated validation covering functionality, security, documentation, compliance, and more
- **Pure Behavior-Based Detection** - Security testing that analyzes tool responses, not tool names
- **Zero False Positives** - Context-aware reflection detection distinguishes data handling from code execution
- **MCP Directory Compliance** - Policy checking for Anthropic's MCP Directory requirements
- **CLI-First Workflow** - Three CLI commands for different assessment scenarios

For detailed information about our enhancements, see the [main README](../README.md).

---

## Upstream Sync Status

| Field                        | Value      |
| ---------------------------- | ---------- |
| **Current Upstream Version** | 0.18.0     |
| **Last Sync Date**           | 2025-12-23 |
| **Commits Integrated**       | 121+       |

### Recent Upstream Features Integrated

- Custom Headers support
- OAuth improvements
- Parameter validation enhancements
- DNS rebinding protection
- Proxy authentication (CVE-2025-49596 fix)

---

## Sync Procedure

For detailed upstream sync workflow, see [UPSTREAM_SYNC_WORKFLOW.md](UPSTREAM_SYNC_WORKFLOW.md).

### Quick Reference

```bash
# Check sync status
./scripts/sync-upstream.sh status

# View upstream changes
./scripts/sync-upstream.sh diff

# Attempt merge
./scripts/sync-upstream.sh merge

# Validate after merge
./scripts/sync-upstream.sh validate
```

---

## Architecture Notes

Assessment functionality is **CLI-only** (since v1.23.0):

- **No UI integration points** - Assessment Tab UI was deprecated
- **CLI tools**: `mcp-assess-full` and `mcp-assess-security` are the primary interfaces
- **~160k lines** of assessment code in dedicated directories (no upstream conflicts)
- **npm package**: Assessment modules exported for programmatic use

This architecture minimizes merge conflicts during upstream syncs.

---

## Migration Path

If Anthropic adopts this package, it can be migrated to `@modelcontextprotocol/inspector-assessment`:

1. Update all package.json names
2. Publish to new namespace
3. Deprecate old packages with migration notice

---

## Acknowledgments

This project builds upon the excellent foundation provided by Anthropic's MCP Inspector team. We're grateful for their work on the original inspector and the MCP protocol specification.

---

## Related Documentation

- **Main README**: [../README.md](../README.md) - Assessment capabilities overview
- **Base Inspector Guide**: [BASE_INSPECTOR_GUIDE.md](BASE_INSPECTOR_GUIDE.md) - UI and operational features
- **Upstream Sync Workflow**: [UPSTREAM_SYNC_WORKFLOW.md](UPSTREAM_SYNC_WORKFLOW.md) - Detailed sync procedure
- **Changelog**: [../CHANGELOG.md](../CHANGELOG.md) - Release history
