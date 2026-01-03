# JSONL Events API

> **Note**: This guide has been split into focused documents for easier navigation.

## Quick Links

- [JSONL Events Reference](JSONL_EVENTS_REFERENCE.md) - All 11 event types and schema definitions
- [JSONL Events Algorithms](JSONL_EVENTS_ALGORITHMS.md) - EventBatcher and AUP enrichment algorithms
- [JSONL Events Integration](JSONL_EVENTS_INTEGRATION.md) - Lifecycle examples, integration checklist, testing, FAQ

## Overview

The MCP Inspector emits structured JSONL events to stderr during assessment, enabling real-time progress tracking and integration with external tools like MCP Auditor.

**Event Types:**

| Event                      | Purpose                     |
| -------------------------- | --------------------------- |
| `server_connected`         | Connection established      |
| `tool_discovered`          | Tool found during discovery |
| `tools_discovery_complete` | All tools enumerated        |
| `module_started`           | Assessment module beginning |
| `test_batch`               | Progress update             |
| `vulnerability_found`      | Security issue detected     |
| `annotation_*`             | Tool annotation issues      |
| `module_complete`          | Module finished             |
| `assessment_complete`      | Full assessment done        |

---

_For the complete documentation index, see [docs/README.md](README.md)._
