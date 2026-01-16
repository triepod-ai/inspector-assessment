# Code Review Cache

This directory contains cached code review results from `/review-my-code`.

**DO NOT COMMIT** - This directory should be in `.gitignore`.

## How it works

- Cache stores Stage 1 (code-reviewer-pro) output per file
- Files are keyed by path + SHA-256 content hash
- When file content changes, cache is automatically invalidated
- Separate cache entries for different models (opus vs haiku) and modes (full vs quick)

## Commands

```bash
# View cache statistics
python3 /home/bryan/triepod-ai-mcp-audit/.claude/helpers/review-cache.py status

# Clear all cached data
python3 /home/bryan/triepod-ai-mcp-audit/.claude/helpers/review-cache.py clear

# Remove entries unused for 30+ days
python3 /home/bryan/triepod-ai-mcp-audit/.claude/helpers/review-cache.py prune

# Remove entries unused for 7 days
python3 /home/bryan/triepod-ai-mcp-audit/.claude/helpers/review-cache.py prune 7
```

## Flags in /review-my-code

- `--no-cache`: Bypass cache for this run (force fresh review)
- `--clear-cache`: Clear cache and exit
