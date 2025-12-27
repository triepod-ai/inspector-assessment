#!/bin/bash
# Upstream Sync Helper for inspector-assessment
# See UPSTREAM_SYNC.md for integration point documentation
#
# Usage:
#   ./scripts/sync-upstream.sh [command]
#
# Commands:
#   status     - Show current sync status and divergence
#   diff       - Fetch upstream and show App.tsx changes
#   merge      - Attempt merge with upstream/main
#   validate   - Run build and tests
#   full       - Run all steps (default)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
UPSTREAM_REMOTE="upstream"
UPSTREAM_BRANCH="main"
APP_TSX="client/src/App.tsx"
SYNC_DOC="UPSTREAM_SYNC.md"

# Integration line ranges from UPSTREAM_SYNC.md
# These are the lines we modify for assessment integration
declare -a INTEGRATION_RANGES=(
    "59:59:Import ClipboardCheck icon"
    "75:75:Import AssessmentTab component"
    "129:129:isLoadingTools state declaration"
    "372:372:assessment tab in availableTabs array"
    "1024:1036:Auto-load tools when assessment tab selected"
    "1061:1067:TabsTrigger for assessment"
    "1236:1249:AssessmentTab component render"
)

# ============================================================================
# Helper Functions
# ============================================================================

print_header() {
    echo -e "\n${BOLD}${BLUE}=== $1 ===${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# ============================================================================
# Check Prerequisites
# ============================================================================

check_prerequisites() {
    # Check we're in the repo root
    if [ ! -f "package.json" ] || [ ! -f "$SYNC_DOC" ]; then
        print_error "Must run from repository root (where package.json and UPSTREAM_SYNC.md exist)"
        exit 1
    fi

    # Check upstream remote exists
    if ! git remote get-url "$UPSTREAM_REMOTE" &>/dev/null; then
        print_error "Upstream remote '$UPSTREAM_REMOTE' not found"
        print_info "Add it with: git remote add upstream https://github.com/modelcontextprotocol/inspector.git"
        exit 1
    fi

    # Check for clean working directory (for merge operations)
    if [ "$1" == "merge" ] || [ "$1" == "full" ]; then
        if [ -n "$(git status --porcelain)" ]; then
            print_warning "Working directory has uncommitted changes"
            print_info "Consider committing or stashing changes before merge"
        fi
    fi
}

# ============================================================================
# Status Command
# ============================================================================

show_status() {
    print_header "Sync Status"

    # Current branch
    local current_branch=$(git branch --show-current)
    echo -e "Current branch: ${BOLD}$current_branch${NC}"

    # Get last sync info from UPSTREAM_SYNC.md (table format: | **Field** | Value |)
    local last_version=$(grep "Last Sync Version" "$SYNC_DOC" | awk -F'|' '{print $3}' | tr -d ' ')
    local last_date=$(grep "Last Sync Date" "$SYNC_DOC" | awk -F'|' '{print $3}' | tr -d ' ')
    local last_commit=$(grep "Last Sync Commit" "$SYNC_DOC" | sed 's/.*`\([^`]*\)`.*/\1/')

    echo -e "Last sync: ${BOLD}$last_version${NC} ($last_date)"
    echo -e "Sync commit: ${CYAN}$last_commit${NC}"

    # Fetch to get latest upstream info
    print_info "Fetching upstream..."
    git fetch "$UPSTREAM_REMOTE" --quiet

    # Get upstream HEAD
    local upstream_head=$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")
    local upstream_short="${upstream_head:0:7}"

    echo -e "\nUpstream HEAD: ${CYAN}$upstream_short${NC}"

    # Check if we're behind
    local behind=$(git rev-list --count HEAD.."$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" 2>/dev/null || echo "0")
    local ahead=$(git rev-list --count "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH"..HEAD 2>/dev/null || echo "0")

    if [ "$behind" -eq 0 ]; then
        print_success "Up to date with upstream"
    else
        print_warning "Behind upstream by $behind commit(s)"
        print_info "Ahead of upstream by $ahead commit(s) (our enhancements)"
    fi

    # Show integration points
    echo -e "\n${BOLD}Integration Points in App.tsx:${NC}"
    for range in "${INTEGRATION_RANGES[@]}"; do
        IFS=':' read -r start end desc <<< "$range"
        echo -e "  Lines $start-$end: $desc"
    done
}

# ============================================================================
# Diff Command
# ============================================================================

fetch_and_diff() {
    print_header "Upstream Changes to App.tsx"

    # Fetch upstream
    print_info "Fetching upstream..."
    git fetch "$UPSTREAM_REMOTE" --quiet

    # Get the last sync commit from UPSTREAM_SYNC.md
    local last_commit=$(grep "Last Sync Commit" "$SYNC_DOC" | sed 's/.*`\([^`]*\)`.*/\1/')

    echo -e "Comparing: ${CYAN}$last_commit${NC} → ${CYAN}$UPSTREAM_REMOTE/$UPSTREAM_BRANCH${NC}\n"

    # Check if App.tsx has changed
    local changes=$(git diff "$last_commit".."$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" -- "$APP_TSX" 2>/dev/null || echo "")

    if [ -z "$changes" ]; then
        print_success "No changes to App.tsx since last sync"
        return 0
    fi

    # Show the diff
    echo -e "${BOLD}Changes to $APP_TSX:${NC}\n"
    git diff "$last_commit".."$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" -- "$APP_TSX" | head -100

    # Check if integration lines are affected
    check_integration_conflicts "$last_commit"
}

check_integration_conflicts() {
    local last_commit="$1"

    print_header "Integration Line Analysis"

    # Get the diff with line numbers
    local diff_output=$(git diff "$last_commit".."$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" -- "$APP_TSX" 2>/dev/null || echo "")

    if [ -z "$diff_output" ]; then
        print_success "No conflicts with integration lines"
        return 0
    fi

    local conflicts_found=0

    for range in "${INTEGRATION_RANGES[@]}"; do
        IFS=':' read -r start end desc <<< "$range"

        # Check if any lines in this range appear in the diff
        # Look for @@ -X,Y +A,B @@ patterns that overlap our ranges
        if echo "$diff_output" | grep -E "^@@.*@@" | while read -r hunk; do
            # Extract line numbers from hunk header
            local old_start=$(echo "$hunk" | sed 's/^@@ -\([0-9]*\).*/\1/')
            local old_count=$(echo "$hunk" | sed 's/^@@ -[0-9]*,\([0-9]*\).*/\1/' | grep -E '^[0-9]+$' || echo "1")
            local old_end=$((old_start + old_count))

            # Check for overlap with our integration range
            if [ "$old_start" -le "$end" ] && [ "$old_end" -ge "$start" ]; then
                return 0  # Found overlap
            fi
        done; then
            print_warning "Lines $start-$end may be affected: $desc"
            conflicts_found=1
        fi
    done

    if [ "$conflicts_found" -eq 0 ]; then
        print_success "Integration lines appear unaffected"
    else
        echo -e "\n${YELLOW}Manual review recommended for affected lines${NC}"
        print_info "See UPSTREAM_SYNC.md for integration point details"
    fi
}

# ============================================================================
# Merge Command
# ============================================================================

do_merge() {
    print_header "Merge Upstream"

    # Fetch first
    print_info "Fetching upstream..."
    git fetch "$UPSTREAM_REMOTE" --quiet

    # Check for uncommitted changes
    if [ -n "$(git status --porcelain)" ]; then
        print_error "Working directory has uncommitted changes"
        print_info "Please commit or stash changes before merging"
        exit 1
    fi

    # Attempt merge
    print_info "Attempting merge with $UPSTREAM_REMOTE/$UPSTREAM_BRANCH..."

    if git merge "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH" --no-edit; then
        print_success "Merge completed successfully!"
    else
        print_error "Merge conflicts detected"
        echo -e "\n${BOLD}Conflict Resolution Guide:${NC}"
        echo -e "1. Check if conflicts are in $APP_TSX"
        echo -e "2. If so, refer to UPSTREAM_SYNC.md for integration points"
        echo -e "3. Keep our integration code (marked with [ASSESSMENT-INTEGRATION])"
        echo -e "4. Accept upstream changes elsewhere"
        echo -e "5. Run: git add . && git commit"
        echo -e "6. Then run: ./scripts/sync-upstream.sh validate"
        exit 1
    fi
}

# ============================================================================
# Validate Command
# ============================================================================

validate_build() {
    print_header "Build Validation"

    # Run build
    print_info "Running npm build..."
    if npm run build; then
        print_success "Build passed"
    else
        print_error "Build failed"
        exit 1
    fi

    # Run tests
    print_info "Running tests..."
    if npm test; then
        print_success "Tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi

    print_success "Validation complete!"

    # Prompt to update sync doc
    update_sync_doc
}

# ============================================================================
# Update Sync Doc
# ============================================================================

update_sync_doc() {
    print_header "Update UPSTREAM_SYNC.md"

    local upstream_head=$(git rev-parse "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH")
    local upstream_short="${upstream_head:0:7}"
    local today=$(date +%Y-%m-%d)

    # Try to get version from upstream
    local upstream_version=$(git show "$UPSTREAM_REMOTE/$UPSTREAM_BRANCH:package.json" 2>/dev/null | grep '"version"' | head -1 | sed 's/.*: *"//' | sed 's/".*//' || echo "unknown")

    echo -e "Update UPSTREAM_SYNC.md with:"
    echo -e "  Version: ${BOLD}$upstream_version${NC}"
    echo -e "  Date: ${BOLD}$today${NC}"
    echo -e "  Commit: ${CYAN}$upstream_head${NC}"

    echo -e "\n${YELLOW}Please update UPSTREAM_SYNC.md manually with these values${NC}"
    echo -e "Lines to update:"
    echo -e "  | **Last Sync Version**   | v$upstream_version"
    echo -e "  | **Last Sync Date**      | $today"
    echo -e "  | **Last Sync Commit**    | \`$upstream_head\`"
}

# ============================================================================
# Full Sync
# ============================================================================

full_sync() {
    show_status
    fetch_and_diff

    echo -e "\n${BOLD}${YELLOW}Ready to merge?${NC}"
    echo -e "Review the changes above. If ready, run:"
    echo -e "  ${CYAN}./scripts/sync-upstream.sh merge${NC}"
    echo -e "\nAfter merge, validate with:"
    echo -e "  ${CYAN}./scripts/sync-upstream.sh validate${NC}"
}

# ============================================================================
# Main
# ============================================================================

main() {
    local command="${1:-full}"

    check_prerequisites "$command"

    case "$command" in
        status)
            show_status
            ;;
        diff)
            fetch_and_diff
            ;;
        merge)
            do_merge
            ;;
        validate)
            validate_build
            ;;
        full)
            full_sync
            ;;
        help|--help|-h)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  status     Show current sync status and divergence"
            echo "  diff       Fetch upstream and show App.tsx changes"
            echo "  merge      Attempt merge with upstream/main"
            echo "  validate   Run build and tests after merge"
            echo "  full       Run status + diff (default)"
            echo ""
            echo "Typical workflow:"
            echo "  1. ./scripts/sync-upstream.sh         # Check status and diff"
            echo "  2. ./scripts/sync-upstream.sh merge   # Merge upstream"
            echo "  3. ./scripts/sync-upstream.sh validate # Build and test"
            echo ""
            echo "See UPSTREAM_SYNC.md for integration point documentation."
            ;;
        *)
            print_error "Unknown command: $command"
            echo "Run '$0 help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
