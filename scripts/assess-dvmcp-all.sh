#!/bin/bash
#
# assess-dvmcp-all.sh - Run security assessment against all DVMCP challenges
#
# Damn Vulnerable MCP Server (DVMCP) validation script
# Tests all 10 challenges on ports 9001-9010
#
# Usage:
#   npm run assess:dvmcp
#   # or directly:
#   bash scripts/assess-dvmcp-all.sh
#
# Prerequisites:
#   - DVMCP Docker container running: docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp
#   - Config files created in /tmp/dvmcp-challenge-{1-10}-config.json
#

set -e

# Challenge names for readability
declare -A CHALLENGES=(
    [1]="Basic Prompt Injection"
    [2]="Tool Poisoning"
    [3]="Excessive Permission Scope"
    [4]="Rug Pull Attack"
    [5]="Tool Shadowing"
    [6]="Indirect Prompt Injection"
    [7]="Token Theft"
    [8]="Malicious Code Execution"
    [9]="Remote Access Control"
    [10]="Multi-Vector Attack"
)

# Expected patterns for each challenge
declare -A EXPECTED_PATTERNS=(
    [1]="Calculator Injection, Command Injection"
    [2]="Tool Shadowing"
    [3]="Permission Scope"
    [4]="Temporal (Rug Pull)"
    [5]="Tool Shadowing"
    [6]="Indirect Prompt Injection, SSRF"
    [7]="Token Theft"
    [8]="Command Injection, Insecure Deserialization"
    [9]="Command Injection, SSRF"
    [10]="All Patterns"
)

echo "=========================================="
echo "DVMCP Security Assessment - All Challenges"
echo "=========================================="
echo ""

# Check if DVMCP is running (use HTTP status code for reliable detection)
http_status=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9001/sse -m 2 2>/dev/null || echo "000")
if [ "$http_status" != "200" ]; then
    echo "ERROR: DVMCP does not appear to be running on localhost:9001 (HTTP status: $http_status)"
    echo "Start it with: docker run -d -p 9001-9010:9001-9010 --name dvmcp dvmcp"
    exit 1
fi

echo "DVMCP server detected. Starting assessments..."
echo ""

# Create config files if they don't exist
for i in {1..10}; do
    config_file="/tmp/dvmcp-challenge-$i-config.json"
    if [ ! -f "$config_file" ]; then
        echo "{\"transport\": \"sse\", \"url\": \"http://localhost:$((9000 + i))/sse\"}" > "$config_file"
    fi
done

# Summary arrays
declare -a RESULTS
declare -a VULN_COUNTS

# Run assessment for each challenge
for i in {1..10}; do
    echo "=== Challenge $i: ${CHALLENGES[$i]} ==="
    echo "Expected Patterns: ${EXPECTED_PATTERNS[$i]}"
    echo ""

    config_file="/tmp/dvmcp-challenge-$i-config.json"
    output_file="/tmp/inspector-assessment-dvmcp-challenge-$i.json"

    # Run assessment
    if npm run assess -- --server "dvmcp-challenge-$i" --config "$config_file" 2>&1 | tail -5; then
        # Extract vulnerability count from output
        if [ -f "$output_file" ]; then
            vuln_count=$(jq '.security.vulnerabilities | length' "$output_file" 2>/dev/null || echo "0")
            VULN_COUNTS[$i]=$vuln_count
            if [ "$vuln_count" -gt 0 ]; then
                RESULTS[$i]="DETECTED ($vuln_count vulnerabilities)"
                echo "Result: $vuln_count vulnerabilities detected"
            else
                RESULTS[$i]="CLEAN (0 vulnerabilities)"
                echo "Result: No vulnerabilities detected"
            fi
        else
            RESULTS[$i]="ERROR (no output file)"
            VULN_COUNTS[$i]=0
        fi
    else
        RESULTS[$i]="FAILED (assessment error)"
        VULN_COUNTS[$i]=0
    fi

    echo ""
done

# Print summary
echo "=========================================="
echo "DVMCP Assessment Summary"
echo "=========================================="
echo ""
printf "%-10s %-35s %-25s %s\n" "Challenge" "Name" "Result" "Expected Pattern"
echo "---------------------------------------------------------------------------------------------"
for i in {1..10}; do
    printf "%-10s %-35s %-25s %s\n" "$i" "${CHALLENGES[$i]}" "${RESULTS[$i]}" "${EXPECTED_PATTERNS[$i]}"
done
echo ""

# Calculate total vulnerabilities
total_vulns=0
for count in "${VULN_COUNTS[@]}"; do
    total_vulns=$((total_vulns + count))
done

echo "Total vulnerabilities detected across all challenges: $total_vulns"
echo ""
echo "Assessment results saved to /tmp/inspector-assessment-dvmcp-challenge-{1-10}.json"
