#!/usr/bin/env bash
set -euo pipefail

echo "================================================================================"
echo "SHADOW-GRAPH // AUTOMATED ZERO-LEAK & STATIC SECURITY AUDIT GATE"
echo "================================================================================"

TRACKED_FILES=$(git ls-files | grep -vE '^(scripts/security-audit\.sh|tests/security/leak-scanner\.test\.ts)$' || true)

if [ -z "$TRACKED_FILES" ]; then
  echo "[WARN] No git tracked files yet; scanning working tree files instead..."
  TRACKED_FILES=$(find . -maxdepth 3 -type f \
    -not -path '*/.*' \
    -not -path './node_modules/*' \
    -not -path './dist/*' \
    -not -path './scripts/security-audit.sh' \
    -not -path './tests/security/leak-scanner.test.ts')
fi

LEAK_FOUND=0

check_pattern() {
  local label="$1"
  local pattern="$2"
  local target_files="$3"
  if [ -n "$target_files" ] && echo "$target_files" | xargs grep -nE "$pattern" 2>/dev/null; then
    echo "[FAIL] Security Violation: Detected $label"
    LEAK_FOUND=1
  else
    echo "[PASS] Zero occurrences of: $label"
  fi
}

check_pattern "Local Linux Home Paths" "/home/[a-zA-Z0-9_-]+" "$TRACKED_FILES"
check_pattern "Local macOS User Paths" "/Users/[a-zA-Z0-9_-]+" "$TRACKED_FILES"
check_pattern "Local Windows User Paths" "C:\\\\Users\\\\[a-zA-Z0-9_-]+" "$TRACKED_FILES"
check_pattern "Hardcoded Secret Tokens (ghp_ / sk- / vercel_)" "(ghp_[a-zA-Z0-9]{20,}|sk-[a-zA-Z0-9]{20,}|vercel_[a-zA-Z0-9]{20,})" "$TRACKED_FILES"

SRC_FILES=$(echo "$TRACKED_FILES" | grep -E '^src/.*\.ts$' || true)
check_pattern "Unsafe Buffer Allocation (Buffer.allocUnsafe)" "Buffer\.allocUnsafe" "$SRC_FILES"
check_pattern "Dynamic Code Execution (eval / new Function)" "(\beval\s*\(|new\s+Function\s*\()" "$SRC_FILES"

if [ "$LEAK_FOUND" -ne 0 ]; then
  echo "================================================================================"
  echo "AUDIT FAILED: Fix the security or privacy violations listed above."
  echo "================================================================================"
  exit 1
fi

echo "================================================================================"
echo "AUDIT PASSED: Zero PII, path leaks, or unsafe sinks detected."
echo "================================================================================"
