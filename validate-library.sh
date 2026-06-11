#!/usr/bin/env bash
# validate-library.sh - integrity guardrail for the SPL hunting library.
# Mandated by tri-agent consensus (2026-06-11). Run before every commit / after every add.
#
# Checks (deterministic, no SPL semantics):
#   1. Every leaf .md is listed exactly once in its folder README.md
#   2. No broken relative markdown links across the tree
#   3. Each leaf has at least one typed section header (Primary detection /
#      Follow-up enrichment / Statistical variant / Detection / Pivot)
#   4. No leaf exceeds the max ```spl fence cap (prevents leaf accretion)
#   5. No hardcoded leftovers (placeholders only)
#
# Exit non-zero on any failure.

set -uo pipefail
cd "$(dirname "$0")" || exit 2

MAX_SPL_FENCES=4
FAIL=0
err() { echo "FAIL: $*" >&2; FAIL=1; }

# Folders to scan (phase + meta). README/CONTRIBUTING/validator are not leaves.
mapfile -t FOLDERS < <(find . -mindepth 1 -maxdepth 1 -type d | sort)

# --- 1 + 3 + 4: per-leaf checks, and presence in folder README ---
for dir in "${FOLDERS[@]}"; do
  readme="$dir/README.md"
  [ -f "$readme" ] || { err "missing folder index: $readme"; continue; }
  for leaf in "$dir"/*.md; do
    base="$(basename "$leaf")"
    [ "$base" = "README.md" ] && continue

    # (1) listed exactly once in folder README
    count=$(grep -c -- "$base" "$readme")
    [ "$count" -eq 1 ] || err "$base listed $count times in $readme (want exactly 1)"

    # (3) at least one typed section header
    if ! grep -qiE '^#{1,4}.*(Primary detection|Follow-up enrichment|Statistical variant|Detection|Pivot|Technique|Principle|Use when)' "$leaf"; then
      err "$leaf has no typed section header"
    fi

    # (4) spl fence cap
    fences=$(grep -c '^```spl' "$leaf")
    [ "$fences" -le "$MAX_SPL_FENCES" ] || err "$leaf has $fences \`\`\`spl blocks (max $MAX_SPL_FENCES) - split it"
  done
done

# --- 2: broken relative markdown links ---
# Match [text](path) where path is relative (no http, no #anchor-only).
while IFS= read -r md; do
  grep -oE '\]\(([^)]+)\)' "$md" | sed -E 's/^\]\(//; s/\)$//' | while IFS= read -r link; do
    case "$link" in
      http*|\#*|mailto:*) continue ;;
    esac
    target="${link%%#*}"
    [ -z "$target" ] && continue
    resolved="$(dirname "$md")/$target"
    [ -e "$resolved" ] || err "broken link in $md -> $link"
  done
done < <(find . -name '*.md')

# --- 5: hardcoded leftovers (should all be <placeholders>) ---
if grep -rEn '10\.0\.0\.[0-9]|DESKTOP-[A-Z0-9]|\bwaldo\b' --include='*.md' . >/dev/null 2>&1; then
  grep -rEn '10\.0\.0\.[0-9]|DESKTOP-[A-Z0-9]|\bwaldo\b' --include='*.md' . >&2
  err "hardcoded environment values found - replace with <placeholders>"
fi

if [ "$FAIL" -eq 0 ]; then
  echo "OK: library integrity checks passed"
fi
exit "$FAIL"
