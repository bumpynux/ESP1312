#!/bin/sh
# Pre-publish leak guard. Exits non-zero if tracked files contain data dumps,
# GPS coordinates, or any pattern listed in the untracked scripts/.pii-local.
# Run by hand (sh scripts/check.sh) or from a pre-push hook.
set -eu
cd "$(git rev-parse --show-toplevel)"
fail=0
flag() { echo "LEAK: $1"; fail=1; }
scan() { git grep -nIE "$1" -- ':!scripts/check.sh' 2>/dev/null; }

# Data files belong in the gitignored logs/, never in the repo.
if git ls-files '*.csv' '*.bin' '*.log' | grep -q .; then
  flag "tracked data files:"; git ls-files '*.csv' '*.bin' '*.log'
fi

# GPS coordinate pairs (decimal degrees, 4+ places).
if scan '\-?[0-9]{1,3}\.[0-9]{4,},[ ]*\-?[0-9]{1,3}\.[0-9]{4,}'; then
  flag "possible GPS coordinates above"
fi

# Private patterns you keep local (city, names, emails, dates, ...), one regex per line.
if [ -f scripts/.pii-local ]; then
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$p" in \#*) continue ;; esac
    scan "$p" && flag "matched private pattern above"
  done < scripts/.pii-local
fi

[ "$fail" -eq 0 ] && { echo "leak check passed"; exit 0; }
echo "LEAK CHECK FAILED, resolve the above before pushing."; exit 1
