#!/usr/bin/env bash
#
# Update EMQ copyright headers to a target year (default 2026).
#
#   "Copyright (c) 2021-2024 EMQ ..."  ->  "Copyright (c) 2021-2026 EMQ ..."
#   "Copyright (c) 2024 EMQ ..."       ->  "Copyright (c) 2024-2026 EMQ ..."
#
# Only the END year is moved forward (the original/start year is preserved),
# and a single year becomes a range. The script is idempotent: a header that
# already ends at >= the target year is left unchanged, so re-running it next
# year is safe.
#
# Usage:
#   tools/update-copyright-year.sh [YEAR] [--dry-run]
#
#   tools/update-copyright-year.sh             # bump to 2026
#   tools/update-copyright-year.sh 2027        # bump to 2027
#   tools/update-copyright-year.sh --dry-run   # show what would change
#
# Scope: tracked *.c *.h *.erl *.hrl files (msquic/ is gitignored and keeps its
# own Microsoft headers, so it is never touched).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
cd "$REPO_ROOT"

YEAR=2026
DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run|-n) DRY_RUN=1 ;;
        [0-9][0-9][0-9][0-9]) YEAR="$arg" ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown arg '$arg'" >&2; exit 2 ;;
    esac
done

HOLDER='EMQ Technologies'
PATTERN="Copyright \(c\) [0-9]{4}(-[0-9]{4})? ${HOLDER}"

# Tracked source files that carry an EMQ copyright line.
# (read loop instead of mapfile for portability with bash 3.2 / macOS)
files=()
while IFS= read -r f; do
    [ -n "$f" ] && files+=("$f")
done < <(git grep -lE "$PATTERN" -- '*.c' '*.h' '*.erl' '*.hrl' || true)

if [ ${#files[@]} -eq 0 ]; then
    echo "No matching copyright headers found."
    exit 0
fi

# Perl program shared by dry-run and apply. Reads $ENV{YEAR} and $ENV{HOLDER}.
read -r -d '' PROG <<'PERL' || true
my $y = $ENV{YEAR};
s{Copyright \(c\) (\d{4})(?:-(\d{4}))? ($ENV{HOLDER})}{
    my ($start, $end, $who) = ($1, $2, $3);
    my $newend = defined $end ? $end : $start;
    $newend = $y if $newend < $y;
    ($start == $newend)
        ? "Copyright (c) $start $who"
        : "Copyright (c) $start-$newend $who";
}ge;
PERL

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

changed=0
for f in "${files[@]}"; do
    YEAR="$YEAR" HOLDER="$HOLDER" perl -pe "$PROG" "$f" > "$tmp"
    if diff -q "$f" "$tmp" >/dev/null 2>&1; then
        continue   # no change for this file
    fi
    changed=$((changed + 1))
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "would update: $f"
        diff "$f" "$tmp" | grep -E '^[<>]' || true
    else
        cat "$tmp" > "$f"
        echo "updated: $f"
    fi
done

if [ "$DRY_RUN" -eq 1 ]; then
    echo "--- dry run: $changed file(s) would change (target year $YEAR) ---"
else
    echo "--- done: $changed file(s) updated to $YEAR ---"
fi
