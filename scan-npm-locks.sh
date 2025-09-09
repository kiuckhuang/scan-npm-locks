#!/usr/bin/env sh
# scan-npm-locks.sh
# Recursively scan npm/yarn/pnpm lockfiles for compromised package@version pairs.
# Exact-match detection + warnings when the package is present at a different version.
# Optional remediation, overrides printing, and heuristic dist/ bundle scan.
#
# Usage:
#   ./scan-npm-locks.sh [DIRECTORY] [--fix] [--print-overrides] [--list FILE] [--scan-dist [DIR]]
#
# Exit codes:
#   0  = no compromised versions found and no warnings
#   8  = warnings only (package present at different version)
#   10 = exact compromised version(s) found
#   2  = bad usage
#
# Requires: POSIX sh + find/awk/grep/sort/sed. jq recommended for package-lock.json parsing.

set -eu

# ---------- CLI ----------
DIR="."
FIX=0
PRINT_OVERRIDES=0
LIST_FILE=""
SCAN_DIST=0
DIST_DIR="dist"

while [ $# -gt 0 ]; do
  case "$1" in
    --fix) FIX=1 ;;
    --print-overrides) PRINT_OVERRIDES=1 ;;
    --list) LIST_FILE="${2-}"; shift ;;
    --scan-dist)
      SCAN_DIST=1
      if [ "${2-}" ] && [ "${2#-}" = "$2" ]; then
        DIST_DIR="$2"; shift
      fi
      ;;
    -h|--help)
      echo "Usage: $0 [DIRECTORY] [--fix] [--print-overrides] [--list FILE] [--scan-dist [DIR]]"
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      echo "Usage: $0 [DIRECTORY] [--fix] [--print-overrides] [--list FILE] [--scan-dist [DIR]]" >&2
      exit 2
      ;;
    *)
      DIR="$1"
      ;;
  esac
  shift
done

exists() { command -v "$1" >/dev/null 2>&1; }
log() { printf '%s\n' "$*"; }
hr() { log "----------------------------------------"; }

# ---------- Embedded default list (you can override with --list FILE) ----------
EMBEDDED_LIST="$(cat <<'EOF'
ansi-regex@6.2.1
ansi-styles@6.2.2
backslash@0.2.1
chalk@5.6.1
chalk-template@1.1.1
color-convert@3.1.1
color-name@2.0.1
color-string@2.1.1
debug@4.4.2
error-ex@1.3.3
has-ansi@6.0.1
is-arrayish@0.3.3
simple-swizzle@0.2.3
slice-ansi@7.1.1
strip-ansi@7.1.1
supports-color@10.2.1
supports-hyperlinks@4.1.1
wrap-ansi@9.0.1
EOF
)"

# ---------- Load & normalize list ----------
LIST_TMP="$(mktemp 2>/dev/null || mktemp -t tmp)"
: >"$LIST_TMP"
if [ -n "$LIST_FILE" ]; then
  if [ ! -f "$LIST_FILE" ]; then
    echo "List file not found: $LIST_FILE" >&2
    exit 2
  fi
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    { gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0); print $0 }
  ' "$LIST_FILE" >>"$LIST_TMP"
else
  printf '%s\n' "$EMBEDDED_LIST" >>"$LIST_TMP"
fi

SORTED_LIST_TMP="$(mktemp 2>/dev/null || mktemp -t tmp)"
: >"$SORTED_LIST_TMP"
awk -F'@' 'NF==2 && $1!="" && $2!="" {print $1 "@" $2}' "$LIST_TMP" | sort -u > "$SORTED_LIST_TMP"
rm -f "$LIST_TMP"

# ---------- Find lockfiles ----------
log "🔍 Scanning for lockfiles under: $DIR"
LOCKFILES=$(find "$DIR" -type f \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' -o -name 'pnpm-lock.yml' \) 2>/dev/null || true)

if [ -z "${LOCKFILES:-}" ]; then
  log "❌ No lockfiles found."
  [ $PRINT_OVERRIDES -eq 1 ] && log "Note: You can still use --print-overrides to output blocks."
  if [ $SCAN_DIST -eq 1 ]; then
    hr; log "🔎 Running heuristic bundle scan (no lockfiles found)…"
  else
    exit 0
  fi
fi

FOUND_ANY=0   # exact compromised version(s) found
WARN_ANY=0    # package present but different version
AFFECTED_DIRS_TMP="$(mktemp 2>/dev/null || mktemp -t tmp)"
: >"$AFFECTED_DIRS_TMP"

# ---------- Helpers ----------
# npm package-lock.json → emit "name<TAB>version" (unique) using jq
# --- BEGIN REPLACEMENT: npm_versions_to_tmp ---
npm_versions_to_tmp() {
  lf="$1"; out="$2"

  if ! command -v jq >/dev/null 2>&1; then
    echo "❌ jq is required to parse package-lock.json (please install jq). File: $lf" >&2
    : >"$out"
    return 1
  fi

  jq -r '
    # take the substring after the LAST "node_modules/" and turn it into a package name
    def key_to_name(k):
      if k == "" then empty else
        ((k | split("node_modules/")) | .[length-1]) as $rest
        | ($rest | split("/")) as $p
        | if ($p[0] | startswith("@")) then
            ($p[0] + "/" + ($p[1] // ""))
          else
            $p[0]
          end
      end;

    def walkdeps(d):                                # npm v1 recursive deps
      (d // {}) | to_entries[]? as $e
      | ($e.key) as $name
      | ($e.value.version // empty) as $ver
      | (if ($ver|length)>0 then [$name,$ver]|@tsv else empty end),
        walkdeps($e.value.dependencies);

    if has("packages") then                         # npm v2/v3
      .packages
      | to_entries[]
      | ( .value.name // key_to_name(.key) ) as $name
      | (.value.version // empty) as $ver
      | select(($name|type=="string") and ($name|length>0) and ($ver|length>0))
      | [$name,$ver] | @tsv
    else                                            # npm v1
      walkdeps(.dependencies)
    end
  ' "$lf" | sort -u >"$out"
}
# --- END REPLACEMENT ---
# yarn.lock → for a given pkg, print all resolved versions (unique)
yarn_versions_for_pkg() {
  lf="$1"; pkg="$2"
  awk -v P="$pkg" '
    /^[^[:space:]].*:\s*$/ { header=$0; next }
    /^[[:space:]]*version "[^"]+"\s*$/ {
      ver=$2; gsub(/"/,"",ver);
      if (header ~ (P "@")) print ver;
    }
  ' "$lf" | sort -u
}

# pnpm-lock.yaml → for a given pkg, print versions based on "/pkg@<ver>:" keys
pnpm_versions_for_pkg() {
  lf="$1"; pkg="$2"
  awk -v P="$pkg" '
    match($0, "/" P "@([^:]+):", m) { print m[1]; }
  ' "$lf" | sort -u
}

# ---------- Scan lockfiles ----------
for LF in $LOCKFILES; do
  hr
  log "Lockfile: $LF"
  THIS_FILE_FLAGGED=0
  base="$(basename "$LF")"
  dirpath="$(cd "$(dirname "$LF")" && pwd)"

  case "$base" in
    package-lock.json)
      VERS_TMP="$(mktemp 2>/dev/null || mktemp -t tmp)"
      : >"$VERS_TMP"
      npm_versions_to_tmp "$LF" "$VERS_TMP"

      while IFS= read -r ITEM; do
        [ -n "$ITEM" ] || continue
        PKG="${ITEM%@*}"
        BADVER="${ITEM##*@}"

        if grep -Fq "$PKG	$BADVER" "$VERS_TMP"; then
          log "🚨 Found compromised version: $PKG@$BADVER"
          FOUND_ANY=1; THIS_FILE_FLAGGED=1
        elif grep -Fq "$PKG" "$VERS_TMP"; then
          # log "grep -F '$PKG' '$VERS_TMP'"
          # echo $(grep -F "$PKG" "$VERS_TMP")
          found="$(grep -F "$PKG" "$VERS_TMP" | cut -f2 | sort -u | paste -sd, - || true)"
          [ -z "$found" ] && found="(version unknown)"
          log "⚠️  WARNING: $PKG present in lockfile, but not at known compromised version ($BADVER). Found versions: $found"
          WARN_ANY=1; THIS_FILE_FLAGGED=1
        fi
      done < "$SORTED_LIST_TMP"

      rm -f "$VERS_TMP"
      ;;

    yarn.lock)
      while IFS= read -r ITEM; do
        [ -n "$ITEM" ] || continue
        PKG="${ITEM%@*}"
        BADVER="${ITEM##*@}"

        versions="$(yarn_versions_for_pkg "$LF" "$PKG" || true)"
        if [ -n "$versions" ]; then
          echo "$versions" | grep -Fxq "$BADVER" && {
            log "🚨 Found compromised version: $PKG@$BADVER"
            FOUND_ANY=1; THIS_FILE_FLAGGED=1
            continue
          }
          log "⚠️  WARNING: $PKG present in lockfile, but not at known compromised version ($BADVER). Found versions: $(printf '%s\n' "$versions" | paste -sd, -)"
          WARN_ANY=1; THIS_FILE_FLAGGED=1
        fi
      done < "$SORTED_LIST_TMP"
      ;;

    pnpm-lock.yaml|pnpm-lock.yml)
      while IFS= read -r ITEM; do
        [ -n "$ITEM" ] || continue
        PKG="${ITEM%@*}"
        BADVER="${ITEM##*@}"

        versions="$(pnpm_versions_for_pkg "$LF" "$PKG" || true)"
        if [ -n "$versions" ]; then
          echo "$versions" | grep -Fxq "$BADVER" && {
            log "🚨 Found compromised version: $PKG@$BADVER"
            FOUND_ANY=1; THIS_FILE_FLAGGED=1
            continue
          }
          log "⚠️  WARNING: $PKG present in lockfile, but not at known compromised version ($BADVER). Found versions: $(printf '%s\n' "$versions" | paste -sd, -)"
          WARN_ANY=1; THIS_FILE_FLAGGED=1
        fi
      done < "$SORTED_LIST_TMP"
      ;;

    *)
      # Unknown lockfile: best-effort token check
      while IFS= read -r ITEM; do
        [ -n "$ITEM" ] || continue
        PKG="${ITEM%@*}"; BADVER="${ITEM##*@}"
        if grep -Fq "$PKG@$BADVER" "$LF"; then
          log "🚨 Found compromised version: $PKG@$BADVER"
          FOUND_ANY=1; THIS_FILE_FLAGGED=1
        elif grep -Fq "$PKG@" "$LF"; then
          log "⚠️  WARNING: $PKG present (unknown format), please review."
          WARN_ANY=1; THIS_FILE_FLAGGED=1
        fi
      done < "$SORTED_LIST_TMP"
      ;;
  esac

  if [ $THIS_FILE_FLAGGED -eq 1 ]; then
    printf '%s\n' "$dirpath" >>"$AFFECTED_DIRS_TMP"
  else
    log "✅ No hits for this lockfile."
  fi
done

hr
if [ $FOUND_ANY -eq 1 ]; then
  log "🚨 Exact compromised version(s) detected."
elif [ $WARN_ANY -eq 1 ]; then
  log "⚠️  Packages of interest present, but versions differ. Please review."
else
  log "✅ No compromised packages detected across lockfiles."
fi

# ---------- Optional remediation ----------
if [ $FIX -eq 1 ] && [ $FOUND_ANY -eq 1 ]; then
  hr
  log "🛠  Remediation: cleaning & reinstalling with scripts disabled per affected directory…"
  hr
  for PKG_DIR in $(sort -u "$AFFECTED_DIRS_TMP"); do
    [ -n "$PKG_DIR" ] || continue
    log "→ Fixing: $PKG_DIR"

    PM=""
    [ -f "$PKG_DIR/pnpm-lock.yaml" ] || [ -f "$PKG_DIR/pnpm-lock.yml" ] && PM="pnpm"
    [ -f "$PKG_DIR/yarn.lock" ] && PM="yarn"
    { [ -f "$PKG_DIR/package-lock.json" ] || [ -f "$PKG_DIR/npm-shrinkwrap.json" ]; } && PM="npm"
    if [ -z "$PM" ]; then
      if exists pnpm; then PM="pnpm"; elif exists yarn; then PM="yarn"; elif exists npm; then PM="npm"; else PM="npm"; fi
    fi

    case "$PM" in
      npm)
        ( cd "$PKG_DIR" && \
          log "   [npm] Removing node_modules & lockfiles…" && \
          rm -rf node_modules package-lock.json npm-shrinkwrap.json 2>/dev/null || true && \
          log "   [npm] Reinstalling (scripts disabled)…" && \
          npm_config_ignore_scripts=1 npm ci 2>/dev/null || npm_config_ignore_scripts=1 npm install )
        ;;
      yarn)
        ( cd "$PKG_DIR" && \
          log "   [yarn] Removing node_modules & lockfile…" && \
          rm -rf node_modules yarn.lock 2>/dev/null || true && \
          log "   [yarn] Reinstalling (scripts disabled)…" && \
          yarn install --ignore-scripts )
        ;;
      pnpm)
        ( cd "$PKG_DIR" && \
          log "   [pnpm] Removing node_modules & lockfile…" && \
          rm -rf node_modules pnpm-lock.yaml pnpm-lock.yml 2>/dev/null || true && \
          log "   [pnpm] Reinstalling (scripts disabled)…" && \
          pnpm install --ignore-scripts )
        ;;
      *)
        log "   [?] Unknown package manager for $PKG_DIR — skipping automatic fix."
        ;;
    esac

    log "   Done: $PKG_DIR"
    hr
  done

  log "Remediation complete."
  log "Next steps:"
  log "  • Rebuild your app(s) and redeploy."
  log "  • Purge CDN/service worker caches if you ship frontend bundles."
  log "  • Rotate CI/registry tokens and enable 2FA/U2F for publish."
fi

# ---------- Optional overrides/resolutions output ----------
if [ $PRINT_OVERRIDES -eq 1 ]; then
  hr
  log "📎 Paste into your package.json to block these exact compromised versions:"
  hr

  # npm / pnpm overrides: block any version >= compromised by enforcing "<compromised"
  log "npm / pnpm (\"overrides\")"
  printf '%s\n' "  \"overrides\": {"
  awk -F'@' '{printf "    \"%s\": \"<%s\",\n", $1, $2}' "$SORTED_LIST_TMP" | sed '$ s/,$//'
  printf '%s\n' "  }"
  hr

  # yarn resolutions: pin to a known-safe version below the compromised one
  log "yarn (\"resolutions\") — replace <SAFE_VERSION_BELOW> with a known-good version lower than the compromised one:"
  printf '%s\n' "  \"resolutions\": {"
  awk -F'@' '{printf "    \"%s\": \"<SAFE_VERSION_BELOW_%s\",\n", $1, $2}' "$SORTED_LIST_TMP" | sed '$ s/,$//'
  printf '%s\n' "  }"
  hr
fi

# ---------- Heuristic scan for built bundles (optional) ----------
if [ $SCAN_DIST -eq 1 ]; then
  hr
  log "🔎 Heuristic scan of built assets (directory: $DIST_DIR)"
  log "   Looking for patched network/wallet hooks typical of the payload…"
  log "   (heuristic only; any hits deserve manual review)"
  hr
  PATTERN='(window\.ethereum\.request|XMLHttpRequest|fetch\(|Solana|tron|Bitcoin Cash|Litecoin)'
  if [ -d "$DIST_DIR" ]; then
    if exists rg; then
      rg -n --no-ignore -S "$PATTERN" "$DIST_DIR" 2>/dev/null || true
    else
      grep -R -n -E "$PATTERN" "$DIST_DIR" 2>/dev/null || true
    fi
  else
    log "ℹ️  Directory not found: $DIST_DIR (skipping heuristic scan)"
  fi
  hr
fi

# ---------- Cleanup & exit ----------
rm -f "$AFFECTED_DIRS_TMP" "$SORTED_LIST_TMP"

if [ $FOUND_ANY -eq 1 ]; then
  exit 10
elif [ $WARN_ANY -eq 1 ]; then
  exit 8
else
  exit 0
fi

