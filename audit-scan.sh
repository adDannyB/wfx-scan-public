#!/usr/bin/env bash
# audit-scan.sh — Analyzes an exported GitHub audit log (JSON).
# Uses the same security-relevant action list as section A6 of wfx-scan.sh.
# Reads a local export and works for organizations without GitHub Enterprise Cloud.
# The input file is read-only. Reports are written locally.
# No network access is required.
#
# Export (organization owners only): Org → Settings → Archive → Logs → Audit log
#   Search for "created:>=2026-10-01", then choose Export → JSON.
#   Exports without Enterprise Cloud omit Git push events.
#
# Requirements: jq, shasum
# Usage:   ./audit-scan.sh <export.json> [suspect-github-login] [since YYYY-MM-DD]
# Example: ./audit-scan.sh ../export-my-org.json suspect-login 2026-10-01
#          ./audit-scan.sh ../export-my-org.json "" 2026-10-01   (omit the suspect account)
#
# Timestamps and the cutoff are in UTC.
# For example, 2026-10-01 means midnight UTC on October 1, 2026.
#
# Output: audit-scan-<timestamp>/ (accessible only to the current user)
#   findings.tsv   — findings (HIGH / REVIEW / INFO), same format as wfx-scan.sh
#   audit_log.tsv  — events since the cutoff, sorted by time (UTC)
#   suspect.tsv    — suspect account timeline
#   actions.tsv    — counts by action since the cutoff
#   export.sha256  — checksum of the original export file
#
# Each event appears at most once in findings.tsv. Security-relevant actions
# by the suspect are HIGH (P3). Other accounts' actions are REVIEW (P1).
#
# ---------------------------------------------------------------------------------------------
# CONTENTS (search for section labels such as P1)
# ---------------------------------------------------------------------------------------------
#   Setup: validate arguments and the export, normalize timestamps, and report
#          missing or invalid timestamps and gaps in coverage
#   P1.  Security-relevant actions by other accounts → REVIEW (as in A6)
#   P2.  Suspect account events → timeline and HIGH summary (as in A6)
#   P3.  Security-relevant actions by the suspect → HIGH (as in A6)
#   P4.  Summary
# ---------------------------------------------------------------------------------------------

# ========== Setup ==========
set -uo pipefail
umask 077   # Restrict access to reports because they contain personal data.

FILE="${1:?Usage: $0 <export.json> [suspect-login] [since YYYY-MM-DD]}"
SUSPECT="${2:-}"
SINCE="${3:-2026-10-01}"

# Reject invalid or swapped arguments early.
if ! [[ "$SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "Cutoff date must use YYYY-MM-DD format. Received: '$SINCE'"; exit 1
fi
if [[ "$SUSPECT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
  echo "The second argument '$SUSPECT' looks like a date. Check the argument order."
  echo "Argument order: <export.json> [suspect-login] [since YYYY-MM-DD]  (use \"\" to omit the login)"
  exit 1
fi

for t in jq shasum; do
  command -v "$t" >/dev/null 2>&1 || { echo "Missing: $t"; exit 1; }
done
[ -r "$FILE" ] || { echo "Cannot read file: $FILE"; exit 1; }
if ! jq empty "$FILE" >/dev/null 2>&1; then
  echo "Invalid JSON file: $FILE"
  echo "Export the audit log as JSON."
  exit 1
fi

# Load the shared security action list (SEC_ACTIONS).
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -r "$HERE/audit-actions.sh" ] || { echo "Missing: $HERE/audit-actions.sh"; exit 1; }
# shellcheck source=audit-actions.sh
. "$HERE/audit-actions.sh"

# Read a JSON array (web export) or one object per line (NDJSON).
# Normalize timestamps to YYYY-MM-DDThh:mm:ssZ (UTC). Accept milliseconds,
# seconds (including numeric strings), ISO timestamps with Z or an offset (+02:00 / +0200),
# optional fractional seconds, and dates alone. Invalid timestamps become "?", missing timestamps "".
# Columns: timestamp, action, actor, target, country, access type (e.g. token type), app, org
RAW="$(mktemp "${TMPDIR:-/tmp}/audit-scan.XXXXXX")"
trap 'rm -f "$RAW"' EXIT
jq -r '
  def from_epoch: (if . > 100000000000 then . / 1000 else . end | floor | todate);
  def norm_ts:
    if type == "number" then from_epoch
    elif type == "string" then
      if test("^[0-9]+$") then (tonumber | from_epoch)
      else
        (capture("^(?<d>[0-9]{4}-[0-9]{2}-[0-9]{2})(?:[T ](?<t>[0-9]{2}:[0-9]{2}(?::[0-9]{2})?)(?:\\.[0-9]+)?)?[ ]*(?<z>Z|[+-][0-9]{2}:?[0-9]{2})?$") // null)
        | if . == null then "?"
          else
            ((.t // "00:00:00") | if length == 5 then . + ":00" else . end) as $t
            | ((.d + "T" + $t + "Z") | fromdateiso8601) as $base
            | ((.z // "Z") | if . == "Z" then 0
                else gsub(":"; "") as $z
                  | (($z[1:3] | tonumber) * 3600 + ($z[3:5] | tonumber) * 60)
                    * (if $z[0:1] == "-" then -1 else 1 end)
                end) as $off
            | ($base - $off) | todate
          end
      end
    else "?" end;
  (if type == "array" then .[] else . end)
  | objects
  | [ ((."@timestamp" // .created_at // null) | if . == null then "" else norm_ts end),
      (.action // "" | tostring),
      (.actor // ""),
      (.repo // .repository // .user // .team // ""),
      ((.actor_location | objects | .country_code) // ""),
      (.programmatic_access_type // ""),
      (.oauth_application_name // .integration // ""),
      (.org // "") ]
  | map(tostring | gsub("[\t\r\n]"; " "))
  | @tsv' "$FILE" > "$RAW"

TOTAL=$(wc -l < "$RAW" | tr -d ' ')
WITH_ACTION=$(awk -F'\t' '$2 != ""' "$RAW" | wc -l | tr -d ' ')
# Use the most common "org" value or "-" for entries with no target, such as summaries,
# so the report can be combined with wfx-scan.sh findings.
ORGN=$(awk -F'\t' '$8 != "" { print $8 }' "$RAW" | sort | uniq -c | sort -rn | awk 'NR == 1 { print $2 }')
ORGN="${ORGN:--}"

# Reject inputs with no events containing an "action" field.
# This catches unsupported shapes such as arrays wrapped in {"data": [...]}.
# An explicit error distinguishes invalid input from an export with no findings.
if [ "$WITH_ACTION" -eq 0 ]; then
  echo "No audit log events found (no object with an \"action\" field): $FILE"
  keys=$(jq -r 'if type == "object" then keys | join(", ") elif type == "array" then "Array mit \(length) Elementen" else type end' "$FILE" 2>/dev/null | head -1)
  [ -n "$keys" ] && echo "Top-level keys: $keys"
  echo "Expected a JSON export from Org → Settings → Audit log (an array of events)."
  exit 1
fi

OUT="audit-scan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
REPORT="$OUT/findings.tsv"
ALL="$OUT/audit_log.tsv"
printf 'severity\trepo\tcheck\tdetail\n' > "$REPORT"
shasum -a 256 "$FILE" > "$OUT/export.sha256"

# Replace tabs in details with " | " to preserve findings.tsv columns.
hit() {
  local d="${4//$'\t'/ | }"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$d" >> "$REPORT"
  printf '    [%s] %s: %s\n' "$1" "$3" "$d"
}

HDR='timestamp\taction\tactor\ttarget\tcountry\taccess_type\tapp\torg\n'
# shellcheck disable=SC2059
printf "$HDR" > "$ALL"
awk -F'\t' -v s="$SINCE" '$2 != "" && $1 != "" && $1 != "?" && $1 >= s' "$RAW" | sort >> "$ALL"
N=$(($(wc -l < "$ALL" | tr -d ' ') - 1))
NOACT=$((TOTAL - WITH_ACTION))
NOTS=$(awk -F'\t' '$2 != "" && $1 == ""' "$RAW" | wc -l | tr -d ' ')
BADTS=$(awk -F'\t' '$2 != "" && $1 == "?"' "$RAW" | wc -l | tr -d ' ')
FIRST=$(awk -F'\t' '$2 != "" && $1 != "" && $1 != "?" { print $1 }' "$RAW" | sort | head -1)
LAST=$(awk -F'\t' '$2 != "" && $1 != "" && $1 != "?" { print $1 }' "$RAW" | sort | tail -1)

echo "$WITH_ACTION events read (${FIRST:-?} … ${LAST:-?} UTC), $N since $SINCE${SUSPECT:+; suspect account: $SUSPECT}"
[ "$NOACT" -gt 0 ] && hit INFO "$ORGN" missing_action "$NOACT objects skipped because they lack an \"action\" field"
[ "$NOTS" -gt 0 ] && hit INFO "$ORGN" missing_timestamp "$NOTS events skipped because they lack a timestamp"
[ "$BADTS" -gt 0 ] && hit INFO "$ORGN" invalid_timestamp "$BADTS events skipped because their timestamps could not be parsed"

# Check whether the export begins after the cutoff (filter or retention)
# or ends too far in the past (stale export with potentially missing recent events).
if [ -n "$FIRST" ] && [[ "$FIRST" > "${SINCE}T23:59:59Z" ]]; then
  hit INFO "$ORGN" incomplete_time_range "Export starts at $FIRST, after the $SINCE cutoff. Earlier events are missing"
fi
STALE=$(date -u -v-2d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '2 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)
if [ -n "$LAST" ] && [ -n "$STALE" ] && [[ "$LAST" < "$STALE" ]]; then
  hit INFO "$ORGN" stale_export "The last event ($LAST) is more than two days old. Export again if you need newer events"
fi

# Write events to findings.tsv. $3 is an awk condition and s is the lowercase login.
# Pass patterns through ENVIRON to preserve backslashes (see audit-actions.sh).
# Column 2 contains the event target, organization, or "-".
emit() {  # emit <severity> <check> <awk-condition>
  local target rest
  awk -F'\t' -v s="$(printf '%s' "$SUSPECT" | tr 'A-Z' 'a-z')" \
    "NR > 1 && ($3) { z = (\$4 != \"\") ? \$4 : ((\$8 != \"\") ? \$8 : \"-\"); print z \"\t\" \$0 }" "$ALL" \
    | while IFS=$'\t' read -r target rest; do
      hit "$1" "$target" "$2" "$rest"
    done
}

IS_SUSP='s != "" && tolower($3) == s'

# P1. Security-relevant actions by other accounts (may be legitimate → REVIEW)
emit REVIEW audit_log_action "\$2 ~ ENVIRON[\"SEC_ACTIONS\"] && !($IS_SUSP)"

if [ -n "$SUSPECT" ]; then
  # P2. Suspect account events (timeline and HIGH summary, as in A6)
  # shellcheck disable=SC2059
  printf "$HDR" > "$OUT/suspect.tsv"
  awk -F'\t' -v s="$(printf '%s' "$SUSPECT" | tr 'A-Z' 'a-z')" "NR > 1 && $IS_SUSP" "$ALL" >> "$OUT/suspect.tsv"
  an=$(($(wc -l < "$OUT/suspect.tsv" | tr -d ' ') - 1))
  if [ "$an" -gt 0 ]; then
    hit HIGH "$ORGN" audit_log_suspect_summary "$an total events by $SUSPECT (suspect.tsv) – summary count"

    # P3. Security-relevant actions performed by the suspect account
    emit HIGH security_action_by_suspect "$IS_SUSP && \$2 ~ ENVIRON[\"SEC_ACTIONS\"]"
  else
    rm -f "$OUT/suspect.tsv"
  fi
fi

# Count events by action since the cutoff.
{ printf 'count\taction\n'; awk -F'\t' 'NR > 1 { c[$2]++ } END { for (a in c) printf "%d\t%s\n", c[a], a }' "$ALL" | sort -rn; } \
  > "$OUT/actions.tsv"

# P4. Summary
p1=$(grep -c "	audit_log_action	" "$REPORT")
p3=$(grep -c "	security_action_by_suspect	" "$REPORT")
echo
echo "Done. Findings: $REPORT"
if [ -n "$SUSPECT" ]; then
  echo "  Security-relevant actions: $((p1 + p3)) – by $SUSPECT: $p3 (HIGH), by other accounts: $p1 (REVIEW)"
else
  echo "  Security-relevant actions: $p1 (REVIEW)"
fi
for st in HIGH REVIEW INFO; do
  printf '  %-8s %s rows\n' "$st" "$(grep -c "^$st	" "$REPORT")"
done
echo "Timeline: $ALL${SUSPECT:+ | Suspect timeline: $OUT/suspect.tsv} | Action counts: $OUT/actions.tsv"
