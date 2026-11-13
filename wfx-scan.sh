#!/usr/bin/env bash
# wfx-scan.sh — Scans GitHub organization repositories for traces of the wfx and GhostAction campaigns.
# READ ONLY: Makes no changes to GitHub or local Git configuration.
# Repositories are cloned with --mirror. The scan does not execute repository code.
# The API exposes secret names and timestamps only.
#
# Requirements: gh (signed in with gh auth login using an account with read access to all organization repositories),
#               git, jq, tar, and shasum
# Organization checks for webhooks, apps, secrets, runners, and audit events require
# additional token scopes and organization owner permissions:
#   gh auth refresh -s admin:org_hook,admin:org,read:audit_log
# Audit log API access requires GitHub Enterprise Cloud.
# Repository secrets, runners, webhooks, and deploy keys require repository admin permissions.
# Missing permissions produce INFO entries with the check_unavailable identifier
# in findings.tsv.
#
# Usage:   ./wfx-scan.sh <org> [suspect-github-login] [since YYYY-MM-DD]
# Example: ./wfx-scan.sh my-org suspect-login 2026-10-01
# Optional: MAX_LOGS=<n> (default 100) — maximum run logs to save per repository
#           SUSPECT_EMAIL=<a@b,c@d> — Git email addresses to match against commit metadata,
#           in addition to the login and GitHub noreply address
#
# Output: wfx-scan-<org>-<timestamp>/
#   findings.tsv   — all findings (CRITICAL / HIGH / REVIEW / INFO)
#   rotation.tsv   — secrets to rotate for affected repositories
#   runs/          — workflow runs since the cutoff, by repository
#   logs/          — ZIP logs for suspicious runs and runs in affected repositories
#   inventory/     — workflow changes, malicious commits, secrets, runners, webhooks,
#                    deploy keys, outside collaborators, owners, apps, audit log, suspect activity
#   mirrors/       — mirror clones
#   evidence.tgz   — archive of mirrors/, runs/, logs/, inventory/, with a SHA-256 checksum
#
# ---------------------------------------------------------------------------------------------
# CONTENTS (search for section labels such as A1 or B3)
# ---------------------------------------------------------------------------------------------
#   Setup: arguments, tools, authentication and scopes, helpers, and indicators
#
#   PART A — organization checks
#     A1.  Org-Owner
#     A2.  Organization webhooks (new or updated → HIGH)
#     A3.  Installed GitHub Apps (new or updated → REVIEW)
#     A4.  Organization and Dependabot secrets
#     A5.  Organization self-hosted runners
#     A6.  Audit log since the cutoff (Enterprise Cloud only)
#     A7.  Suspect account activity from GitHub search
#
#   PART B — per-repository checks
#     B1.  Mirror clone
#     B2.  Malicious code at branch tips (default → CRITICAL, others → HIGH),
#          including suspicious filenames
#     B3.  Malicious code in history, including removed and backdated commits
#     B4.  Workflow and action file changes since the cutoff
#     B5.  Suspicious branch names
#     B5a. pull_request_target / “Pwn Request” patterns
#     B5b. Suspect commits based on Git metadata
#     B5c. Campaign commit messages
#     B6.  Probe PRs
#     B7.  Workflow runs since the cutoff
#     B8.  Campaign artifacts and caches
#     B9.  Webhooks, deploy keys, and outside collaborators
#     B10. Secrets accessible to repository workflows
#     B11. Repository self-hosted runners
#     B12. Save workflow run logs
#
#   PART C — final steps
#     C1.  Rotation list (rotation.tsv)
#     C2.  Evidence archive (evidence.tgz and checksum) and summary
# ---------------------------------------------------------------------------------------------

# ========== Setup ==========
set -uo pipefail
export GIT_TERMINAL_PROMPT=0   # Disable interactive Git credential prompts

ORG="${1:?Usage: $0 <org> [suspect-login] [since YYYY-MM-DD]}"
SUSPECT="${2:-}"
SINCE="${3:-2026-10-01}"
MAX_LOGS="${MAX_LOGS:-100}"

# Reject invalid or swapped arguments early
if ! [[ "$SINCE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "Cutoff date must use YYYY-MM-DD format. Received: '$SINCE'"; exit 1
fi
if [[ "$SUSPECT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2} ]]; then
  echo "The second argument '$SUSPECT' looks like a date. Check the argument order."
  echo "Argument order: <org> [suspect-login] [since YYYY-MM-DD]  (use \"\" to omit the login)"
  exit 1
fi
[[ "$MAX_LOGS" =~ ^[0-9]+$ ]] || { echo "MAX_LOGS must be a non-negative integer. Received: '$MAX_LOGS'"; exit 1; }

for t in gh git jq tar shasum; do
  command -v "$t" >/dev/null 2>&1 || { echo "Missing: $t"; exit 1; }
done

# Load the shared audit action list used by A6 and audit-scan.sh
HERE="$(cd "$(dirname "$0")" && pwd)"
[ -r "$HERE/audit-actions.sh" ] || { echo "Missing: $HERE/audit-actions.sh"; exit 1; }
# shellcheck source=audit-actions.sh
. "$HERE/audit-actions.sh"
gh auth status >/dev/null 2>&1 || { echo "Sign in to GitHub CLI first with gh auth login"; exit 1; }

# Scope warning (available for classic tokens only)
SCOPES=$(gh auth status 2>&1 | grep -i 'token scopes' || true)
if [ -n "$SCOPES" ]; then
  missing=""
  for sc in admin:org_hook admin:org read:audit_log; do
    case "$SCOPES" in *"'$sc'"*) ;; *) missing="$missing $sc" ;; esac
  done
  if [ -n "$missing" ]; then
    echo "WARNING: Missing token scopes:$missing. Affected checks will be reported as 'check_unavailable'."
    echo "         Add scopes with: gh auth refresh -s admin:org_hook,admin:org,read:audit_log"
  fi
fi

OUT="wfx-scan-$ORG-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/mirrors" "$OUT/runs" "$OUT/inventory" "$OUT/logs"
REPORT="$OUT/findings.tsv"
ERR="$OUT/errors.log"
TMP="$OUT/.api.tmp"
SECRETS="$OUT/inventory/secrets.tsv"
RUNNERS="$OUT/inventory/runner.tsv"
printf 'severity\trepo\tcheck\tdetail\n' > "$REPORT"
printf 'repo\tscope\tname\tcreated_at\tupdated_at\n' > "$SECRETS"
printf 'scope\tname\tos\tstatus\tlabels\n' > "$RUNNERS"

# Details can contain whole TSV rows (A2, A3, A6). Replace tabs with " | "
# to preserve the column layout of findings.tsv.
hit() {
  local d="${4//$'\t'/ | }"
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$d" >> "$REPORT"
  printf '    [%s] %s: %s\n' "$1" "$3" "$d"
}

# Run an API request and write the response to $TMP.
# Record unsuccessful checks (missing permissions or scopes, 404, etc.) in $FAILED
# so they appear in findings.tsv as INFO / check_unavailable.
# Call directly because a pipeline subshell would lose changes to $FAILED.
FAILED=""
api_get() {
  local chk=$1; shift
  if gh api "$@" > "$TMP" 2>>"$ERR" </dev/null; then
    return 0
  fi
  FAILED="$FAILED $chk"
  : > "$TMP"
  return 1
}
report_failed() {
  [ -n "$FAILED" ] && hit INFO "$1" check_unavailable "${FAILED# } – check permissions and token scopes in errors.log"
  FAILED=""
}

# Add secrets from $TMP to the inventory and flag updates since the cutoff as REVIEW.
# $1 = repository or organization, $2 = scope (repo / org / environment:<name> / dependabot)
record_secrets() {
  jq -r --arg r "$1" --arg e "$2" '.secrets[] | [$r, $e, .name, .created_at, .updated_at] | @tsv' "$TMP" >> "$SECRETS"
  jq -r --arg s "$SINCE" '.secrets[] | select(.updated_at >= $s) | "\(.name) updated_at=\(.updated_at)"' "$TMP" \
    | while IFS= read -r l; do hit REVIEW "$1" secret_updated_since_cutoff "$2: $l"; done
}

# Indicators (wfx and GhostAction)
# The short string "wfx" can occur by chance in Base64, such as lockfile integrity hashes.
# Require a boundary on both sides, counting separators such as -_. as boundaries.
# This catches wfx-loot, .wfx-$$, and wfx_status while filtering examples like "Awfx.x"
# (minified JavaScript) and "aBcwfx-_" (Base64url/JWT).
IOC_WFX='(^|[^A-Za-z0-9+/=])wfx([^A-Za-z0-9+/=]|$)'
# Strong content indicators (CRITICAL/HIGH, repository classified as affected): wfx variables,
# Telegram, exfiltration IPs, campaign token, and GhostAction indicators.
# Sources: SafeDep, Endor Labs, and Aikido (wfx), StepSecurity (GhostAction), as of 2026-11-13.
IOC="$IOC_WFX|WF_TG_BOTS|WF_SECRETS|WF_CALLBACK|api\.telegram\.org/bot|194\.150\.166\.244|18\.143\.168\.96|153\.75\.82\.159|1004340163187|b42d70a7aab9140ca19e8249|toJSON\(secrets\)|AKIA_CTX_START|193\.32\.204\.199|c=monami"
# Weak indicators (HIGH / suspicious_pattern) can also occur in legitimate code.
# Match the specific YAML step "name: Pass runtime" and package.json postinstall scripts
# that call a .ci-xxxxxx.sh file.
IOC_WEAK='name:[[:space:]]*.?Pass runtime.?[[:space:]]*$|"postinstall"[[:space:]]*:[[:space:]]*"[^"]*\.ci-[a-z0-9]{6}\.sh'
# A "chore/" branch with eight characters and no digits may be legitimate.
# Report it as REVIEW in B5 and exclude it from probe PR and suspicious run matching.
SUSP_BRANCH='^(wfx|ci-[0-9]+-|ci-check-[0-9]{4}$|chore/[a-z0-9]{8}$)'
# Campaign filenames can reveal a match even when the contents are obfuscated.
#   SUSP_FILE_HIDDEN: hidden stealer helper (.ci-xxxxxx.sh). The pattern also matches
#                     legitimate filenames such as .ci-deploy.sh. An affected finding
#                     requires the known stealer's SHA-256 hash.
#   SUSP_FILE_WF:     Workflow filenames from wfx (build-audit-*) and GhostAction
SUSP_FILE_HIDDEN='(^|/)\.ci-[a-z0-9]{6}\.sh$'
SUSP_FILE_WF='^\.github/workflows/(build-audit-[^/]*|github_actions_security)\.ya?ml$'
STEALER_SHA256='89695abb392d5cfd4972672961e644bb46baa98aa1ed7173c2a2816c762735cf'
# Campaign commit messages (case-insensitive match on the full subject line).
# Report as REVIEW because a message alone is a weak signal (B5c).
#   SUSP_MSG:         specific messages in any commit since the cutoff
#   SUSP_MSG_GENERIC: common messages, limited to commits that change workflows or .ci-*.sh
SUSP_MSG='^(chore: add dependency audit workflow|ci: refresh build cache|chore: add ci helper|add github actions security workflow|docs: dependency audit notes)$'
SUSP_MSG_GENERIC='^(ci: restore|ci: cleanup)$'
# Pass patterns to awk through ENVIRON to preserve backslashes.
export SUSP_FILE_HIDDEN SUSP_MSG SUSP_MSG_GENERIC
# chore/<8 characters> without a digit is REVIEW in B5 and excluded from B6/B12.
weak_chore() { [[ "$1" == chore/* && ! "$1" =~ [0-9] ]]; }
# These checks classify a repository as affected, making its logs eligible for collection
# and including its secrets in rotation.tsv. Other HIGH findings, such as pwn_request_pattern,
# older history hits, and new webhooks, require review on their own merits.
# An affected classification identifies strong indicators that warrant checking workflow runs.
AFFECT_CHECKS='^(malicious_code_on_default_branch|malicious_code_on_branch|malicious_code_in_history|hidden_ci_file|wfx_artifact|wfx_cache)$'

# Clone with git directly because gh repo clone can also configure and fetch the upstream
# remote for forks, which would change the mirror and history search results.
# Use gh credentials for this call only, leaving ~/.gitconfig untouched.
mirror_clone() {
  git -c credential.helper= -c 'credential.helper=!gh auth git-credential' \
    clone --mirror --quiet "https://github.com/$1.git" "$2"
}

# ========== PART A — organization checks ==========
# A1. Org-Owner
echo "Collecting organization inventory for $ORG …"
if api_get org_owners "orgs/$ORG/members?role=admin&per_page=100" --paginate; then
  jq -r '.[].login' "$TMP" > "$OUT/inventory/org_owners.txt"
fi

# A2. Organization webhooks
if api_get org_webhooks "orgs/$ORG/hooks?per_page=100" --paginate; then
  jq -r '.[] | [.id, .config.url, .created_at, .updated_at] | @tsv' "$TMP" > "$OUT/inventory/org_webhooks.tsv"
  # Created or updated, including changes to the URL of an existing hook.
  awk -F'\t' -v s="$SINCE" '$3 >= s || $4 >= s' "$OUT/inventory/org_webhooks.tsv" | while IFS= read -r l; do
    hit HIGH "$ORG" org_webhook_created_or_updated "$l"
  done
fi

# A3. Installed GitHub Apps
if api_get org_apps "orgs/$ORG/installations?per_page=100" --paginate; then
  jq -r '.installations[] | [.app_slug, .created_at, .updated_at, .repository_selection] | @tsv' "$TMP" \
    > "$OUT/inventory/org_apps.tsv"
  awk -F'\t' -v s="$SINCE" '$2 >= s || $3 >= s' "$OUT/inventory/org_apps.tsv" | while IFS= read -r l; do
    hit REVIEW "$ORG" org_app_installed_or_updated "$l"
  done
fi

# A4. All organization secrets. Repository-level access is recorded separately.
if api_get org_secrets "orgs/$ORG/actions/secrets?per_page=100" --paginate; then
  record_secrets "$ORG" org
fi
if api_get org_dependabot_secrets "orgs/$ORG/dependabot/secrets?per_page=100" --paginate; then
  record_secrets "$ORG" org-dependabot
fi

# A5. Organization self-hosted runners. The API omits registration dates.
# Look for new registrations in the audit log (*.register_self_hosted_runner).
if api_get org_runner "orgs/$ORG/actions/runners?per_page=100" --paginate; then
  jq -r '.runners[] | ["org", .name, .os, .status, ([.labels[].name] | join(","))] | @tsv' "$TMP" >> "$RUNNERS"
  rn=$(jq -s '[.[].runners[]] | length' "$TMP")
  [ "$rn" -gt 0 ] && hit REVIEW "$ORG" self_hosted_runner_org "$rn runners (inventory/runner.tsv). Check the audit log for new registrations"
fi

# A6. Audit log since the cutoff (Enterprise Cloud only). Use GitHub's event timestamps.
# The API returns Git push events for the last seven days only.
AUDIT="$OUT/inventory/audit_log.tsv"
if api_get audit_log -X GET "orgs/$ORG/audit-log" -f phrase="created:>=$SINCE" -f include=all -f per_page=100 --paginate; then
  # Count events missing timestamps as INFO to avoid sorting them under 1970.
  jq -r '.[] | [(."@timestamp" // null | if type == "number" then (. / 1000 | floor | todate) else "" end),
                (.action // ""), (.actor // ""), (.repo // .user // "")] | map(tostring | gsub("[\t\r\n]"; " ")) | @tsv' \
    "$TMP" > "$AUDIT.tmp"
  awk -F'\t' '$1 != ""' "$AUDIT.tmp" | sort > "$AUDIT"
  ats=$(awk -F'\t' '$1 == ""' "$AUDIT.tmp" | wc -l | tr -d ' ')
  [ "$ats" -gt 0 ] && hit INFO "$ORG" missing_timestamp "$ats audit log events skipped because they lack a timestamp (inventory/audit_log_raw.json)"
  rm -f "$AUDIT.tmp"
  cp "$TMP" "$OUT/inventory/audit_log_raw.json"
  # Security-relevant actions use the same list as audit-scan.sh.
  # Each event appears at most once, as HIGH for the suspect account or REVIEW otherwise.
  # Compare GitHub logins case-insensitively.
  # Pass the pattern through ENVIRON to preserve backslashes.
  # Column 2 of findings.tsv contains the event target or organization.
  sl=$(printf '%s' "$SUSPECT" | tr 'A-Z' 'a-z')
  awk -F'\t' -v s="$sl" -v o="$ORG" '$2 ~ ENVIRON["SEC_ACTIONS"] {
      z = ($4 != "") ? $4 : o
      print ((s != "" && tolower($3) == s) ? "HIGH" : "REVIEW") "\t" z "\t" $0 }' "$AUDIT" \
    | while IFS=$'\t' read -r st z l; do
      if [ "$st" = HIGH ]; then
        hit HIGH "$z" security_action_by_suspect "$l"
      else
        hit REVIEW "$z" audit_log_action "$l"
      fi
    done
  if [ -n "$SUSPECT" ]; then
    an=$(awk -F'\t' -v s="$sl" 'tolower($3) == s' "$AUDIT" | wc -l | tr -d ' ')
    [ "$an" -gt 0 ] && hit HIGH "$ORG" audit_log_suspect_summary "$an total events by $SUSPECT (inventory/audit_log.tsv) – summary count"
  fi
fi

# A7. Search for suspect activity across the organization. GitHub links commits to
# accounts through verified email addresses. Git author fields can be forged.
# GitHub commit search covers default branches only.
# Step B5b checks Git metadata across branches for each repository.
if [ -n "$SUSPECT" ]; then
  if api_get search_prs_issues -X GET search/issues -f q="org:$ORG author:$SUSPECT created:>=$SINCE" -f per_page=100 --paginate; then
    jq -r '.items[] | [.created_at, (.repository_url | sub(".*/repos/"; "")), (if .pull_request then "PR" else "Issue" end), "#\(.number)", .state, .title, .html_url] | @tsv' \
      "$TMP" > "$OUT/inventory/suspect_prs_issues.tsv"
    pn=$(wc -l < "$OUT/inventory/suspect_prs_issues.tsv" | tr -d ' ')
    [ "$pn" -gt 0 ] && hit REVIEW "$ORG" prs_issues_by_suspect "$pn PRs or issues by $SUSPECT (inventory/suspect_prs_issues.tsv)"
  fi
  : > "$OUT/inventory/suspect_commits.tsv"
  for role in author committer; do
    if api_get "search_commits_$role" -X GET search/commits -f q="org:$ORG $role:$SUSPECT committer-date:>=$SINCE" -f per_page=100 --paginate; then
      jq -r --arg r "$role" '.items[] | [.commit.committer.date, .repository.full_name, .sha[0:7], $r, (.commit.message | split("\n")[0]), .html_url] | @tsv' \
        "$TMP" >> "$OUT/inventory/suspect_commits.tsv"
    fi
  done
  cn=$(sort -u -t$'\t' -k2,3 "$OUT/inventory/suspect_commits.tsv" | wc -l | tr -d ' ')
  [ "$cn" -gt 0 ] && hit REVIEW "$ORG" commits_by_suspect "$cn commits by $SUSPECT according to GitHub search (inventory/suspect_commits.tsv)"
fi
report_failed "$ORG"

# ========== PART B — per-repository checks ==========
# Load the repository list and run B1–B12 for each repository.
gh repo list "$ORG" --limit 5000 --json nameWithOwner --jq '.[].nameWithOwner' 2>>"$ERR" \
  | sort > "$OUT/repos.txt"
TOTAL=$(wc -l < "$OUT/repos.txt" | tr -d ' ')
[ "$TOTAL" -gt 0 ] || { echo "No repositories found. Check the organization name and GitHub CLI login."; exit 1; }
echo "$TOTAL repositories found. Cutoff date: $SINCE${SUSPECT:+, suspect account: $SUSPECT}"

i=0
while IFS= read -r R; do
  i=$((i+1))
  N="${R#*/}"
  M="$OUT/mirrors/$N.git"
  FAILED=""
  echo "[$i/$TOTAL] $R"

  # B1. Mirror clone (all branches, tags, and PR refs)
  if mirror_clone "$R" "$M" </dev/null 2>>"$ERR"; then

    # B2. Malicious code at the current tip of each branch.
    # Workflows with on: push can run on any branch that contains them.
    # Default branch → CRITICAL, other branches → HIGH.
    DEF=$(git -C "$M" symbolic-ref --quiet --short HEAD 2>/dev/null || true)
    git -C "$M" for-each-ref --format='%(refname)' refs/heads 2>/dev/null | while IFS= read -r ref; do
      # Skip binary files with -I to avoid coincidental byte matches for "wfx".
      files=$(git -C "$M" grep -I -E -l "$IOC" "$ref" -- 2>/dev/null | while IFS= read -r f; do
        printf '%s ' "${f#"$ref":}"
      done)
      b="${ref#refs/heads/}"
      if [ -n "$files" ]; then
        if [ "$b" = "$DEF" ]; then
          hit CRITICAL "$R" malicious_code_on_default_branch "$b: $files"
        else
          hit HIGH "$R" malicious_code_on_branch "$b: $files"
        fi
      fi
      # Weak content indicators are reported without classifying the repository as affected.
      weak=$(git -C "$M" grep -I -E -l "$IOC_WEAK" "$ref" -- 2>/dev/null | while IFS= read -r f; do
        printf '%s ' "${f#"$ref":}"
      done)
      [ -n "$weak" ] && hit HIGH "$R" suspicious_pattern "$b: $weak(Pass runtime / postinstall → .ci-*.sh – review the contents)"
      # Check campaign filenames, which can match even when the contents are obfuscated.
      # For .ci-xxxxxx.sh, only the known stealer hash classifies the repository as affected.
      # Other filename matches are HIGH with a digit in the name and REVIEW otherwise.
      git -C "$M" ls-tree -r --name-only "$ref" 2>/dev/null | while IFS= read -r f; do
        if [[ "$f" =~ $SUSP_FILE_HIDDEN ]]; then
          sha=$(git -C "$M" cat-file blob "$ref:$f" 2>/dev/null | shasum -a 256 | cut -c1-64)
          if [ "$sha" = "$STEALER_SHA256" ]; then
            d="$b: $f (known wfx stealer, sha256=$sha)"
            if [ "$b" = "$DEF" ]; then hit CRITICAL "$R" hidden_ci_file "$d"; else hit HIGH "$R" hidden_ci_file "$d"; fi
          else
            fn="${f##*/}"; st=REVIEW
            [[ "$fn" =~ [0-9] ]] && st=HIGH
            hit "$st" "$R" ci_filename_pattern "$b: $f sha256=$sha (filename matches the pattern, hash differs – review the contents)"
          fi
        elif [[ "$f" =~ $SUSP_FILE_WF ]]; then
          hit HIGH "$R" suspicious_workflow_name "$b: $f"
        fi
      done
    done

    # B3. Search history, including removed commits and PR refs.
    # Omit --since because commit dates can be forged and traversal can stop at
    # backdated commits. Record both the author and committer dates.
    # If either date meets the cutoff, malicious_code_in_history counts as affected.
    # If both precede it, malicious_code_in_older_history requires manual review for
    # old legitimate code (e.g. toJSON(secrets) from 2021) or a backdated attack.
    # Keep full commit SHAs to find the associated workflow logs in B12.
    # Also check commits that add a .ci-xxxxxx.sh file. Treat a known stealer hash
    # as malicious code and other matches as REVIEW / ci_file_in_history.
    # Report each commit at most once, checking filenames first.
    # $MALSHAS lists commits whose run logs take priority in B12 (B3 and B5c).
    MALSHAS="$OUT/inventory/${N}_suspicious_commits.txt"
    : > "$MALSHAS"
    {
      git -C "$M" log --all --diff-filter=A --name-only \
        --format='@@C@@%x09%H%x09%aI%x09%cI%x09%an <%ae>%x09%s' -- ':(glob)**/.ci-*.sh' 2>/dev/null \
        | awk -F'\t' '$1 == "@@C@@" { h = $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6; next }
                      h != "" && $0 ~ ENVIRON["SUSP_FILE_HIDDEN"] { print "F\t" h "\t" $0 }'
      git -C "$M" log --all -G "$IOC" \
        --format='G%x09%H%x09%aI%x09%cI%x09%an <%ae>%x09%s%x09-' 2>/dev/null
    } | { seen=" "; while IFS=$'\t' read -r src h ad cd who subj f; do
        extra=""
        if [ "$src" = F ]; then
          sha=$(git -C "$M" cat-file blob "$h:$f" 2>/dev/null | shasum -a 256 | cut -c1-64)
          if [ "$sha" != "$STEALER_SHA256" ]; then
            hit REVIEW "$R" ci_file_in_history "${h:0:9} | $ad | $who | $subj | adds: $f sha256=$sha (filename matches the pattern, hash differs)"
            continue
          fi
          extra="adds: $f (known wfx stealer)"
        fi
        case "$seen" in *" $h "*) continue ;; esac
        seen="$seen$h "
        line="${h:0:9} | autor $ad | committer $cd | $who | $subj${extra:+ | $extra}"
        if [[ ! "$ad" < "$SINCE" ]] || [[ ! "$cd" < "$SINCE" ]]; then
          printf '%s\n' "$h" >> "$MALSHAS"
          hit HIGH "$R" malicious_code_in_history "$line"
        else
          hit HIGH "$R" malicious_code_in_older_history "$line – both dates precede the cutoff. Review for old code or backdated commits"
        fi
      done; }

    # B4. List workflow and action changes since the cutoff for manual review.
    # This supplements B3 using commit dates, which can be forged.
    WF="$OUT/inventory/${N}_workflow_changes.txt"
    git -C "$M" log --all --since="$SINCE" --date=iso \
      --format='%h | %ad | %an <%ae> | %s' -- .github/workflows .github/actions \
      ':(glob)**/action.yml' ':(glob)**/action.yaml' > "$WF" 2>/dev/null
    wn=$(wc -l < "$WF" | tr -d ' ')
    if [ "$wn" -gt 0 ]; then hit REVIEW "$R" workflow_changes "$wn commits (inventory/${N}_workflow_changes.txt)"; else rm -f "$WF"; fi

    # B5. Suspicious branch names
    git -C "$M" for-each-ref --format='%(refname:short)' refs/heads 2>/dev/null \
      | grep -E "$SUSP_BRANCH" | while IFS= read -r b; do
        if weak_chore "$b"; then
          hit REVIEW "$R" suspicious_branch "$b (matches chore/xxxxxxxx without a digit. May be legitimate)"
        else
          hit HIGH "$R" suspicious_branch "$b"
        fi
      done

    # B5c. Campaign commit messages since the cutoff (weak signals → REVIEW).
    # Match generic messages such as "ci: cleanup" only when workflows or .ci-*.sh files change.
    # Record the SHAs so B12 can save logs from runs on those commits.
    {
      git -C "$M" log --all --since="$SINCE" --format='%H%x09%aI%x09%an <%ae>%x09%s' 2>/dev/null \
        | awk -F'\t' 'tolower($4) ~ ENVIRON["SUSP_MSG"]'
      git -C "$M" log --all --since="$SINCE" --format='%H%x09%aI%x09%an <%ae>%x09%s' \
        -- .github/workflows ':(glob)**/.ci-*.sh' 2>/dev/null \
        | awk -F'\t' 'tolower($4) ~ ENVIRON["SUSP_MSG_GENERIC"]'
    } | while IFS=$'\t' read -r h ad who subj; do
        printf '%s\n' "$h" >> "$MALSHAS"
        hit REVIEW "$R" suspicious_commit_message "${h:0:9} | $ad | $who | $subj"
      done

    # B5a. pull_request_target on the default branch can run with secrets for fork PRs.
    # Flag workflows that also check out PR code as HIGH ("Pwn Request").
    # Other pull_request_target findings are REVIEW.
    if [ -n "$DEF" ]; then
      git -C "$M" grep -l -F 'pull_request_target' "refs/heads/$DEF" -- .github/workflows 2>/dev/null \
        | while IFS= read -r f; do
          p="${f#refs/heads/"$DEF":}"
          if git -C "$M" show "$f" 2>/dev/null | grep -qE 'github\.event\.pull_request\.head|github\.head_ref|refs/pull/'; then
            hit HIGH "$R" pwn_request_pattern "$p (pull_request_target + checkout of PR code)"
          else
            hit REVIEW "$R" pull_request_target "$p"
          fi
        done
    fi

    # B5b. Suspect commits since the cutoff based on Git metadata.
    # Author names and emails can be forged. Cross-check inventory/suspect_commits.tsv.
    # Match full values to avoid partial matches such as "jan" and "Janina".
    # Match the login, its GitHub noreply address, or a comma-separated SUSPECT_EMAIL entry.
    if [ -n "$SUSPECT" ]; then
      SC="$OUT/inventory/${N}_suspect_commits.txt"
      git -C "$M" log --all --since="$SINCE" --date=iso \
        --format='%h%x09%ad%x09%an%x09%ae%x09%cn%x09%ce%x09%s' 2>/dev/null \
        | awk -F'\t' -v s="$SUSPECT" -v em="${SUSPECT_EMAIL:-}" '
            BEGIN { s = tolower(s); n = split(tolower(em), mails, ","); for (k = 1; k <= n; k++) { gsub(/ /, "", mails[k]); if (mails[k] != "") ok[mails[k]] = 1 } }
            function match_id(nm, ml) {
              nm = tolower(nm); ml = tolower(ml)
              return nm == s || (ml in ok) || ml == s "@users.noreply.github.com" || index(ml, "+" s "@users.noreply.github.com") > 0
            }
            match_id($3, $4) || match_id($5, $6) { print $1 "\t" $2 "\t" $3 " <" $4 ">\t" $5 " <" $6 ">\t" $7 }' > "$SC"
      sc=$(wc -l < "$SC" | tr -d ' ')
      if [ "$sc" -gt 0 ]; then hit REVIEW "$R" commits_by_suspect "$sc commits according to Git metadata (inventory/${N}_suspect_commits.txt)"; else rm -f "$SC"; fi
    fi
  else
    MALSHAS="$OUT/inventory/${N}_suspicious_commits.txt"
    : > "$MALSHAS"
    hit INFO "$R" clone_failed "repository may be empty or inaccessible. See errors.log"
  fi

  # B6. Probe PRs
  if gh pr list -R "$R" --state all --limit 200 --search "created:>=$SINCE" \
       --json number,title,author,createdAt,headRefName > "$TMP" 2>>"$ERR" </dev/null; then
    jq -r --arg b "$SUSP_BRANCH" '.[] | select((.title | test("dependency audit|security.?audit"; "i")) or (.headRefName | test($b) and ((startswith("chore/") and (test("[0-9]") | not)) | not))) | "#\(.number) \(.createdAt) \(.author.login) \(.headRefName) \(.title)"' \
      "$TMP" | while IFS= read -r p; do
        hit HIGH "$R" probe_pr "$p"
      done
  else
    FAILED="$FAILED probe_prs"
  fi

  # B7. Preserve workflow run records since the cutoff. Logs expire after retention.
  # The created filter silently caps API results at 1,000 runs. Fetch pages
  # newest first until reaching runs older than the cutoff.
  # Columns: created_at, actor, triggering_actor, event, branch, sha, workflow, conclusion, url, run_id
  RUNS="$OUT/runs/$N.tsv"
  : > "$RUNS"
  page=1
  while :; do
    api_get workflow_runs -X GET "repos/$R/actions/runs" -f per_page=100 -f page="$page" || break
    jq -r --arg s "$SINCE" '.workflow_runs[] | select(.created_at >= $s)
      | [.created_at, .actor.login, .triggering_actor.login, .event, .head_branch, .head_sha, .name, (.conclusion // "in_progress"), .html_url, .id] | @tsv' \
      "$TMP" >> "$RUNS"
    n=$(jq '.workflow_runs | length' "$TMP")
    oldest=$(jq -r '.workflow_runs[-1].created_at // ""' "$TMP")
    [ "$n" -lt 100 ] && break
    [[ "$oldest" < "$SINCE" ]] && break
    page=$((page+1))
  done
  if [ -n "$SUSPECT" ] && [ -s "$RUNS" ]; then
    sn=$(awk -F'\t' -v s="$SUSPECT" '$2 == s || $3 == s' "$RUNS" | wc -l | tr -d ' ')
    [ "$sn" -gt 0 ] && hit REVIEW "$R" runs_by_suspect "$sn runs by $SUSPECT (runs/$N.tsv)"
  fi

  # B8. Campaign artifacts and caches
  if api_get artifacts "repos/$R/actions/artifacts?per_page=100" --paginate; then
    jq -r '.artifacts[] | select(.name | test("^wfx")) | "\(.name) \(.created_at)"' "$TMP" \
      | while IFS= read -r a; do hit HIGH "$R" wfx_artifact "$a"; done
  fi
  if api_get caches "repos/$R/actions/caches?per_page=100" --paginate; then
    jq -r '.actions_caches[] | select(.key | test("^wfx")) | "\(.key) \(.created_at)"' "$TMP" \
      | while IFS= read -r c; do hit HIGH "$R" wfx_cache "$c"; done
  fi

  # B9. Webhooks, deploy keys, and outside collaborators (requires repository admin permissions)
  if api_get repo_webhooks "repos/$R/hooks?per_page=100" --paginate; then
    # Created or updated
    jq -r --arg s "$SINCE" '.[] | select(.created_at >= $s or .updated_at >= $s)
      | "\(.config.url) created_at=\(.created_at) updated_at=\(.updated_at)"' "$TMP" \
      | while IFS= read -r h; do hit HIGH "$R" webhook_created_or_updated "$h"; done
  fi
  if api_get deploy_keys "repos/$R/keys?per_page=100" --paginate; then
    jq -r --arg s "$SINCE" '.[] | select(.created_at >= $s)
      | "\(.title) created_at=\(.created_at) read_only=\(.read_only)"' "$TMP" \
      | while IFS= read -r k; do hit HIGH "$R" new_deploy_key "$k"; done
  fi
  if api_get outside_collaborators "repos/$R/collaborators?affiliation=outside&per_page=100" --paginate; then
    jq -r '.[].login' "$TMP" | while IFS= read -r u; do
      printf '%s\t%s\n' "$R" "$u" >> "$OUT/inventory/outside_collaborators.tsv"
    done
  fi

  # B10. Secrets available to repository workflows (used by rotation.tsv)
  if api_get repo_secrets "repos/$R/actions/secrets?per_page=100" --paginate; then
    record_secrets "$R" repo
  fi
  if api_get org_secrets_available_to_repo "repos/$R/actions/organization-secrets?per_page=100" --paginate; then
    # Inventory only. Organization secret changes are reported at organization level.
    jq -r --arg r "$R" '.secrets[] | [$r, "org", .name, .created_at, .updated_at] | @tsv' "$TMP" >> "$SECRETS"
  fi
  if api_get dependabot_secrets "repos/$R/dependabot/secrets?per_page=100" --paginate; then
    record_secrets "$R" dependabot
  fi
  if api_get environments "repos/$R/environments?per_page=100" --paginate; then
    envs=$(jq -r '.environments[]? | "\(.name | @uri)\t\(.name)"' "$TMP")
    if [ -n "$envs" ]; then
      while IFS=$'\t' read -r enc name; do
        if api_get "environment_secrets:$name" "repos/$R/environments/$enc/secrets?per_page=100" --paginate; then
          record_secrets "$R" "environment:$name"
        fi
      done <<< "$envs"
    fi
  fi

  # B11. Repository self-hosted runners (always REVIEW)
  if api_get repo_runner "repos/$R/actions/runners?per_page=100" --paginate; then
    jq -r --arg r "$R" '.runners[] | [$r, .name, .os, .status, ([.labels[].name] | join(","))] | @tsv' "$TMP" \
      | tee -a "$RUNNERS" | while IFS=$'\t' read -r _ rname ros rstat rlab; do
        hit REVIEW "$R" self_hosted_runner_repo "$rname ($ros, $rstat, $rlab)"
      done
  fi

  # B12. Save workflow logs before they expire.
  # Prioritize runs on suspicious commits (B3, B5c), by the suspect account,
  # on suspicious branches, or with "wfx" in the workflow name.
  # In affected repositories (AFFECT_CHECKS), also select other runs since the cutoff.
  # Save suspicious runs first to prioritize them within MAX_LOGS.
  if [ -s "$RUNS" ]; then
    susp=$(awk -F'\t' -v s="$SUSPECT" -v b="$SUSP_BRANCH" \
      'FILENAME == ARGV[1] { m[$0] = 1; next }
       ($6 in m) || (s != "" && ($2 == s || $3 == s)) || ($5 ~ b && !($5 ~ /^chore\// && $5 !~ /[0-9]/)) || tolower($7) ~ /wfx|dependency audit|github actions security/ { print $10 }' \
      "$MALSHAS" "$RUNS")
    if awk -F'\t' -v r="$R" -v c="$AFFECT_CHECKS" '$2 == r && $3 ~ c { f=1 } END { exit !f }' "$REPORT"; then
      sel=$( { printf '%s\n' "$susp"; cut -f10 "$RUNS"; } | awk 'NF && !seen[$0]++')
    else
      sel="$susp"
    fi
    if [ -n "$sel" ]; then
      ln=$(printf '%s\n' "$sel" | wc -l | tr -d ' ')
      LD="$OUT/logs/$N"
      mkdir -p "$LD"
      ok=0; bad=0
      while IFS= read -r id; do
        if gh api "repos/$R/actions/runs/$id/logs" > "$LD/$id.zip" 2>>"$ERR" </dev/null; then
          ok=$((ok+1))
        else
          rm -f "$LD/$id.zip"; bad=$((bad+1))
        fi
      done <<< "$(printf '%s\n' "$sel" | head -n "$MAX_LOGS")"
      [ "$ok" -gt 0 ] || rmdir "$LD" 2>/dev/null
      msg="$ok logs saved to logs/$N/"
      [ "$bad" -gt 0 ] && msg="$msg, $bad unavailable (possibly expired or deleted)"
      hit INFO "$R" logs_saved "$msg"
      [ "$ln" -gt "$MAX_LOGS" ] && hit INFO "$R" log_limit_reached "saved only $MAX_LOGS of $ln logs. Run again with MAX_LOGS=$ln"
    fi
  fi
  [ -s "$RUNS" ] || rm -f "$RUNS"
  [ -s "$MALSHAS" ] || rm -f "$MALSHAS"

  report_failed "$R"
done < "$OUT/repos.txt"
rm -f "$TMP"

# ========== PART C — final steps ==========
# C1. Rotation list
# Include secrets accessible to workflows in affected repositories (AFFECT_CHECKS).
# The GhostAction toJSON(secrets) pattern accesses repository, environment, and available organization secrets.
# Include Dependabot secrets as well, although they are visible only to Dependabot runs.
ROT="$OUT/rotation.tsv"
AFFECTED=$(awk -F'\t' -v o="$ORG" -v c="$AFFECT_CHECKS" 'NR > 1 && $2 != o && $3 ~ c { print $2 }' "$REPORT" | sort -u)
printf 'repo\tscope\tname\tcreated_at\tupdated_at\n' > "$ROT"
if [ -n "$AFFECTED" ]; then
  awk -F'\t' 'NR == FNR { a[$1] = 1; next } FNR > 1 && ($1 in a)' <(printf '%s\n' "$AFFECTED") "$SECRETS" \
    | sort -t$'\t' -k2,2 -k3,3 >> "$ROT"
fi

# C2. Evidence archive, checksum, and summary
echo "Creating evidence archive and checksum …"
if tar -czf "$OUT/evidence.tgz" -C "$OUT" mirrors runs logs inventory 2>>"$ERR"; then
  shasum -a 256 "$OUT/evidence.tgz" > "$OUT/evidence.tgz.sha256"
fi

echo
echo "Done. Findings: $REPORT"
for s in CRITICAL HIGH REVIEW INFO; do
  printf '  %-9s %s\n' "$s" "$(grep -c "^$s	" "$REPORT")"
done
if [ -n "$AFFECTED" ]; then
  rn=$(tail -n +2 "$ROT" | cut -f2,3 | sort -u | wc -l | tr -d ' ')
  echo
  echo "Affected repositories: $(printf '%s\n' "$AFFECTED" | wc -l | tr -d ' ') – secrets to rotate: $rn (see $ROT)"
  echo "Also review credentials and access that workflows obtain at runtime, such as OIDC roles and cloud keys from vaults."
fi
