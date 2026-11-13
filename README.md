# wfx-scan

Tools for investigating the **wfx** (since November 10, 2026) and **GhostAction**
(since October 2026) campaigns. The campaigns used compromised accounts to inject
code into GitHub Actions workflows and steal secrets and cloud credentials.

Both scanners are **read-only on GitHub** and write their results locally.

## Tools

| File | What it does | Who can use it |
|---|---|---|
| [`wfx-scan.sh`](wfx-scan.sh) | Scans organization repositories for campaign indicators, saves workflow run records and logs, inventories access and settings, and builds a secret rotation list. | Organization members with repository access. Owner and admin permissions enable additional checks. |
| [`audit-scan.sh`](audit-scan.sh) | Analyzes an exported audit log for security-relevant actions and suspect account activity. It can substitute for section A6 of the main scan. | Anyone with an export. An organization owner can export it. |
| [`audit-actions.sh`](audit-actions.sh) | Provides the shared list of security-relevant audit actions used by both scanners. | Loaded by the scanners. |

Start with `wfx-scan.sh`. If the organization lacks Enterprise Cloud, ask an owner
for a JSON audit log export and run `audit-scan.sh` as well. Both scanners write
`findings.tsv` in the same format so their findings can be combined.

### Quick start

If you have already signed in to GitHub CLI, run this from the directory containing the scripts:

```bash
./wfx-scan.sh my-org
```

Replace `my-org` with your GitHub organization name. The suspect's GitHub login
and the cutoff date are optional. The default cutoff is October 1, 2026.
See [Requirements](#requirements) for tools and permissions.

## `wfx-scan.sh`: Scan repositories

The scanner uses `git clone --mirror` and does not execute code from the repositories.

### Requirements

- macOS or Linux with `bash`, `git`, `jq`, `tar`, and `shasum`.
- [GitHub CLI](https://cli.github.com/) (`gh)), signed in with an account that
  can read the repositories you want to scan.
- Organization owner or repository admin permissions and additional token scopes
  for checks such as webhooks, apps, secrets, runners, and deploy keys. The
  audit log API requires GitHub Enterprise Cloud.

```bash
gh auth login
gh auth refresh -s admin:org_hook,admin:org,read:audit_log
```

Checks that fail because of missing permissions or scopes appear as
`INFO` findings with the identifier `check_unavailable`.

### Usage

```text
./wfx-scan.sh <org> [suspect-github-login] [since YYYY-MM-DD]
```

```bash
./wfx-scan.sh my-org example-user 2026-10-01
```

Use `""` as the second argument to set a cutoff without specifying a suspect login.

| Optional environment variable | Purpose |
|---|---|
| `MAX_LOGS` | Maximum workflow logs to save per repository (default 100). Suspicious runs take priority. |
| `SUSPECT_EMAIL` | Comma-separated Git email addresses to match against commit metadata. |

```bash
MAX_LOGS=300 SUSPECT_EMAIL="name@example.org" ./wfx-scan.sh my-org example-user 2026-10-01
```

A scan of around 200 repositories can take 20–60 minutes, plus additional time
to save logs. Mirror clones can occupy several GB.

### Results

The scanner writes to `wfx-scan-<org>-<timestamp>/`.

| File or directory | Contents |
|---|---|
| `findings.tsv` | All findings. Open in a spreadsheet and review `CRITICAL` rows first. |
| `rotation.tsv` | Names of secrets accessible to workflows in **affected** repositories. |
| `runs/` | Workflow runs since the cutoff, by repository. |
| `logs/` | ZIP logs for suspicious runs. In affected repositories, other runs since the cutoff are also eligible, up to `MAX_LOGS`. |
| `inventory/` | Workflow changes, malicious commits, secrets, runners, webhooks, deploy keys, outside collaborators, organization owners, apps, audit log, and suspect activity. |
| `mirrors/` | Repository mirror clones. |
| `evidence.tgz`, `evidence.tgz.sha256` | Archive of `mirrors/`, `runs/`, `logs/`, and `inventory/`, plus a SHA-256 checksum. |
| `errors.log` | Errors such as insufficient permissions. |

The scanner marks a repository as **affected** when it finds a strong campaign
indicator. Examples include malicious code on a branch, a malicious commit dated
at or after the cutoff, a helper file matching the known stealer's hash, or a
`wfx` artifact or cache. Review workflow runs and their logs to determine whether
the code ran. Other `HIGH` findings, such as `pwn_request_pattern`,
`suspicious_pattern`, `ci_filename_pattern`, new webhooks, and
`malicious_code_in_older_history`, warrant review and do not automatically add
secrets to `rotation.tsv`.

#### Severity levels

| Level | Meaning |
|---|---|
| **CRITICAL** | Malicious code or a hash match for the known `.ci-xxxxxx.sh` stealer on the current default branch. Investigate immediately. |
| **HIGH** | Malicious code on other branches or in history, suspicious branch or workflow filenames, weak content patterns, `.ci-xxxxxx.sh` names with digits, probe PRs, wfx artifacts or caches, new or updated webhooks, new deploy keys, “Pwn Request” patterns, or audit events involving the suspect account. |
| **REVIEW** | Workflow changes, campaign commit messages, `.ci-xxxxxx.sh` filename matches without a digit or found only in history (without a hash match), suspect activity, new or updated apps, updated secrets, self-hosted runners, security-relevant audit actions, or `pull_request_target`. |
| **INFO** | Checks that could not run, such as due to missing permissions or an empty repository, and log collection status. |

`malicious_code_in_older_history` means both commit timestamps precede the cutoff.
Review the match to distinguish old legitimate code from a possible backdated commit.

#### Indicators

The “Indicators” section of [`wfx-scan.sh`](wfx-scan.sh) lists the patterns. They
draw on analyses by SafeDep, Endor Labs, and Aikido (wfx) and StepSecurity
(GhostAction), as of November 13, 2026. SafeDep’s indicators of compromise (IOCs)
were a key source for the scanner’s wfx detection rules.
[SafeDep’s wfx IOC list](https://safedep.io/blog/github-actions-wfx-credential-stealer#indicators-of-compromise)

| Type | Indicators |
|---|---|
| Strong content indicators | `WF_SECRETS`, `WF_TG_BOTS`, `WF_CALLBACK`, Telegram bot API and chat ID, exfiltration IPs, a campaign token, `toJSON(secrets)`, and GhostAction indicators. |
| Weak content indicators | YAML step `name: Pass runtime` or a `package.json` postinstall script that calls `.ci-xxxxxx.sh`. |
| Filenames | `.ci-xxxxxx.sh` is classified as affected only when the SHA-256 matches the known stealer. Otherwise it is reported as `ci_filename_pattern` (the pattern also matches names such as `.ci-deploy.sh`). Workflow names include `.github/workflows/build-audit-*.yml` and `github_actions_security.yml`. |
| Branch names | `wfx…`, `ci-<number>-…`, `ci-check-<4 digits>`, and `chore/<8 characters>`. A `chore/` match without digits is `REVIEW` and is excluded from probe PR matching. |
| Commit messages | Examples include “chore: add dependency audit workflow”, “ci: refresh build cache”, and “chore: add ci helper”. Generic messages such as “ci: restore” and “ci: cleanup” only match commits that modify workflows or `.ci-*.sh` files. |
| Artifacts, caches, and PRs | `wfx-loot-*` artifacts, `wfx…` cache keys, and PR titles containing “dependency audit” or “security audit”. |

## `audit-scan.sh`: Analyze an audit log export

Without GitHub Enterprise Cloud, section A6 of `wfx-scan.sh` cannot use the audit
log API. An organization owner can export the audit log and run the same checks
with `audit-scan.sh`, which reads the export locally without network access.
The script requires `jq` and `shasum`.

In the organization settings, open **Archive → Logs → Audit log**, search for
`created:>=2026-10-01`, then select **Export → JSON**. Exports without Enterprise
Cloud omit Git push events.

```bash
./audit-scan.sh ../export-my-org.json example-user 2026-10-01
```

The scanner writes to `audit-scan-<timestamp>/`.

| File | Contents |
|---|---|
| `findings.tsv` | Findings in the same format as `wfx-scan.sh`. |
| `audit_log.tsv` | All events since the cutoff, sorted by time. |
| `suspect.tsv` | Timeline of the suspect account, if it has events. |
| `actions.tsv` | Event count by action. |
| `export.sha256` | Checksum of the original export. |

| Check | Severity |
|---|---|
| `audit_log_action` — security-relevant action by another account | REVIEW |
| `security_action_by_suspect` — security-relevant action by the suspect account | HIGH |
| `audit_log_suspect_summary` — total events by the suspect account | HIGH |
| `incomplete_time_range` — the export begins after the cutoff | INFO |
| `stale_export` — the last event is more than two days old | INFO |
| `missing_timestamp`, `invalid_timestamp`, `missing_action` — skipped events | INFO |

Each event appears at most once in `findings.tsv`. Login matching is
case-insensitive. The script reports an error if the input contains no objects
with an `action` field, for example if the JSON array is wrapped in another object.

All timestamps and the cutoff are in UTC. The date `2026-10-01` means midnight UTC
at the start of October 1.

Both scanners use [`audit-actions.sh`](audit-actions.sh) for security-relevant
actions. The list covers access mechanisms (webhooks, deploy keys, runners, apps,
and tokens), membership and permissions, repository changes, secrets and
variables, protection rules, Actions settings, and workflow reruns or deletions.

Keep the audit log export outside the repository directory, for example in its
parent directory. The export contains personal data. The `.gitignore` also
excludes JSON and CSV files.

## Handling scan results

- **Keep results private and out of Git.** They can include complete repository
  mirrors, workflow logs, secrets in Git history, and personal data in audit logs.
  The `.gitignore` excludes the standard outputs.
- Both scanners create their output directory in the current working directory.
- **Run the scanners locally.** The main scanner uses a token with repository read
  access. Running it in a GitHub Actions workflow would expose that credential to
  the workflow environment under investigation.
- After the investigation, store the results securely if you need to retain the
  evidence, or delete them.

## Development and review

The scanner was written with Opus 5.5 and reviewed by GPT-6.1 Sol.

## License

[MIT](LICENSE). The scanners look for known indicators. A scan with no findings
cannot establish that an organization was unaffected.
