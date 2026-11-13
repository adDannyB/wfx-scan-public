# audit-actions.sh — Shared list of security-relevant audit log actions.
# Sourced by wfx-scan.sh (A6) and audit-scan.sh (P1/P3) so both scans use
# the same list.
#
# Action names were checked against GitHub's “Audit log events for your organization”
# documentation (docs.github.com, as of 2026-11-13).
#
# Groups (REVIEW for other accounts, HIGH for the suspect account):
#   Access and backdoors  hook.*, public_key.create (deploy keys), *register_self_hosted_runner,
#                         integration_installation.*, oauth_application.*,
#                         org.oauth_app_access_approved, personal_access_token.*
#   Members and roles     org.add_member / update_member (role changes) / remove_member /
#                         add_outside_collaborator / remove_outside_collaborator,
#                         organization_role.assign / revoke, team.add_member,
#                         repo.add_member / update_member / remove_member
#   Repositories          repo.access (visibility), repo.create / transfer / destroy
#   Secrets and variables *actions_secret* (organization, repository, environment), *integration_secret*
#                         (Dependabot/Codespaces), *actions_variable*
#   Protection rules      protected_branch.destroy / policy_override / update*, repository_ruleset.*,
#                         environment.add|update|remove_protection_rule,
#                         org.disable_two_factor_requirement,
#                         *secret_scanning_push_protection* (bypass, disabling, bypass lists)
#   Actions settings      org|repo.update_actions_settings, repo.actions_enabled,
#                         org|repo.set_default_workflow_permissions (GITHUB_TOKEN permissions),
#                         org|repo.set_*fork_pr*_policy, org|repo.set_workflow_permission_can_approve_pr
#   Workflow runs         workflows.rerun_workflow_run (reruns historical code),
#                         workflows.delete_workflow_run (can remove evidence), workflows.enable|disable_workflow
#
# Pass the pattern to awk through ENVIRON to preserve backslashes.
# With awk -v, "^hook\.create" could become "^hook.create" and also match "hookXcreate".

SEC_ACTIONS='^hook\.|^public_key\.create|register_self_hosted_runner|^integration_installation\.|^oauth_application\.|^org\.oauth_app_access_approved|^personal_access_token\.|^org\.(add_member|update_member|remove_member|add_outside_collaborator|remove_outside_collaborator|disable_two_factor_requirement)|^organization_role\.(assign|revoke)|^team\.add_member|^repo\.(add_member|update_member|remove_member|access|create|transfer|destroy|actions_enabled)|actions_secret|integration_secret|actions_variable|^protected_branch\.(destroy|policy_override|update)|^repository_ruleset\.|^environment\.(add|update|remove)_protection_rule|secret_scanning_push_protection|^(org|repo)\.(update_actions_settings|set_default_workflow_permissions|set_actions_fork_pr_approvals_policy|set_actions_private_fork_pr_approvals_policy|set_fork_pr_workflows_policy|set_workflow_permission_can_approve_pr)|^workflows\.(rerun_workflow_run|delete_workflow_run|enable_workflow|disable_workflow)'
export SEC_ACTIONS
