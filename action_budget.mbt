///|
pub(all) struct ActionBudget {
  action : String
  max_new_grants : Int
  max_revocations : Int
} derive(Debug)

///|
fn budget_for_action(
  budgets : Array[ActionBudget],
  action : String,
) -> ActionBudget {
  for budget in budgets {
    if budget.action == action {
      return budget
    }
  }
  { action, max_new_grants: 0, max_revocations: 0, }
}

///|
fn count_action_changes(
  report : AuditReport,
  action : String,
  kind : ChangeKind,
) -> Int {
  let mut count = 0
  for change in report.changes {
    if change.request.action == action && change.kind == kind {
      count += 1
    }
  }
  count
}

///|
/// Independent per-action budgets. Unlisted actions have a zero budget.
/// This gate complements the tenant-aware strict gate.
pub fn check_action_budgets(
  report : AuditReport,
  budgets : Array[ActionBudget],
) -> GateResult {
  let findings : Array[GateFinding] = []
  if !report.complete {
    return { verdict: Indeterminate, findings, }
  }
  let seen : Array[String] = []
  for budget in budgets {
    if !is_valid_identifier(budget.action) ||
      budget.max_new_grants < 0 ||
      budget.max_revocations < 0 ||
      seen.contains(budget.action) {
      return { verdict: Indeterminate, findings, }
    }
    seen.push(budget.action)
  }
  let actions : Array[String] = []
  for change in report.changes {
    if !actions.contains(change.request.action) {
      actions.push(change.request.action)
    }
  }
  for action in actions {
    let budget = budget_for_action(budgets, action)
    let grants = count_action_changes(report, action, NewGrant)
    let revocations = count_action_changes(report, action, RevokedGrant)
    if grants > budget.max_new_grants {
      for change in report.changes {
        if change.request.action == action && change.kind is NewGrant {
          findings.push({
            code: "ACTION_GRANT_BUDGET",
            request: change.request,
            message: "new grants for \{action} exceed its budget",
          })
        }
      }
    }
    if revocations > budget.max_revocations {
      for change in report.changes {
        if change.request.action == action && change.kind is RevokedGrant {
          findings.push({
            code: "ACTION_REVOCATION_BUDGET",
            request: change.request,
            message: "revocations for \{action} exceed its budget",
          })
        }
      }
    }
  }
  { verdict: if findings.length() == 0 { Pass } else { Fail }, findings, }
}
