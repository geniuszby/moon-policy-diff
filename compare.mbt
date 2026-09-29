///|
pub fn classify_change(before : Decision, after : Decision) -> ChangeKind {
  match (before.kind, after.kind) {
    (Denied, Allowed) => NewGrant
    (Allowed, Denied) => RevokedGrant
    (Allowed, Allowed) => UnchangedAllow
    (Denied, Denied) => UnchangedDeny
    _ => Inconclusive
  }
}

///|
/// Every claim is scoped to the supplied request universe. Invalid input
/// returns an incomplete report and never silently asserts equivalence.
pub fn compare_policies(
  before : AccessPolicy,
  after : AccessPolicy,
  universe : RequestUniverse,
) -> AuditReport {
  let diagnostics : Array[Diagnostic] = []
  for issue in validate_policy(before) {
    diagnostics.push(issue)
  }
  for issue in validate_policy(after) {
    diagnostics.push(issue)
  }
  for issue in validate_universe(universe) {
    diagnostics.push(issue)
  }
  let changes : Array[DecisionChange] = []
  if has_errors(diagnostics) {
    return {
      before_name: before.name,
      after_name: after.name,
      requests_considered: 0,
      changes,
      diagnostics,
      complete: false,
    }
  }
  for request in universe.requests {
    let old_decision = evaluate_request(before, universe, request)
    let new_decision = evaluate_request(after, universe, request)
    changes.push({
      request,
      before: old_decision,
      after: new_decision,
      kind: classify_change(old_decision, new_decision),
    })
  }
  {
    before_name: before.name,
    after_name: after.name,
    requests_considered: universe.requests.length(),
    changes,
    diagnostics,
    complete: true,
  }
}

///|
pub fn count_changes(report : AuditReport, kind : ChangeKind) -> Int {
  let mut count = 0
  for change in report.changes {
    if change.kind == kind {
      count += 1
    }
  }
  count
}

///|
pub fn find_witnesses(
  report : AuditReport,
  kind : ChangeKind,
) -> Array[DecisionChange] {
  let witnesses : Array[DecisionChange] = []
  for change in report.changes {
    if change.kind == kind {
      witnesses.push(change)
    }
  }
  witnesses
}
