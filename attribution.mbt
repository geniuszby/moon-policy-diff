///|
pub(all) enum ChangeCause {
  RuleRevision
  RoleInheritanceRevision
  EitherRevision
  CombinedRevision
  Unattributed
} derive(Eq, Debug)

///|
pub(all) struct AttributedChange {
  request : AccessRequest
  kind : ChangeKind
  cause : ChangeCause
  changed_rule_ids : Array[String]
  role_edges_changed : Bool
} derive(Debug)

///|
fn find_rule(policy : AccessPolicy, id : String) -> AccessRule? {
  for rule in policy.rules {
    if rule.id == id {
      return Some(rule)
    }
  }
  None
}

///|
fn changed_rules(before : AccessPolicy, after : AccessPolicy) -> Array[String] {
  let changed : Array[String] = []
  for rule in before.rules {
    match find_rule(after, rule.id) {
      None => changed.push(rule.id)
      Some(next) => if next != rule { changed.push(rule.id) }
    }
  }
  for rule in after.rules {
    if find_rule(before, rule.id) is None {
      changed.push(rule.id)
    }
  }
  changed
}

///|
fn target_decision(
  policy : AccessPolicy,
  universe : RequestUniverse,
  request : AccessRequest,
  target : DecisionKind,
) -> Bool {
  evaluate_request(policy, universe, request).kind == target
}

///|
/// A two-factor counterfactual: swap only the rules, then only the role graph.
/// The result explains the observed decision for the supplied request and
/// these two policy dimensions; it is not a general causal proof.
pub fn attribute_changes(
  before : AccessPolicy,
  after : AccessPolicy,
  universe : RequestUniverse,
) -> Array[AttributedChange] {
  let result : Array[AttributedChange] = []
  let report = compare_policies(before, after, universe)
  if !report.complete {
    return result
  }
  let rule_ids = changed_rules(before, after)
  let edges_changed = before.role_inheritance != after.role_inheritance
  let rule_only : AccessPolicy = {
    name: "rule-counterfactual",
    role_inheritance: before.role_inheritance,
    rules: after.rules,
  }
  let role_only : AccessPolicy = {
    name: "role-counterfactual",
    role_inheritance: after.role_inheritance,
    rules: before.rules,
  }
  for change in report.changes {
    if change.kind is NewGrant || change.kind is RevokedGrant {
      let rules_reach_target = target_decision(
        rule_only,
        universe,
        change.request,
        change.after.kind,
      )
      let roles_reach_target = target_decision(
        role_only,
        universe,
        change.request,
        change.after.kind,
      )
      let cause = match (rules_reach_target, roles_reach_target) {
        (true, true) => EitherRevision
        (true, false) => RuleRevision
        (false, true) => RoleInheritanceRevision
        (false, false) =>
          if rule_ids.length() > 0 && edges_changed {
            CombinedRevision
          } else {
            Unattributed
          }
      }
      result.push({
        request: change.request,
        kind: change.kind,
        cause,
        changed_rule_ids: rule_ids,
        role_edges_changed: edges_changed,
      })
    }
  }
  result
}

///|
pub fn cause_name(cause : ChangeCause) -> String {
  match cause {
    RuleRevision => "rule revision"
    RoleInheritanceRevision => "role inheritance revision"
    EitherRevision => "either revision independently"
    CombinedRevision => "combined rule and role revisions"
    Unattributed => "unattributed"
  }
}

///|
pub fn render_attribution(changes : Array[AttributedChange]) -> String {
  let out = StringBuilder()
  out.write_string("Attributed permission changes: \{changes.length()}\n")
  for change in changes {
    out.write_string(
      "\{change_name(change.kind)} \{change.request.principal_id} \{change.request.action} \{change.request.resource_id}: \{cause_name(change.cause)}\n",
    )
    out.write_string("  changed rules: ")
    write_ids(out, change.changed_rule_ids)
    out.write_string("\n")
  }
  out.to_string()
}
