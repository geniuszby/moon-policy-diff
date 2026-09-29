///|
pub(all) enum RuleDeltaKind {
  AddedRule
  RemovedRule
  ModifiedRule
  UnchangedRule
} derive(Eq, Debug)

///|
pub(all) struct RuleDelta {
  rule_id : String
  kind : RuleDeltaKind
} derive(Debug)

///|
pub(all) struct StructuralDiff {
  rules : Array[RuleDelta]
  added_role_edges : Array[RoleInheritance]
  removed_role_edges : Array[RoleInheritance]
} derive(Debug)

///|
fn has_edge(edges : Array[RoleInheritance], target : RoleInheritance) -> Bool {
  for edge in edges {
    if edge.child == target.child && edge.parent == target.parent {
      return true
    }
  }
  false
}

///|
/// Lists syntactic policy changes by stable rule ID and directed role edge.
/// It complements, but cannot replace, behavioral comparison on requests.
pub fn structural_diff(
  before : AccessPolicy,
  after : AccessPolicy,
) -> StructuralDiff {
  let rules : Array[RuleDelta] = []
  for old_rule in before.rules {
    match find_rule(after, old_rule.id) {
      None => rules.push({ rule_id: old_rule.id, kind: RemovedRule, })
      Some(new_rule) =>
        if new_rule == old_rule {
          rules.push({ rule_id: old_rule.id, kind: UnchangedRule, })
        } else {
          rules.push({ rule_id: old_rule.id, kind: ModifiedRule, })
        }
    }
  }
  for new_rule in after.rules {
    if find_rule(before, new_rule.id) is None {
      rules.push({ rule_id: new_rule.id, kind: AddedRule, })
    }
  }
  let added_role_edges : Array[RoleInheritance] = []
  let removed_role_edges : Array[RoleInheritance] = []
  for edge in after.role_inheritance {
    if !has_edge(before.role_inheritance, edge) {
      added_role_edges.push(edge)
    }
  }
  for edge in before.role_inheritance {
    if !has_edge(after.role_inheritance, edge) {
      removed_role_edges.push(edge)
    }
  }
  { rules, added_role_edges, removed_role_edges, }
}

///|
fn delta_name(kind : RuleDeltaKind) -> String {
  match kind {
    AddedRule => "ADDED"
    RemovedRule => "REMOVED"
    ModifiedRule => "MODIFIED"
    UnchangedRule => "UNCHANGED"
  }
}

///|
pub fn render_structural_diff(diff : StructuralDiff) -> String {
  let out = StringBuilder()
  out.write_string("Structural policy changes\n")
  for rule in diff.rules {
    if !(rule.kind is UnchangedRule) {
      out.write_string("\{delta_name(rule.kind)} rule \{rule.rule_id}\n")
    }
  }
  for edge in diff.added_role_edges {
    out.write_string("ADDED role edge \{edge.child} -> \{edge.parent}\n")
  }
  for edge in diff.removed_role_edges {
    out.write_string("REMOVED role edge \{edge.child} -> \{edge.parent}\n")
  }
  out.to_string()
}
