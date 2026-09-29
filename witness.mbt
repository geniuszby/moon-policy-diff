///|
pub(all) struct WitnessGroup {
  kind : ChangeKind
  action : String
  resource_kind : String
  cross_tenant : Bool
  before_rules : Array[String]
  after_rules : Array[String]
  occurrences : Int
  example : AccessRequest
} derive(Debug)

///|
pub(all) struct WitnessSelection {
  groups : Array[WitnessGroup]
  total_changed_requests : Int
  omitted_groups : Int
  complete : Bool
} derive(Debug)

///|
fn resource_kind(universe : RequestUniverse, id : String) -> String {
  for resource in universe.resources {
    if resource.id == id {
      return resource.kind
    }
  }
  ""
}

///|
fn same_signature(a : WitnessGroup, b : WitnessGroup) -> Bool {
  a.kind == b.kind &&
  a.action == b.action &&
  a.resource_kind == b.resource_kind &&
  a.cross_tenant == b.cross_tenant &&
  a.before_rules == b.before_rules &&
  a.after_rules == b.after_rules
}

///|
/// Picks one representative request per decision signature. The first
/// request in input order is retained. This is a compact review view, while
/// the full audit report remains the source of all individual changes.
pub fn select_witnesses(
  report : AuditReport,
  universe : RequestUniverse,
  max_groups : Int,
) -> WitnessSelection {
  let groups : Array[WitnessGroup] = []
  if !report.complete || max_groups < 1 {
    return {
      groups,
      total_changed_requests: 0,
      omitted_groups: 0,
      complete: false,
    }
  }
  let mut total_changed = 0
  let mut omitted = 0
  let suppressed_signatures : Array[WitnessGroup] = []
  for change in report.changes {
    if !(change.kind is NewGrant ||
      change.kind is RevokedGrant ||
      change.kind is Inconclusive) {
      continue
    }
    total_changed += 1
    let source_tenant = principal_tenant(universe, change.request.principal_id)
    let target_tenant = resource_tenant(universe, change.request.resource_id)
    let candidate : WitnessGroup = {
      kind: change.kind,
      action: change.request.action,
      resource_kind: resource_kind(universe, change.request.resource_id),
      cross_tenant: source_tenant != target_tenant,
      before_rules: change.before.decisive_rules,
      after_rules: change.after.decisive_rules,
      occurrences: 1,
      example: change.request,
    }
    let mut index = -1
    for i, existing in groups {
      if same_signature(existing, candidate) {
        index = i
        break
      }
    }
    if index >= 0 {
      groups[index] = {
        ..groups[index],
        occurrences: groups[index].occurrences + 1,
      }
    } else if groups.length() < max_groups {
      groups.push(candidate)
    } else {
      let mut seen = false
      for suppressed in suppressed_signatures {
        if same_signature(suppressed, candidate) {
          seen = true
          break
        }
      }
      if !seen {
        suppressed_signatures.push(candidate)
        omitted += 1
      }
    }
  }
  {
    groups,
    total_changed_requests: total_changed,
    omitted_groups: omitted,
    complete: omitted == 0,
  }
}

///|
pub fn render_witnesses(selection : WitnessSelection) -> String {
  let out = StringBuilder()
  out.write_string("Changed requests: \{selection.total_changed_requests}\n")
  out.write_string("Representative groups: \{selection.groups.length()}\n")
  out.write_string("Complete grouping: \{selection.complete}\n")
  for group in selection.groups {
    out.write_string(
      "\{change_name(group.kind)} \{group.action} \{group.resource_kind} cross-tenant=\{group.cross_tenant} count=\{group.occurrences}\n",
    )
    out.write_string(
      "  witness: \{group.example.principal_id} \{group.example.action} \{group.example.resource_id}\n",
    )
    out.write_string("  old rules: ")
    write_ids(out, group.before_rules)
    out.write_string("\n  new rules: ")
    write_ids(out, group.after_rules)
    out.write_string("\n")
  }
  if selection.omitted_groups > 0 {
    out.write_string("Omitted distinct groups: \{selection.omitted_groups}\n")
  }
  out.to_string()
}
