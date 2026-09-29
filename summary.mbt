///|
pub(all) struct ChangeGroup {
  principal_tenant : String
  resource_tenant : String
  action : String
  new_grants : Int
  revocations : Int
  unchanged : Int
  inconclusive : Int
} derive(Debug)

///|
fn group_index(
  groups : Array[ChangeGroup],
  principal_tenant : String,
  resource_tenant : String,
  action : String,
) -> Int {
  for index, group in groups {
    if group.principal_tenant == principal_tenant &&
      group.resource_tenant == resource_tenant &&
      group.action == action {
      return index
    }
  }
  -1
}

///|
/// Groups decisions by subject tenant, resource tenant, and action.
/// This is an aggregate over the explicit sample, not a population estimate.
pub fn group_changes(
  report : AuditReport,
  universe : RequestUniverse,
) -> Array[ChangeGroup] {
  let groups : Array[ChangeGroup] = []
  if !report.complete {
    return groups
  }
  for change in report.changes {
    let source_tenant = principal_tenant(universe, change.request.principal_id)
    let target_tenant = resource_tenant(universe, change.request.resource_id)
    let index = group_index(
      groups,
      source_tenant,
      target_tenant,
      change.request.action,
    )
    let current = if index >= 0 {
      groups[index]
    } else {
      {
        principal_tenant: source_tenant,
        resource_tenant: target_tenant,
        action: change.request.action,
        new_grants: 0,
        revocations: 0,
        unchanged: 0,
        inconclusive: 0,
      }
    }
    let mut next = current
    match change.kind {
      NewGrant => next = { ..next, new_grants: next.new_grants + 1, }
      RevokedGrant => next = { ..next, revocations: next.revocations + 1, }
      UnchangedAllow | UnchangedDeny =>
        next = { ..next, unchanged: next.unchanged + 1, }
      Inconclusive => next = { ..next, inconclusive: next.inconclusive + 1, }
    }
    if index >= 0 {
      groups[index] = next
    } else {
      groups.push(next)
    }
  }
  groups
}

///|
pub fn render_groups(groups : Array[ChangeGroup]) -> String {
  let out = StringBuilder()
  out.write_string("Tenant/action groups: \{groups.length()}\n")
  for group in groups {
    out.write_string(
      "\{group.principal_tenant} -> \{group.resource_tenant} / \{group.action}: +\{group.new_grants} -\{group.revocations} =\{group.unchanged} ?\{group.inconclusive}\n",
    )
  }
  out.to_string()
}

///|
pub fn cross_tenant_change_count(groups : Array[ChangeGroup]) -> Int {
  let mut count = 0
  for group in groups {
    if group.principal_tenant != group.resource_tenant {
      count += group.new_grants + group.revocations
    }
  }
  count
}
