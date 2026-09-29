///|
test "new grant includes request and rule witnesses" {
  let before = empty_policy("before")
  let allow : AccessRule = {
    id: "read",
    effect: Permit,
    roles: ["reader"],
    actions: ["read"],
    resource_kinds: ["invoice"],
    resource_ids: [],
    tenant_relation: SameTenant,
    conditions: [],
  }
  let after : AccessPolicy = {
    name: "after",
    role_inheritance: [],
    rules: [allow],
  }
  let universe = parse_universe(
      "principal alice acme reader -\nresource inv invoice acme -\nrequest alice read inv -",
    ).universe
  let report = compare_policies(before, after, universe)
  assert_true(report.complete)
  assert_eq(count_changes(report, NewGrant), 1)
  assert_eq(report.changes[0].after.decisive_rules[0], "read")
}

///|
test "invalid universe cannot produce an equivalence claim" {
  let report = compare_policies(
    empty_policy("a"),
    empty_policy("b"),
    empty_universe(),
  )
  assert_false(report.complete)
  assert_eq(report.requests_considered, 0)
}
