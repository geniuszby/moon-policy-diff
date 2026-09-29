///|
test "strict gate rejects a new cross-tenant grant" {
  let universe = parse_universe(
      "principal alice tenant-a reader -\nresource report report tenant-b -\nrequest alice read report -",
    ).universe
  let rule : AccessRule = {
    id: "allow",
    effect: Permit,
    roles: ["reader"],
    actions: ["read"],
    resource_kinds: ["report"],
    resource_ids: [],
    tenant_relation: AnyTenant,
    conditions: [],
  }
  let after : AccessPolicy = {
    name: "after",
    role_inheritance: [],
    rules: [rule],
  }
  let report = compare_policies(empty_policy("before"), after, universe)
  let gate = check_gate(report, universe, strict_gate())
  assert_true(gate.verdict is Fail)
  assert_eq(gate.findings.length(), 2)
}

///|
test "incomplete report cannot pass a gate" {
  let universe = empty_universe()
  let report = compare_policies(empty_policy("a"), empty_policy("b"), universe)
  assert_true(
    check_gate(report, universe, strict_gate()).verdict is Indeterminate,
  )
}
