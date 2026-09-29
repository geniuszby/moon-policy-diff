///|
test "groups distinguish local and cross-tenant effects" {
  let universe = parse_universe(
      "principal alice a reader -\nresource a-doc document a -\nresource b-doc document b -\nrequest alice read a-doc -\nrequest alice read b-doc -",
    ).universe
  let after = parse_policy(
      "policy after\nrule permit permit reader read document - any -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let groups = group_changes(report, universe)
  assert_eq(groups.length(), 2)
  assert_eq(cross_tenant_change_count(groups), 1)
  assert_eq(groups[0].new_grants, 1)
  assert_eq(groups[1].new_grants, 1)
}

///|
test "incomplete reports have no aggregate claims" {
  let universe = empty_universe()
  let report = compare_policies(empty_policy("a"), empty_policy("b"), universe)
  assert_eq(group_changes(report, universe).length(), 0)
}
