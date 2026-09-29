///|
test "representative witness groups keep cross tenant cases distinct" {
  let universe = parse_universe(
      "principal alice a reader -\nresource local document a -\nresource remote document b -\nrequest alice read local -\nrequest alice read remote -",
    ).universe
  let after = parse_policy(
      "policy after\nrule read permit reader read document - any -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let selected = select_witnesses(report, universe, 10)
  assert_true(selected.complete)
  assert_eq(selected.groups.length(), 2)
  assert_false(selected.groups[0].cross_tenant)
  assert_true(selected.groups[1].cross_tenant)
}

///|
test "group cap is explicit rather than silently dropping groups" {
  let universe = parse_universe(
      "principal alice a reader -\nresource local document a -\nresource remote document b -\nrequest alice read local -\nrequest alice read remote -",
    ).universe
  let after = parse_policy(
      "policy after\nrule read permit reader read document - any -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let selected = select_witnesses(report, universe, 1)
  assert_false(selected.complete)
  assert_eq(selected.omitted_groups, 1)
}
