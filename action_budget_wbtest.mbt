///|
test "an action budget permits a planned read grant but blocks export" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -\nrequest alice export doc -",
    ).universe
  let after = parse_policy(
      "policy after\nrule read permit reader read document - same -\nrule export permit reader export document - same -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let gate = check_action_budgets(report, [
    { action: "read", max_new_grants: 1, max_revocations: 0, },
  ])
  assert_true(gate.verdict is Fail)
  assert_eq(gate.findings.length(), 1)
  assert_eq(gate.findings[0].request.action, "export")
}

///|
test "invalid or duplicate budgets are indeterminate" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let report = compare_policies(empty_policy("a"), empty_policy("b"), universe)
  let gate = check_action_budgets(report, [
    { action: "read", max_new_grants: 1, max_revocations: 0, },
    { action: "read", max_new_grants: 1, max_revocations: 0, },
  ])
  assert_true(gate.verdict is Indeterminate)
}

///|
test "an explicit revocation budget can permit a planned access removal" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let before = parse_policy(
      "policy before\nrule read permit reader read document - same -",
    ).policy
  let report = compare_policies(before, empty_policy("after"), universe)
  let gate = check_action_budgets(report, [
    { action: "read", max_new_grants: 0, max_revocations: 1, },
  ])
  assert_eq(count_changes(report, RevokedGrant), 1)
  assert_true(gate.verdict is Pass)
}
