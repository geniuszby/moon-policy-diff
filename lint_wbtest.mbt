///|
test "lint warns on unconditional cross-tenant permit" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document b -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy("policy p\nrule broad permit - - - - any -").policy
  let issues = lint_policy(policy, universe)
  assert_true(issues.length() > 0)
  assert_eq(issues[0].code, "L001")
}

///|
test "lint detects exact rule conflicts" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule permit permit reader read document - same -\nrule deny deny reader read document - same -",
    ).policy
  let issues = lint_policy(policy, universe)
  let mut conflicts = 0
  for issue in issues {
    if issue.code == "L004" {
      conflicts += 1
    }
  }
  assert_eq(conflicts, 1)
}
