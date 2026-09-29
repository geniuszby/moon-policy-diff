///|
test "new inherited role is attributed to role graph" {
  let universe = parse_universe(
      "principal intern a trainee department=finance\nresource report report a -\nrequest intern read report -",
    ).universe
  let before = parse_policy(
      "policy before\nrule read permit analyst read report - same -",
    ).policy
  let after = parse_policy(
      "policy after\ninherit trainee analyst\nrule read permit analyst read report - same -",
    ).policy
  let changes = attribute_changes(before, after, universe)
  assert_eq(changes.length(), 1)
  assert_true(changes[0].cause is RoleInheritanceRevision)
}

///|
test "new rule is attributed to rule revision" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let before = empty_policy("before")
  let after = parse_policy(
      "policy after\nrule read permit reader read document - same -",
    ).policy
  let changes = attribute_changes(before, after, universe)
  assert_eq(changes.length(), 1)
  assert_true(changes[0].cause is RuleRevision)
  assert_true(changes[0].changed_rule_ids.contains("read"))
}
