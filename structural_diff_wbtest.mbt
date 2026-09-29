///|
test "structural diff reports changed rule and role edge" {
  let before = parse_policy(
      "policy before\nrule read permit reader read document - same -",
    ).policy
  let after = parse_policy(
      "policy after\ninherit trainee reader\nrule read deny reader read document - same -",
    ).policy
  let diff = structural_diff(before, after)
  assert_eq(diff.rules.length(), 1)
  assert_true(diff.rules[0].kind is ModifiedRule)
  assert_eq(diff.added_role_edges.length(), 1)
  assert_true(render_structural_diff(diff).contains("MODIFIED rule read"))
}

///|
test "structural diff includes removals" {
  let before = parse_policy(
      "policy before\ninherit trainee reader\nrule old permit reader read document - same -",
    ).policy
  let after = empty_policy("after")
  let diff = structural_diff(before, after)
  assert_true(diff.rules[0].kind is RemovedRule)
  assert_eq(diff.removed_role_edges.length(), 1)
}
