///|
test "SaaS export rollout finds both local and cross tenant grants" {
  let before = parse_policy(
    "policy before\nrule read permit reader read invoice - same -\nrule deny-export deny reader export invoice - any -",
  )
  let after = parse_policy(
    "policy after\nrule read permit reader read invoice - same -\nrule export permit reader export invoice - any -",
  )
  let universe = parse_universe(
    "principal alice tenant-a reader -\nprincipal bob tenant-b reader -\nresource inv-a invoice tenant-a -\nresource inv-b invoice tenant-b -\nrequest alice read inv-a -\nrequest alice export inv-a -\nrequest alice export inv-b -\nrequest bob export inv-a -",
  )
  assert_false(has_errors(before.diagnostics))
  assert_false(has_errors(after.diagnostics))
  assert_false(has_errors(universe.diagnostics))
  let report = compare_policies(before.policy, after.policy, universe.universe)
  let gate = check_gate(report, universe.universe, strict_gate())
  assert_true(report.complete)
  assert_eq(report.requests_considered, 4)
  assert_eq(count_changes(report, NewGrant), 3)
  assert_eq(
    cross_tenant_change_count(group_changes(report, universe.universe)),
    2,
  )
  assert_true(gate.verdict is Fail)
}

///|
test "AI tool rollout identifies a newly executable capability" {
  let before = parse_policy(
      "policy before\nrule inspect permit analyst inspect document - same -",
    ).policy
  let after = parse_policy(
      "policy after\nrule inspect permit analyst inspect document - same -\nrule execute permit agent execute tool - same principal:approved:eq:yes",
    ).policy
  let universe = parse_universe(
      "principal assistant workspace agent approved=yes\nprincipal observer workspace analyst -\nresource search tool workspace -\nresource report document workspace -\nrequest assistant execute search -\nrequest observer inspect report -",
    ).universe
  let report = compare_policies(before, after, universe)
  assert_eq(count_changes(report, NewGrant), 1)
  assert_eq(report.changes[0].request.principal_id, "assistant")
  assert_eq(report.changes[0].after.decisive_rules[0], "execute")
  let expected = parse_expectations("expect assistant execute search deny")
  let verification = verify_expectations(after, universe, expected.expectations)
  assert_eq(verification.failed, 1)
}

///|
test "finance role promotion is distinguishable from rule edits" {
  let before = parse_policy(
      "policy before\nrule finance permit analyst read report - same principal:department:eq:finance",
    ).policy
  let after = parse_policy(
      "policy after\ninherit trainee analyst\nrule finance permit analyst read report - same principal:department:eq:finance",
    ).policy
  let universe = parse_universe(
      "principal alice a analyst department=finance\nprincipal intern a trainee department=finance\nresource forecast report a -\nmatrix read,export",
    ).universe
  let report = compare_policies(before, after, universe)
  assert_true(report.complete)
  assert_eq(count_changes(report, NewGrant), 1)
  let causes = attribute_changes(before, after, universe)
  assert_eq(causes.length(), 1)
  assert_true(causes[0].cause is RoleInheritanceRevision)
  let diff = structural_diff(before, after)
  assert_eq(diff.added_role_edges.length(), 1)
  assert_true(diff.rules[0].kind is UnchangedRule)
}
