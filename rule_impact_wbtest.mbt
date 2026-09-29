///|
test "ablation shows a deny protects a request" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule allow permit reader read document - same -\nrule block deny reader read document - same -",
    ).policy
  let impact = measure_rule_impact(policy, universe)
  assert_true(impact.complete)
  assert_eq(impact.impacts[1].grants_when_removed, 1)
  assert_eq(impact.impacts[0].revocations_when_removed, 0)
  assert_true(inert_rules(impact).contains("allow"))
}

///|
test "ablation of essential permit revokes access" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule allow permit reader read document - same -",
    ).policy
  let impact = measure_rule_impact(policy, universe)
  assert_eq(impact.impacts[0].revocations_when_removed, 1)
}
