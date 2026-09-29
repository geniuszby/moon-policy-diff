///|
test "coverage distinguishes matching from decisive permit" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule allow permit reader read document - same -\nrule deny deny reader read document - same -",
    ).policy
  let coverage = measure_policy_coverage(policy, universe)
  assert_eq(coverage.allowed_requests, 0)
  assert_eq(coverage.denied_requests, 1)
  assert_eq(coverage.rule_coverage[0].matched_requests, 1)
  assert_eq(coverage.rule_coverage[0].decisive_requests, 0)
  assert_true(shadowed_rules(coverage).contains("allow"))
}

///|
test "unmatched is scoped to the supplied universe" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule write permit reader write document - same -",
    ).policy
  let coverage = measure_policy_coverage(policy, universe)
  assert_true(unmatched_rules(coverage).contains("write"))
}
