///|
test "parse a policy and explicit request universe" {
  let policy = parse_policy(
    "policy base\ninherit manager reader\nrule read permit reader read invoice - same -",
  )
  assert_false(has_errors(policy.diagnostics))
  assert_eq(policy.policy.rules.length(), 1)
  let universe = parse_universe(
    "principal alice acme manager department=finance\nresource inv-1 invoice acme -\nrequest alice read inv-1 -",
  )
  assert_false(has_errors(universe.diagnostics))
  assert_eq(universe.universe.requests.length(), 1)
}

///|
test "parser reports invalid directives and malformed attributes" {
  assert_true(has_errors(parse_policy("policy p\nunknown x").diagnostics))
  assert_true(
    has_errors(
      parse_universe(
        "principal alice acme reader broken\nresource r invoice acme -\nrequest alice read r -",
      ).diagnostics,
    ),
  )
}
