///|
test "expectation regression catches changed grant" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let assertions = parse_expectations("expect alice read doc deny")
  assert_false(has_errors(assertions.diagnostics))
  let before = verify_expectations(
    empty_policy("before"),
    universe,
    assertions.expectations,
  )
  assert_eq(before.passed, 1)
  let after = parse_policy(
      "policy after\nrule read permit reader read document - same -",
    ).policy
  let changed = verify_expectations(after, universe, assertions.expectations)
  assert_eq(changed.failed, 1)
}

///|
test "missing or ambiguous request is inconclusive" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let assertions = parse_expectations("expect alice write doc deny")
  let result = verify_expectations(
    empty_policy("p"),
    universe,
    assertions.expectations,
  )
  assert_eq(result.inconclusive, 1)
  assert_true(has_errors(result.diagnostics))
}

///|
test "expectation parser rejects unsupported result" {
  let assertions = parse_expectations("expect alice read doc maybe")
  assert_true(has_errors(assertions.diagnostics))
}
