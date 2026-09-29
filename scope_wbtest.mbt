///|
test "scope identifies uncovered cross tenant request" {
  let universe = parse_universe(
      "principal alice a reader -\nresource local document a -\nresource remote document b -\nrequest alice read local -",
    ).universe
  let scope = analyze_scope(universe, ["read"], 10)
  assert_true(scope.complete)
  assert_eq(scope.possible_requests, 2)
  assert_eq(scope.represented_requests, 1)
  assert_eq(scope.missing_examples[0].resource_id, "remote")
}

///|
test "scope reports truncation instead of a misleading total" {
  let universe = parse_universe(
      "principal alice a reader -\nresource local document a -\nresource remote document b -\nrequest alice read local -",
    ).universe
  let scope = analyze_scope(universe, ["read"], 1)
  assert_false(scope.complete)
  assert_true(has_errors(scope.diagnostics))
}
