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

///|
test "scope deduplicates actions and attribute variants" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc approved=yes\nrequest alice read doc approved=no\nrequest alice read doc -",
    ).universe
  let scope = analyze_scope(universe, ["read", "read", "write", "write"], 10)
  assert_true(scope.complete)
  assert_eq(scope.possible_requests, 2)
  assert_eq(scope.represented_requests, 1)
  assert_eq(scope.missing_requests, 1)
  assert_eq(scope.missing_examples[0].action, "write")
}

///|
test "scope index preserves colon-containing identifier boundaries" {
  let universe = parse_universe(
      "principal team:alice a reader -\nprincipal team a reader -\nresource doc document a -\nrequest team:alice read doc -",
    ).universe
  // These two represented/missing triples would collide if their fields
  // were joined with an unescaped colon.
  let scope = analyze_scope(universe, ["read", "alice:read"], 10)
  assert_true(scope.complete)
  assert_eq(scope.possible_requests, 4)
  assert_eq(scope.represented_requests, 1)
  assert_eq(scope.missing_requests, 3)
  assert_true(
    scope.missing_examples.any(fn(request) {
      request.principal_id == "team" && request.action == "alice:read"
    }),
  )
}

///|
test "scope indexes a large sample and retains bounded missing examples" {
  let universe = empty_universe()
  universe.principals.push({
    id: "alice",
    tenant: "a",
    roles: ["reader"],
    attributes: [],
  })
  for i in 0..<10000 {
    let id = "doc-\{i}"
    universe.resources.push({
      id,
      kind: "document",
      tenant: "a",
      attributes: [],
    })
    if i < 9980 {
      universe.requests.push({
        principal_id: "alice",
        action: "read",
        resource_id: id,
        attributes: [],
      })
    }
  }
  let scope = analyze_scope(universe, ["read"], 10000)
  assert_true(scope.complete)
  assert_eq(scope.possible_requests, 10000)
  assert_eq(scope.represented_requests, 9980)
  assert_eq(scope.missing_requests, 20)
  assert_eq(scope.missing_examples.length(), 10)
  assert_eq(scope.missing_examples[0].resource_id, "doc-9980")
  assert_eq(scope.missing_examples[9].resource_id, "doc-9989")
}
