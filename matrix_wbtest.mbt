///|
test "matrix expands same and cross tenant requests" {
  let universe : RequestUniverse = {
    principals: [
      { id: "alice", tenant: "a", roles: [], attributes: [], },
      { id: "bob", tenant: "b", roles: [], attributes: [], },
    ],
    resources: [
      { id: "doc-a", kind: "doc", tenant: "a", attributes: [], },
      { id: "doc-b", kind: "doc", tenant: "b", attributes: [], },
    ],
    requests: [],
  }
  let expanded = expand_request_matrix(universe, ["read", "write"], 100)
  assert_false(has_errors(expanded.diagnostics))
  assert_eq(expanded.generated_requests, 8)
  assert_eq(tenant_pairs(expanded.universe).length(), 4)
}

///|
test "matrix overflow returns no partial expansion" {
  let universe : RequestUniverse = {
    principals: [
      { id: "a", tenant: "t", roles: [], attributes: [], },
      { id: "b", tenant: "t", roles: [], attributes: [], },
    ],
    resources: [{ id: "r", kind: "doc", tenant: "t", attributes: [], }],
    requests: [],
  }
  let expanded = expand_request_matrix(universe, ["read"], 1)
  assert_true(has_errors(expanded.diagnostics))
  assert_eq(expanded.universe.requests.length(), 0)
}

///|
test "universe DSL matrix generates a bounded request sample" {
  let parsed = parse_universe(
    "principal alice a reader -\nresource doc document b -\nmatrix read,write",
  )
  assert_false(has_errors(parsed.diagnostics))
  assert_eq(parsed.universe.requests.length(), 2)
  assert_eq(parsed.universe.requests[0].action, "read")
}
