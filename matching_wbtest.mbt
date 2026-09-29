///|
test "glob matching is anchored and handles stars" {
  assert_true(glob_matches("invoice:*", "invoice:123"))
  assert_true(glob_matches("a?c", "abc"))
  assert_true(glob_matches("*", ""))
  assert_false(glob_matches("invoice:*", "xinvoice:123"))
  assert_false(glob_matches("a?c", "ac"))
}

///|
test "role inheritance gives a holder parent role" {
  let policy : AccessPolicy = {
    name: "roles",
    role_inheritance: [{ child: "manager", parent: "reader", }],
    rules: [],
  }
  let principal : Principal = {
    id: "alice",
    tenant: "acme",
    roles: ["manager"],
    attributes: [],
  }
  assert_true(effective_roles(policy, principal).contains("reader"))
}

///|
test "missing attribute is not unequal by default" {
  let principal : Principal = {
    id: "alice",
    tenant: "acme",
    roles: [],
    attributes: [],
  }
  let resource : AccessResource = {
    id: "invoice:1",
    kind: "invoice",
    tenant: "acme",
    attributes: [],
  }
  let request : AccessRequest = {
    principal_id: "alice",
    action: "read",
    resource_id: "invoice:1",
    attributes: [],
  }
  let condition : AttributeCondition = {
    source: PrincipalAttribute,
    key: "department",
    operator: NotEquals,
    value: "finance",
  }
  assert_false(condition_matches(condition, principal, resource, request))
}
