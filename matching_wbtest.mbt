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

///|
test "effective roles includes every direct role beyond the policy edge limit" {
  let direct : Array[String] = []
  for index in 0..<4100 {
    direct.push("role-\{index}")
  }
  let principal : Principal = {
    id: "large",
    tenant: "tenant",
    roles: direct,
    attributes: [],
  }
  let roles = effective_roles(empty_policy("p"), principal)
  assert_eq(roles.length(), 4100)
  assert_true(roles.contains("role-4099"))
}

///|
test "effective roles terminates on repeated cyclic edges" {
  let policy : AccessPolicy = {
    name: "cycle",
    role_inheritance: [
      { child: "a", parent: "b", },
      { child: "b", parent: "a", },
      { child: "a", parent: "b", },
    ],
    rules: [],
  }
  let principal : Principal = {
    id: "alice",
    tenant: "tenant",
    roles: ["a", "a"],
    attributes: [],
  }
  let roles = effective_roles(policy, principal)
  assert_eq(roles.length(), 2)
  assert_true(roles.contains("a"))
  assert_true(roles.contains("b"))
}
