///|
fn test_rule(id : String) -> AccessRule {
  {
    id,
    effect: Permit,
    roles: ["reader"],
    actions: ["read"],
    resource_kinds: ["invoice"],
    resource_ids: [],
    tenant_relation: SameTenant,
    conditions: [],
  }
}

///|
test "duplicate rule ids fail validation" {
  let policy : AccessPolicy = {
    name: "test",
    role_inheritance: [],
    rules: [test_rule("x"), test_rule("x")],
  }
  let issues = validate_policy(policy)
  assert_true(has_errors(issues))
  assert_true(issues.iter().any(issue => issue.code == "P012"))
}

///|
test "inheritance cycles are rejected" {
  let policy : AccessPolicy = {
    name: "test",
    role_inheritance: [
      { child: "admin", parent: "staff", },
      { child: "staff", parent: "admin", },
    ],
    rules: [],
  }
  assert_true(validate_policy(policy).iter().any(issue => issue.code == "P014"))
}

///|
test "unknown request references are errors" {
  let universe : RequestUniverse = {
    principals: [],
    resources: [],
    requests: [
      {
        principal_id: "missing",
        action: "read",
        resource_id: "also-missing",
        attributes: [],
      },
    ],
  }
  let issues = validate_universe(universe)
  assert_true(issues.iter().any(issue => issue.code == "U006"))
  assert_true(issues.iter().any(issue => issue.code == "U007"))
}
