///|
test "deny wins over a matching permit" {
  let principal : Principal = {
    id: "alice",
    tenant: "a",
    roles: ["reader"],
    attributes: [],
  }
  let resource : AccessResource = {
    id: "invoice-1",
    kind: "invoice",
    tenant: "a",
    attributes: [],
  }
  let request : AccessRequest = {
    principal_id: "alice",
    action: "read",
    resource_id: "invoice-1",
    attributes: [],
  }
  let universe : RequestUniverse = {
    principals: [principal],
    resources: [resource],
    requests: [request],
  }
  let permit : AccessRule = {
    id: "permit-read",
    effect: Permit,
    roles: ["reader"],
    actions: ["read"],
    resource_kinds: ["invoice"],
    resource_ids: [],
    tenant_relation: SameTenant,
    conditions: [],
  }
  let deny : AccessRule = {
    id: "deny-read",
    effect: Deny,
    roles: ["reader"],
    actions: ["read"],
    resource_kinds: ["invoice"],
    resource_ids: [],
    tenant_relation: SameTenant,
    conditions: [],
  }
  let policy : AccessPolicy = {
    name: "p",
    role_inheritance: [],
    rules: [permit, deny],
  }
  let decision = evaluate_request(policy, universe, request)
  assert_true(decision.kind is Denied)
  assert_eq(decision.decisive_rules.length(), 1)
  assert_eq(decision.decisive_rules[0], "deny-read")
}

///|
test "missing principal is unknown rather than denied" {
  let request : AccessRequest = {
    principal_id: "missing",
    action: "read",
    resource_id: "r",
    attributes: [],
  }
  let decision = evaluate_request(empty_policy("p"), empty_universe(), request)
  assert_true(decision.kind is Unknown)
}
