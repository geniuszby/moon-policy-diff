///|
fn release_test_request() -> @moon_policy.Request {
  @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc",
    subject_attributes={ "tenant": @moon_policy.StringValue("a") },
    resource_attributes={ "tenant": @moon_policy.StringValue("a") },
  )
}

///|
fn release_test_allow() -> @moon_policy.Policy {
  @moon_policy.Policy(rules=[
    @moon_policy.Rule(id="allow", effect=@moon_policy.Allow),
  ])
}

///|
fn release_has_code(report : ReleaseReport, code : String) -> Bool {
  report.findings.any(fn(finding) { finding.code == code })
}

///|
test "release delegates diffs and traces to published MoonPolicy" {
  let before = @moon_policy.Policy()
  let after = release_test_allow()
  let request = release_test_request()
  let report = audit_release(before, after, [request], strict_release_config())
  assert_true(report.complete)
  assert_eq(report.changes, before.access_changes(after, [request]))
  assert_eq(report.changes[0].current, after.authorize(request))
  assert_true(release_has_code(report, "ACTION_GRANT_BUDGET"))
}

///|
test "release uses upstream role bindings and transitive permissions" {
  let before = @moon_policy.Policy()
  let after = @moon_policy.Policy(
    role_permissions={ "viewer": ["read"], "admin": [] },
    role_parents={ "admin": ["viewer"] },
    bindings=[@moon_policy.RoleBinding(subject="alice", role="admin")],
  )
  let config : ReleaseConfig = {
    ..strict_release_config(),
    action_budgets: [{ action: "read", max_new_grants: 1, max_revocations: 0, }],
  }
  let report = audit_release(before, after, [release_test_request()], config)
  assert_true(report.verdict is Pass)
  assert_true(report.changes[0].current.trace.contains("role:viewer:read"))
}

///|
test "unchanged cross tenant grants violate release isolation" {
  let seed = release_test_request()
  let request : @moon_policy.Request = {
    ..seed,
    resource_attributes: { "tenant": @moon_policy.StringValue("b") },
  }
  let policy = release_test_allow()
  let report = audit_release(policy, policy, [request], strict_release_config())
  assert_eq(report.changes.length(), 0)
  assert_true(report.verdict is Fail)
  assert_true(release_has_code(report, "TENANT_ISOLATION"))
  let cases = release_regression_cases(report)
  assert_eq(cases.length(), 1)
  assert_false(cases[0].expected_allowed)
  assert_eq(policy.run_cases(cases).failed, 1)
}

///|
test "an action budget cannot bypass a tenant invariant" {
  let seed = release_test_request()
  let request : @moon_policy.Request = {
    ..seed,
    resource_attributes: { "tenant": @moon_policy.StringValue("b") },
  }
  let config : ReleaseConfig = {
    ..strict_release_config(),
    action_budgets: [
      { action: "read", max_new_grants: 100, max_revocations: 100, },
    ],
  }
  let report = audit_release(
    @moon_policy.Policy(),
    release_test_allow(),
    [request],
    config,
  )
  assert_false(release_has_code(report, "ACTION_GRANT_BUDGET"))
  assert_true(release_has_code(report, "TENANT_ISOLATION"))
  assert_true(report.verdict is Fail)
}

///|
test "missing or nonstring tenant metadata is indeterminate" {
  for
    attributes in [
      Map([]),
      Map([("tenant", @moon_policy.BoolValue(true))]),
      Map([("tenant", @moon_policy.StringValue(""))]),
    ] {
    let request : @moon_policy.Request = {
      ..release_test_request(),
      resource_attributes: attributes,
    }
    let report = audit_release(
      release_test_allow(),
      release_test_allow(),
      [request],
      strict_release_config(),
    )
    assert_false(report.complete)
    assert_true(report.verdict is Indeterminate)
    assert_true(release_has_code(report, "UNKNOWN_TENANT"))
  }
}

///|
test "denied requests do not require tenant metadata" {
  let request = @moon_policy.Request(
    subject="alice",
    action="read",
    resource="doc",
  )
  let report = audit_release(
    @moon_policy.Policy(),
    @moon_policy.Policy(),
    [request],
    strict_release_config(),
  )
  assert_true(report.complete)
  assert_true(report.verdict is Pass)
}

///|
test "forbidden action is checked even when its decision did not change" {
  let config : ReleaseConfig = {
    ..strict_release_config(),
    forbidden_actions: ["read"],
  }
  let report = audit_release(
    release_test_allow(),
    release_test_allow(),
    [release_test_request()],
    config,
  )
  assert_true(report.verdict is Fail)
  assert_true(release_has_code(report, "FORBIDDEN_ACTION"))
}

///|
test "release counts equivalent samples once regardless of map insertion order" {
  let first = release_test_request()
  first.context.set("x", @moon_policy.IntValue(1))
  first.context.set("y", @moon_policy.IntValue(2))
  let second : @moon_policy.Request = {
    ..first,
    context: Map([
      ("y", @moon_policy.IntValue(2)),
      ("x", @moon_policy.IntValue(1)),
    ]),
  }
  let config : ReleaseConfig = {
    ..strict_release_config(),
    action_budgets: [{ action: "read", max_new_grants: 1, max_revocations: 0, }],
  }
  let report = audit_release(
    @moon_policy.Policy(),
    release_test_allow(),
    [first, second],
    config,
  )
  assert_eq(report.requests_evaluated, 1)
  assert_eq(report.changes.length(), 1)
  assert_true(report.verdict is Pass)
}

///|
test "invalid release config and policies cannot produce a pass" {
  let budget : ActionBudget = {
    action: "read",
    max_new_grants: 1,
    max_revocations: 0,
  }
  let configs : Array[ReleaseConfig] = [
    { ..strict_release_config(), action_budgets: [budget, budget], },
    {
      ..strict_release_config(),
      action_budgets: [{ ..budget, max_new_grants: -1, }],
    },
    { ..strict_release_config(), tenant_attribute: "metadata.tenant", },
  ]
  for config in configs {
    let report = audit_release(
      @moon_policy.Policy(),
      release_test_allow(),
      [release_test_request()],
      config,
    )
    assert_true(report.verdict is Indeterminate)
    assert_eq(report.requests_evaluated, 0)
  }
  let invalid = @moon_policy.Policy(bindings=[
    @moon_policy.RoleBinding(subject="alice", role="undeclared"),
  ])
  assert_true(
    audit_release(
      invalid,
      release_test_allow(),
      [release_test_request()],
      strict_release_config(),
    ).verdict
    is Indeterminate,
  )
}

///|
test "release revocation budget and native replay preserve the old baseline" {
  let before = release_test_allow()
  let after = @moon_policy.Policy()
  let report = audit_release(
    before,
    after,
    [release_test_request()],
    strict_release_config(),
  )
  assert_true(release_has_code(report, "ACTION_REVOCATION_BUDGET"))
  let cases = release_regression_cases(report)
  assert_eq(before.run_cases(cases).passed, 1)
  assert_eq(after.run_cases(cases).failed, 1)
  let parsed = @moon_policy.cases_from_json(
    release_cases_json(report).stringify(),
  )
  assert_eq(after.run_cases(parsed).failed, 1)
}

///|
test "multiple invariant cases have unique names accepted by upstream replay" {
  let seed = release_test_request()
  let first : @moon_policy.Request = {
    ..seed,
    resource_attributes: { "tenant": @moon_policy.StringValue("b") },
  }
  let second : @moon_policy.Request = { ..first, resource: "another-doc", }
  let report = audit_release(
    @moon_policy.Policy(),
    release_test_allow(),
    [first, second],
    strict_release_config(),
  )
  let cases = @moon_policy.cases_from_json(
    release_cases_json(report).stringify(),
  )
  assert_eq(cases.length(), 2)
  assert_eq(release_test_allow().run_cases(cases).failed, 2)
}

///|
test "indeterminate tenant metadata does not export partial baseline cases" {
  let request : @moon_policy.Request = {
    ..release_test_request(),
    resource_attributes: Map([]),
  }
  let report = audit_release(
    @moon_policy.Policy(),
    release_test_allow(),
    [request],
    strict_release_config(),
  )
  assert_eq(report.changes.length(), 1)
  assert_false(report.complete)
  assert_eq(release_regression_cases(report).length(), 0)
}

///|
test "finite risk domain covers threshold boundary and missing value" {
  let plan = parse_release_plan(
    (
      #|{"domains":[{"source":"context","key":"risk","values":[null,0,20,21,20]}]}
    ),
  )
  let samples = generate_release_samples(
    [release_test_request()],
    plan.domains,
    plan.max_requests,
  )
  assert_true(samples.complete)
  assert_eq(samples.requests.length(), 4)
  let after = @moon_policy.Policy(rules=[
    @moon_policy.Rule(
      id="low-risk",
      effect=@moon_policy.Allow,
      condition=@moon_policy.Compare(
        path="context.risk",
        op=@moon_policy.LessOrEqual,
        value=20,
      ),
    ),
  ])
  let run = run_release_plan(
    @moon_policy.Policy(),
    after,
    [release_test_request()],
    plan,
  )
  assert_eq(run.report.changes.length(), 2)
  assert_eq(run.report.requests_evaluated, 4)
  assert_false(after.authorize(samples.requests[0]).allowed)
  assert_true(after.authorize(samples.requests[2]).allowed)
  assert_false(after.authorize(samples.requests[3]).allowed)
}

///|
test "finite domains clone maps and keep seed attributes intact" {
  let seed = release_test_request()
  seed.context.set("risk", @moon_policy.IntValue(7))
  let domain : ReleaseAttributeDomain = {
    source: RequestAttribute,
    key: "risk",
    values: [
      None,
      Some(@moon_policy.IntValue(1)),
      Some(@moon_policy.IntValue(2)),
    ],
  }
  let samples = generate_release_samples([seed], [domain], 3)
  assert_true(samples.complete)
  assert_eq(seed.context.get("risk"), Some(@moon_policy.IntValue(7)))
  assert_true(samples.requests[0].context.get("risk") is None)
  assert_eq(
    samples.requests[1].context.get("risk"),
    Some(@moon_policy.IntValue(1)),
  )
  assert_eq(
    samples.requests[2].context.get("risk"),
    Some(@moon_policy.IntValue(2)),
  )
}

///|
test "finite domain overflow yields no partial audit or cases" {
  let plan = parse_release_plan(
    (
      #|{"max_requests":3,"domains":[{"source":"context","key":"a","values":[1,2]},{"source":"context","key":"b","values":[1,2]}]}
    ),
  )
  let run = run_release_plan(
    @moon_policy.Policy(),
    release_test_allow(),
    [release_test_request()],
    plan,
  )
  assert_false(run.samples.complete)
  assert_eq(run.samples.requests.length(), 0)
  assert_true(run.report.verdict is Indeterminate)
  assert_eq(run.report.requests_evaluated, 0)
  assert_eq(release_regression_cases(run.report).length(), 0)
}

///|
test "invalid finite domains are rejected before generation" {
  let valid : ReleaseAttributeDomain = {
    source: RequestAttribute,
    key: "risk",
    values: [Some(@moon_policy.IntValue(1))],
  }
  for
    domains in [
      [valid, valid],
      [{ ..valid, values: [], }],
      [{ ..valid, key: "nested.risk", }],
      [{ ..valid, source: PrincipalAttribute, key: "id", }],
    ] {
    let samples = generate_release_samples(
      [release_test_request()],
      domains,
      10,
    )
    assert_false(samples.complete)
    assert_eq(samples.requests.length(), 0)
  }
}

///|
fn release_plan_rejected(text : String) -> Bool {
  try {
    let _ = parse_release_plan(text)
    false
  } catch {
    _ => true
  }
}

///|
test "large finite domain product stops before integer overflow" {
  let domains : Array[ReleaseAttributeDomain] = []
  for i in 0..<32 {
    domains.push({
      source: RequestAttribute,
      key: "flag-\{i}",
      values: [
        Some(@moon_policy.BoolValue(true)),
        Some(@moon_policy.BoolValue(false)),
      ],
    })
  }
  let samples = generate_release_samples(
    [release_test_request()],
    domains,
    100000,
  )
  assert_false(samples.complete)
  assert_eq(samples.requests.length(), 0)
}

///|
test "subject resource and context domains form a complete typed product" {
  let plan = parse_release_plan(
    (
      #|{"domains":[{"source":"subject","key":"department","values":["finance","sales"]},{"source":"resource","key":"classified","values":[true,false]},{"source":"context","key":"approved","values":[null,true]}]}
    ),
  )
  let samples = generate_release_samples(
    [release_test_request()],
    plan.domains,
    8,
  )
  assert_true(samples.complete)
  assert_eq(samples.candidate_count, 8)
  assert_eq(samples.requests.length(), 8)
  for request in samples.requests {
    assert_true(request.subject_attributes.get("department") is Some(_))
    assert_true(request.resource_attributes.get("classified") is Some(_))
    assert_eq(
      request.subject_attributes.get("tenant"),
      Some(@moon_policy.StringValue("a")),
    )
  }
}

///|
test "release plan rejects typos and malformed typed values" {
  assert_true(
    release_plan_rejected(
      (
        #|{"forbid_cross_tenent":true}
      ),
    ),
  )
  assert_true(
    release_plan_rejected(
      (
        #|{"forbid_cross_tenant":"true"}
      ),
    ),
  )
  assert_true(
    release_plan_rejected(
      (
        #|{"max_requests":1.5}
      ),
    ),
  )
  assert_true(
    release_plan_rejected(
      (
        #|{"domains":[{"source":"unknown","key":"risk","values":[1]}]}
      ),
    ),
  )
  assert_true(
    release_plan_rejected(
      (
        #|{"domains":[{"source":"context","key":"risk","values":[1.5]}]}
      ),
    ),
  )
}

///|
test "upstream missing attribute semantics remain conservative under negation" {
  let plan = parse_release_plan(
    (
      #|{"domains":[{"source":"context","key":"approved","values":[null,true,false]}]}
    ),
  )
  let after = @moon_policy.Policy(rules=[
    @moon_policy.Rule(
      id="not-approved",
      effect=@moon_policy.Allow,
      condition=@moon_policy.Not(
        @moon_policy.Equals(
          path="context.approved",
          value=@moon_policy.BoolValue(true),
        ),
      ),
    ),
  ])
  let run = run_release_plan(
    @moon_policy.Policy(),
    after,
    [release_test_request()],
    plan,
  )
  assert_eq(run.report.changes.length(), 1)
  assert_false(after.authorize(run.samples.requests[0]).allowed)
  assert_false(after.authorize(run.samples.requests[1]).allowed)
  assert_true(after.authorize(run.samples.requests[2]).allowed)
}
