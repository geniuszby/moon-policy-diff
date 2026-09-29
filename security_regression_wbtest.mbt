///|
test "a permit cannot override a matching explicit deny" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule allow permit reader read document - same -\nrule block deny reader read document - same -",
    ).policy
  let decision = evaluate_request(policy, universe, universe.requests[0])
  assert_true(decision.kind is Denied)
  assert_eq(decision.decisive_rules[0], "block")
}

///|
test "default deny applies when a permit misses an attribute" {
  let universe = parse_universe(
      "principal alice a reader department=sales\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule finance permit reader read document - same principal:department:eq:finance",
    ).policy
  let decision = evaluate_request(policy, universe, universe.requests[0])
  assert_true(decision.kind is Denied)
  assert_eq(decision.decisive_rules.length(), 0)
}

///|
test "not-equals condition does not match a missing attribute" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule not-finance permit reader read document - same principal:department:neq:finance",
    ).policy
  assert_true(
    evaluate_request(policy, universe, universe.requests[0]).kind is Denied,
  )
}

///|
test "a missing condition explicitly matches absent attributes" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule unclassified permit reader read document - same resource:classification:missing:-",
    ).policy
  assert_true(
    evaluate_request(policy, universe, universe.requests[0]).kind is Allowed,
  )
}

///|
test "other-tenant rule cannot grant to same tenant" {
  let universe = parse_universe(
      "principal alice a reader -\nresource local document a -\nresource remote document b -\nrequest alice read local -\nrequest alice read remote -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule external permit reader read document - other -",
    ).policy
  assert_true(
    evaluate_request(policy, universe, universe.requests[0]).kind is Denied,
  )
  assert_true(
    evaluate_request(policy, universe, universe.requests[1]).kind is Allowed,
  )
}

///|
test "an exception to grant count does not bypass cross-tenant gate" {
  let universe = parse_universe(
      "principal alice a reader -\nresource remote document b -\nrequest alice read remote -",
    ).universe
  let after = parse_policy(
      "policy after\nrule external permit reader read document - any -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let mut gate_config = strict_gate()
  gate_config = {
    ..gate_config,
    permitted_principals: ["alice"],
    permitted_actions: ["read"],
  }
  let result = check_gate(report, universe, gate_config)
  assert_true(result.verdict is Fail)
  assert_eq(result.findings.length(), 1)
  assert_eq(result.findings[0].code, "CROSS_TENANT")
}

///|
test "exception needs both principal and action to match" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let after = parse_policy(
      "policy after\nrule read permit reader read document - same -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let mut gate_config = strict_gate()
  gate_config = {
    ..gate_config,
    permitted_principals: ["alice"],
    permitted_actions: ["write"],
  }
  let result = check_gate(report, universe, gate_config)
  assert_true(result.verdict is Fail)
  assert_eq(result.findings[0].code, "NEW_GRANT")
}

///|
test "role inheritance cycle fails validation" {
  let policy = parse_policy(
    "policy p\ninherit alpha beta\ninherit beta gamma\ninherit gamma alpha",
  )
  assert_true(has_errors(policy.diagnostics))
  let mut cycle_found = false
  for issue in policy.diagnostics {
    if issue.code == "P014" {
      cycle_found = true
    }
  }
  assert_true(cycle_found)
}

///|
test "duplicate rule ids cannot be compared as a complete audit" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule duplicate permit reader read document - same -\nrule duplicate deny reader read document - same -",
    ).policy
  let report = compare_policies(empty_policy("before"), policy, universe)
  assert_false(report.complete)
  assert_eq(report.requests_considered, 0)
}

///|
test "unknown request reference never becomes an ordinary deny" {
  let universe : RequestUniverse = {
    principals: [],
    resources: [{ id: "doc", kind: "document", tenant: "a", attributes: [], }],
    requests: [
      {
        principal_id: "ghost",
        action: "read",
        resource_id: "doc",
        attributes: [],
      },
    ],
  }
  let decision = evaluate_request(
    empty_policy("p"),
    universe,
    universe.requests[0],
  )
  assert_true(decision.kind is Unknown)
  let report = compare_policies(
    empty_policy("before"),
    empty_policy("after"),
    universe,
  )
  assert_false(report.complete)
}

///|
test "a changed role edge is observable through an inherited permission" {
  let universe = parse_universe(
      "principal intern a trainee -\nresource doc document a -\nrequest intern read doc -",
    ).universe
  let before = parse_policy(
      "policy before\nrule read permit reader read document - same -",
    ).policy
  let after = parse_policy(
      "policy after\ninherit trainee reader\nrule read permit reader read document - same -",
    ).policy
  let report = compare_policies(before, after, universe)
  assert_eq(count_changes(report, NewGrant), 1)
  assert_true(
    attribute_changes(before, after, universe)[0].cause
    is RoleInheritanceRevision,
  )
}

///|
test "a sample with request attributes is distinct from the empty variant" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc approved=yes\nrequest alice read doc -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule approved permit reader read document - same request:approved:eq:yes",
    ).policy
  let first = evaluate_request(policy, universe, universe.requests[0])
  let second = evaluate_request(policy, universe, universe.requests[1])
  assert_true(first.kind is Allowed)
  assert_true(second.kind is Denied)
}

///|
test "JSON output quotes hostile identifiers as values" {
  let decision = unknown_decision("quote \" and newline\n")
  let report : AuditReport = {
    before_name: "old\"name",
    after_name: "new",
    requests_considered: 0,
    changes: [],
    diagnostics: [],
    complete: false,
  }
  let gate : GateResult = { verdict: Indeterminate, findings: [], }
  let output = render_report_json(report, gate)
  assert_true(output.contains("old\\\"name"))
  assert_true(decision.explanation.contains("\n"))
}

///|
test "matrix generation deduplicates an explicit request" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let expansion = expand_request_matrix(universe, ["read"], 10)
  assert_eq(expansion.generated_requests, 0)
  assert_eq(expansion.universe.requests.length(), 1)
}

///|
test "scope counts a request with attributes as a represented triple" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc approved=yes",
    ).universe
  let scope = analyze_scope(universe, ["read"], 10)
  assert_true(scope.complete)
  assert_eq(scope.represented_requests, 1)
}

///|
test "wildcard matcher backtracks across multiple stars" {
  assert_true(glob_matches("a*b*c", "axxxbyyc"))
  assert_true(glob_matches("*a*b", "xxaxyb"))
  assert_false(glob_matches("a*b*c", "axxxbyyd"))
}

///|
test "malformed attribute token is rejected before evaluation" {
  let parsed = parse_universe(
    "principal alice a reader department\nresource doc document a -\nrequest alice read doc -",
  )
  assert_true(has_errors(parsed.diagnostics))
  let mut parser_error = false
  for issue in parsed.diagnostics {
    if issue.code == "PARSE" {
      parser_error = true
    }
  }
  assert_true(parser_error)
}

///|
test "two different operators on one attribute are not duplicate conditions" {
  let policy = parse_policy(
    "policy p\nrule check permit reader read document - same principal:department:exists:-,principal:department:neq:sales",
  )
  assert_false(has_errors(policy.diagnostics))
  let mut repeated = false
  for issue in policy.diagnostics {
    if issue.code == "P011" {
      repeated = true
    }
  }
  assert_false(repeated)
}

///|
test "negative global gate budget is indeterminate" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let report = compare_policies(
    empty_policy("before"),
    empty_policy("after"),
    universe,
  )
  let config : GateConfig = { ..strict_gate(), max_new_grants: -1, }
  assert_true(check_gate(report, universe, config).verdict is Indeterminate)
}

///|
test "unlisted action has zero release budget" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice export doc -",
    ).universe
  let after = parse_policy(
      "policy after\nrule export permit reader export document - same -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let gate = check_action_budgets(report, [])
  assert_true(gate.verdict is Fail)
  assert_eq(gate.findings[0].code, "ACTION_GRANT_BUDGET")
}

///|
test "request universe duplicate is diagnosed without changing a decision" {
  let parsed = parse_universe(
    "principal alice a reader -\nresource doc document a -\nrequest alice read doc -\nrequest alice read doc -",
  )
  assert_false(has_errors(parsed.diagnostics))
  let mut duplicate = false
  for issue in parsed.diagnostics {
    if issue.code == "U009" {
      duplicate = true
    }
  }
  assert_true(duplicate)
}

///|
test "a source-matched request must name the same resource exactly" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc-a document a -\nresource doc-b document a -\nrequest alice read doc-a -\nrequest alice read doc-b -",
    ).universe
  let policy = parse_policy(
      "policy p\nrule only-a permit reader read document doc-a same -",
    ).policy
  assert_true(
    evaluate_request(policy, universe, universe.requests[0]).kind is Allowed,
  )
  assert_true(
    evaluate_request(policy, universe, universe.requests[1]).kind is Denied,
  )
}

///|
test "a representative witness cap counts omitted signatures once" {
  let universe = parse_universe(
      "principal alice a reader -\nresource local document a -\nresource remote-1 document b -\nresource remote-2 document b -\nrequest alice read local -\nrequest alice read remote-1 -\nrequest alice read remote-2 -",
    ).universe
  let after = parse_policy(
      "policy after\nrule all permit reader read document - any -",
    ).policy
  let report = compare_policies(empty_policy("before"), after, universe)
  let selected = select_witnesses(report, universe, 1)
  assert_eq(selected.groups.length(), 1)
  assert_eq(selected.omitted_groups, 1)
  assert_eq(selected.total_changed_requests, 3)
}

///|
test "a grant requiring both a new rule and a role edge is attributed jointly" {
  let universe = parse_universe(
      "principal intern a trainee -\nresource doc document a -\nrequest intern read doc -",
    ).universe
  let before = empty_policy("before")
  let after = parse_policy(
      "policy after\ninherit trainee reader\nrule read permit reader read document - same -",
    ).policy
  let changes = attribute_changes(before, after, universe)
  assert_eq(changes.length(), 1)
  assert_true(changes[0].cause is CombinedRevision)
}

///|
test "independent role and rule routes are both recognized" {
  let universe = parse_universe(
      "principal intern a trainee -\nresource doc document a -\nrequest intern read doc -",
    ).universe
  let before = parse_policy(
      "policy before\nrule inherited permit reader read document - same -",
    ).policy
  let after = parse_policy(
      "policy after\ninherit trainee reader\nrule inherited permit reader read document - same -\nrule direct permit trainee read document - same -",
    ).policy
  let changes = attribute_changes(before, after, universe)
  assert_eq(changes.length(), 1)
  assert_true(changes[0].cause is EitherRevision)
}
