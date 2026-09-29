///|
pub(all) struct RuleImpact {
  rule_id : String
  grants_when_removed : Int
  revocations_when_removed : Int
  example_grant : AccessRequest?
  example_revocation : AccessRequest?
} derive(Debug)

///|
pub(all) struct RuleImpactReport {
  policy_name : String
  impacts : Array[RuleImpact]
  diagnostics : Array[Diagnostic]
  complete : Bool
} derive(Debug)

///|
fn without_rule(policy : AccessPolicy, id : String) -> AccessPolicy {
  let rules : Array[AccessRule] = []
  for rule in policy.rules {
    if rule.id != id {
      rules.push(rule)
    }
  }
  { name: policy.name, role_inheritance: policy.role_inheritance, rules, }
}

///|
/// Measures the effect of deleting each rule, one at a time, over the
/// explicit universe. Interacting rule deletions are outside this analysis.
pub fn measure_rule_impact(
  policy : AccessPolicy,
  universe : RequestUniverse,
) -> RuleImpactReport {
  let diagnostics : Array[Diagnostic] = []
  for issue in validate_policy(policy) {
    diagnostics.push(issue)
  }
  for issue in validate_universe(universe) {
    diagnostics.push(issue)
  }
  if policy.rules.length() > 128 || universe.requests.length() > 5000 {
    diagnostics.push({
      code: "I001",
      severity: Error,
      message: "rule impact supports at most 128 rules and 5000 requests",
    })
  }
  let impacts : Array[RuleImpact] = []
  if has_errors(diagnostics) {
    return { policy_name: policy.name, impacts, diagnostics, complete: false, }
  }
  for rule in policy.rules {
    let ablated = without_rule(policy, rule.id)
    let mut grants = 0
    let mut revocations = 0
    let mut example_grant : AccessRequest? = None
    let mut example_revocation : AccessRequest? = None
    for request in universe.requests {
      let before = evaluate_request(policy, universe, request)
      let after = evaluate_request(ablated, universe, request)
      match classify_change(before, after) {
        NewGrant => {
          grants += 1
          if example_grant is None {
            example_grant = Some(request)
          }
        }
        RevokedGrant => {
          revocations += 1
          if example_revocation is None {
            example_revocation = Some(request)
          }
        }
        _ => ()
      }
    }
    impacts.push({
      rule_id: rule.id,
      grants_when_removed: grants,
      revocations_when_removed: revocations,
      example_grant,
      example_revocation,
    })
  }
  { policy_name: policy.name, impacts, diagnostics, complete: true, }
}

///|
pub fn inert_rules(report : RuleImpactReport) -> Array[String] {
  let ids : Array[String] = []
  if !report.complete {
    return ids
  }
  for impact in report.impacts {
    if impact.grants_when_removed == 0 && impact.revocations_when_removed == 0 {
      ids.push(impact.rule_id)
    }
  }
  ids
}

///|
pub fn render_rule_impact(report : RuleImpactReport) -> String {
  let out = StringBuilder()
  out.write_string("Rule impact: \{report.policy_name}\n")
  out.write_string("Complete: \{report.complete}\n")
  for diagnostic in report.diagnostics {
    out.write_string("\{diagnostic.code}: \{diagnostic.message}\n")
  }
  for item in report.impacts {
    out.write_string(
      "\{item.rule_id}: deleting grants \{item.grants_when_removed}, revokes \{item.revocations_when_removed}\n",
    )
    match item.example_grant {
      Some(request) =>
        out.write_string(
          "  grant witness: \{request.principal_id} \{request.action} \{request.resource_id}\n",
        )
      None => ()
    }
    match item.example_revocation {
      Some(request) =>
        out.write_string(
          "  revocation witness: \{request.principal_id} \{request.action} \{request.resource_id}\n",
        )
      None => ()
    }
  }
  out.to_string()
}
