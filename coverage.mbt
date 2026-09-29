///|
pub(all) struct RuleCoverage {
  rule_id : String
  matched_requests : Int
  decisive_requests : Int
} derive(Debug)

///|
pub(all) struct PolicyCoverage {
  policy_name : String
  evaluated_requests : Int
  allowed_requests : Int
  denied_requests : Int
  rule_coverage : Array[RuleCoverage]
  actions_seen : Array[String]
  principal_tenants_seen : Array[String]
  resource_tenants_seen : Array[String]
} derive(Debug)

///|
fn add_unique(values : Array[String], value : String) -> Unit {
  if !values.contains(value) {
    values.push(value)
  }
}

///|
fn principal_tenant(universe : RequestUniverse, id : String) -> String {
  for principal in universe.principals {
    if principal.id == id {
      return principal.tenant
    }
  }
  ""
}

///|
fn resource_tenant(universe : RequestUniverse, id : String) -> String {
  for resource in universe.resources {
    if resource.id == id {
      return resource.tenant
    }
  }
  ""
}

///|
/// Counts are observational: a rule with zero matches in this universe may
/// still match a request outside the supplied finite sample.
pub fn measure_policy_coverage(
  policy : AccessPolicy,
  universe : RequestUniverse,
) -> PolicyCoverage {
  let counts : Array[RuleCoverage] = []
  for rule in policy.rules {
    counts.push({ rule_id: rule.id, matched_requests: 0, decisive_requests: 0, })
  }
  let actions_seen : Array[String] = []
  let principal_tenants_seen : Array[String] = []
  let resource_tenants_seen : Array[String] = []
  let mut allowed_requests = 0
  let mut denied_requests = 0
  for request in universe.requests {
    add_unique(actions_seen, request.action)
    add_unique(
      principal_tenants_seen,
      principal_tenant(universe, request.principal_id),
    )
    add_unique(
      resource_tenants_seen,
      resource_tenant(universe, request.resource_id),
    )
    let decision = evaluate_request(policy, universe, request)
    match decision.kind {
      Allowed => allowed_requests += 1
      Denied => denied_requests += 1
      Unknown => ()
    }
    for index in 0..<counts.length() {
      for trace in decision.traces {
        if trace.rule_id == counts[index].rule_id && trace.matched {
          counts[index] = {
            rule_id: counts[index].rule_id,
            matched_requests: counts[index].matched_requests + 1,
            decisive_requests: counts[index].decisive_requests,
          }
        }
      }
      if decision.decisive_rules.contains(counts[index].rule_id) {
        counts[index] = {
          rule_id: counts[index].rule_id,
          matched_requests: counts[index].matched_requests,
          decisive_requests: counts[index].decisive_requests + 1,
        }
      }
    }
  }
  {
    policy_name: policy.name,
    evaluated_requests: universe.requests.length(),
    allowed_requests,
    denied_requests,
    rule_coverage: counts,
    actions_seen,
    principal_tenants_seen,
    resource_tenants_seen,
  }
}

///|
pub fn unmatched_rules(coverage : PolicyCoverage) -> Array[String] {
  let result : Array[String] = []
  for item in coverage.rule_coverage {
    if item.matched_requests == 0 {
      result.push(item.rule_id)
    }
  }
  result
}

///|
pub fn shadowed_rules(coverage : PolicyCoverage) -> Array[String] {
  let result : Array[String] = []
  for item in coverage.rule_coverage {
    if item.matched_requests > 0 && item.decisive_requests == 0 {
      result.push(item.rule_id)
    }
  }
  result
}

///|
pub fn render_coverage(coverage : PolicyCoverage) -> String {
  let out = StringBuilder()
  out.write_string("Policy: \{coverage.policy_name}\n")
  out.write_string("Explicit requests: \{coverage.evaluated_requests}\n")
  out.write_string("Allowed: \{coverage.allowed_requests}\n")
  out.write_string("Denied: \{coverage.denied_requests}\n")
  out.write_string("Distinct actions: \{coverage.actions_seen.length()}\n")
  out.write_string(
    "Principal tenants: \{coverage.principal_tenants_seen.length()}\n",
  )
  out.write_string(
    "Resource tenants: \{coverage.resource_tenants_seen.length()}\n",
  )
  for item in coverage.rule_coverage {
    out.write_string(
      "Rule \{item.rule_id}: matched \{item.matched_requests}, decisive \{item.decisive_requests}\n",
    )
  }
  out.to_string()
}
