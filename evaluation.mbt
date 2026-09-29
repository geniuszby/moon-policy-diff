///|
/// A deny rule takes precedence over permits. Without a matching rule,
/// evaluation uses default deny.
pub fn evaluate_request(
  policy : AccessPolicy,
  universe : RequestUniverse,
  request : AccessRequest,
) -> Decision {
  let mut principal : Principal? = None
  let mut resource : AccessResource? = None
  for candidate in universe.principals {
    if candidate.id == request.principal_id {
      principal = Some(candidate)
      break
    }
  }
  for candidate in universe.resources {
    if candidate.id == request.resource_id {
      resource = Some(candidate)
      break
    }
  }
  match (principal, resource) {
    (None, _) => return unknown_decision("Principal is not in the universe")
    (_, None) => return unknown_decision("Resource is not in the universe")
    (Some(principal), Some(resource)) => {
      let roles = effective_roles(policy, principal)
      let traces : Array[RuleTrace] = []
      let permits : Array[String] = []
      let denies : Array[String] = []
      for rule in policy.rules {
        let trace = rule_match_trace(rule, roles, principal, resource, request)
        traces.push(trace)
        if trace.matched {
          match trace.effect {
            Permit => permits.push(trace.rule_id)
            Deny => denies.push(trace.rule_id)
          }
        }
      }
      if denies.length() > 0 {
        return {
          kind: Denied,
          decisive_rules: denies,
          traces,
          explanation: "A deny rule matched",
        }
      }
      if permits.length() > 0 {
        return {
          kind: Allowed,
          decisive_rules: permits,
          traces,
          explanation: "A permit rule matched",
        }
      }
      { kind: Denied, decisive_rules: [], traces, explanation: "Default deny", }
    }
  }
}

///|
pub fn evaluate_validated(
  policy : AccessPolicy,
  universe : RequestUniverse,
  request : AccessRequest,
) -> Decision {
  if has_errors(validate_policy(policy)) ||
    has_errors(validate_universe(universe)) {
    return unknown_decision("Invalid policy or request universe")
  }
  evaluate_request(policy, universe, request)
}
