///|
/// Small glob matcher: '*' accepts any sequence and '?' one character.
/// Iterative backtracking avoids a regular-expression dependency.
pub fn glob_matches(pattern : String, value : String) -> Bool {
  let p = pattern.to_array()
  let v = value.to_array()
  let mut pi = 0
  let mut vi = 0
  let mut last_star = -1
  let mut after_star = 0
  while vi < v.length() {
    if pi < p.length() && (p[pi] == '?' || p[pi] == v[vi]) {
      pi += 1
      vi += 1
    } else if pi < p.length() && p[pi] == '*' {
      last_star = pi
      pi += 1
      after_star = vi
    } else if last_star >= 0 {
      after_star += 1
      vi = after_star
      pi = last_star + 1
    } else {
      return false
    }
  }
  while pi < p.length() && p[pi] == '*' {
    pi += 1
  }
  pi == p.length()
}

///|
pub fn selector_matches(selectors : Array[String], value : String) -> Bool {
  if selectors.length() == 0 {
    return true
  }
  for selector in selectors {
    if glob_matches(selector, value) {
      return true
    }
  }
  false
}

///|
/// Compute roles reachable from the principal's direct grants.
pub fn effective_roles(
  policy : AccessPolicy,
  principal : Principal,
) -> Array[String] {
  let roles : Array[String] = []
  let pending : Array[String] = []
  let queued : Map[String, Bool] = Map([])
  for role in principal.roles {
    if queued.get(role) is None {
      pending.push(role)
      queued.set(role, true)
    }
  }
  let mut next = 0
  while next < pending.length() {
    let role = pending[next]
    next += 1
    roles.push(role)
    for edge in policy.role_inheritance {
      if edge.child == role && queued.get(edge.parent) is None {
        pending.push(edge.parent)
        queued.set(edge.parent, true)
      }
    }
  }
  roles
}

///|
fn role_selector_matches(
  selectors : Array[String],
  roles : Array[String],
) -> Bool {
  if selectors.length() == 0 || selectors.contains("*") {
    return true
  }
  for role in roles {
    if selector_matches(selectors, role) {
      return true
    }
  }
  false
}

///|
fn condition_value(
  condition : AttributeCondition,
  principal : Principal,
  resource : AccessResource,
  request : AccessRequest,
) -> String? {
  match condition.source {
    PrincipalAttribute => lookup_attribute(principal.attributes, condition.key)
    ResourceAttribute => lookup_attribute(resource.attributes, condition.key)
    RequestAttribute => lookup_attribute(request.attributes, condition.key)
  }
}

///|
pub fn condition_matches(
  condition : AttributeCondition,
  principal : Principal,
  resource : AccessResource,
  request : AccessRequest,
) -> Bool {
  let actual = condition_value(condition, principal, resource, request)
  match condition.operator {
    Equals => actual == Some(condition.value)
    NotEquals =>
      match actual {
        Some(value) => value != condition.value
        None => false
      }
    Exists => actual is Some(_)
    Missing => actual is None
  }
}

///|
pub fn rule_match_trace(
  rule : AccessRule,
  roles : Array[String],
  principal : Principal,
  resource : AccessResource,
  request : AccessRequest,
) -> RuleTrace {
  if !role_selector_matches(rule.roles, roles) {
    return {
      rule_id: rule.id,
      effect: rule.effect,
      matched: false,
      reason: "role",
    }
  }
  if !selector_matches(rule.actions, request.action) {
    return {
      rule_id: rule.id,
      effect: rule.effect,
      matched: false,
      reason: "action",
    }
  }
  if !selector_matches(rule.resource_kinds, resource.kind) {
    return {
      rule_id: rule.id,
      effect: rule.effect,
      matched: false,
      reason: "resource kind",
    }
  }
  if !selector_matches(rule.resource_ids, resource.id) {
    return {
      rule_id: rule.id,
      effect: rule.effect,
      matched: false,
      reason: "resource id",
    }
  }
  match rule.tenant_relation {
    AnyTenant => ()
    SameTenant =>
      if principal.tenant != resource.tenant {
        return {
          rule_id: rule.id,
          effect: rule.effect,
          matched: false,
          reason: "tenant mismatch",
        }
      }
    OtherTenant =>
      if principal.tenant == resource.tenant {
        return {
          rule_id: rule.id,
          effect: rule.effect,
          matched: false,
          reason: "same tenant",
        }
      }
  }
  for condition in rule.conditions {
    if !condition_matches(condition, principal, resource, request) {
      return {
        rule_id: rule.id,
        effect: rule.effect,
        matched: false,
        reason: "attribute \{condition.key}",
      }
    }
  }
  { rule_id: rule.id, effect: rule.effect, matched: true, reason: "matched", }
}

///|
pub fn matching_rule_ids(
  policy : AccessPolicy,
  principal : Principal,
  resource : AccessResource,
  request : AccessRequest,
) -> Array[String] {
  let roles = effective_roles(policy, principal)
  let ids : Array[String] = []
  for rule in policy.rules {
    let trace = rule_match_trace(rule, roles, principal, resource, request)
    if trace.matched {
      ids.push(rule.id)
    }
  }
  ids
}
