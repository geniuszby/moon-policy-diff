///|
fn diagnostic(
  code : String,
  severity : DiagnosticSeverity,
  message : String,
) -> Diagnostic {
  { code, severity, message, }
}

///|
fn duplicate_strings(values : Array[String]) -> Array[String] {
  let seen : Array[String] = []
  let duplicates : Array[String] = []
  for value in values {
    if seen.contains(value) {
      if !duplicates.contains(value) {
        duplicates.push(value)
      }
    } else {
      seen.push(value)
    }
  }
  duplicates
}

///|
fn validate_selector(
  values : Array[String],
  owner : String,
  field : String,
  issues : Array[Diagnostic],
) -> Unit {
  if values.contains("*") && values.length() != 1 {
    issues.push(
      diagnostic(
        "P004",
        Error,
        "\{owner}: '*' must be the only \{field} selector",
      ),
    )
  }
  for value in values {
    if value == "" {
      issues.push(
        diagnostic("P005", Error, "\{owner}: empty \{field} selector"),
      )
    }
  }
  for repeated in duplicate_strings(values) {
    issues.push(
      diagnostic(
        "P006",
        Warning,
        "\{owner}: repeated \{field} selector \{repeated}",
      ),
    )
  }
}

///|
fn validate_attributes(
  attrs : Array[(String, String)],
  owner : String,
  issues : Array[Diagnostic],
) -> Unit {
  let keys : Array[String] = []
  for item in attrs {
    if !is_valid_identifier(item.0) {
      issues.push(
        diagnostic("P007", Error, "\{owner}: invalid attribute key '\{item.0}'"),
      )
    }
    keys.push(item.0)
  }
  for repeated in duplicate_strings(keys) {
    issues.push(
      diagnostic("P008", Error, "\{owner}: duplicate attribute '\{repeated}'"),
    )
  }
}

///|
fn role_reaches(
  edges : Array[RoleInheritance],
  start : String,
  target : String,
  max_visits : Int,
) -> Bool {
  let pending : Array[String] = [start]
  let seen : Array[String] = []
  while pending.length() > 0 && seen.length() <= max_visits {
    let current = pending.remove(0)
    if current == target {
      return true
    }
    if seen.contains(current) {
      continue
    }
    seen.push(current)
    for edge in edges {
      if edge.child == current && !seen.contains(edge.parent) {
        pending.push(edge.parent)
      }
    }
  }
  false
}

///|
pub fn validate_policy(policy : AccessPolicy) -> Array[Diagnostic] {
  let issues : Array[Diagnostic] = []
  if !is_valid_identifier(policy.name) {
    issues.push(diagnostic("P001", Error, "invalid policy name"))
  }
  if policy.rules.length() > 4096 {
    issues.push(diagnostic("P002", Error, "policy exceeds 4096-rule limit"))
  }
  if policy.role_inheritance.length() > 4096 {
    issues.push(diagnostic("P003", Error, "policy exceeds 4096 role edges"))
  }
  let ids : Array[String] = []
  for rule in policy.rules {
    if !is_valid_identifier(rule.id) {
      issues.push(diagnostic("P009", Error, "invalid rule id '\{rule.id}'"))
    }
    ids.push(rule.id)
    validate_selector(rule.roles, rule.id, "roles", issues)
    validate_selector(rule.actions, rule.id, "actions", issues)
    validate_selector(rule.resource_kinds, rule.id, "resource kinds", issues)
    validate_selector(rule.resource_ids, rule.id, "resource ids", issues)
    let seen_conditions : Array[String] = []
    for condition in rule.conditions {
      if !is_valid_identifier(condition.key) {
        issues.push(
          diagnostic("P010", Error, "\{rule.id}: invalid condition key"),
        )
      }
      let marker = "{condition.source}:{condition.key}:{condition.operator}"
      if seen_conditions.contains(marker) {
        issues.push(
          diagnostic(
            "P011",
            Warning,
            "\{rule.id}: repeated condition \{marker}",
          ),
        )
      }
      seen_conditions.push(marker)
    }
  }
  for repeated in duplicate_strings(ids) {
    issues.push(diagnostic("P012", Error, "duplicate rule id \{repeated}"))
  }
  let edges : Array[String] = []
  for edge in policy.role_inheritance {
    if !is_valid_identifier(edge.child) || !is_valid_identifier(edge.parent) {
      issues.push(diagnostic("P013", Error, "invalid role inheritance name"))
    }
    edges.push("\{edge.child}>\{edge.parent}")
    if role_reaches(policy.role_inheritance, edge.parent, edge.child, 4096) {
      issues.push(
        diagnostic(
          "P014",
          Error,
          "role inheritance cycle involving \{edge.child}",
        ),
      )
    }
  }
  for repeated in duplicate_strings(edges) {
    issues.push(diagnostic("P015", Warning, "repeated role edge \{repeated}"))
  }
  issues
}

///|
pub fn validate_universe(universe : RequestUniverse) -> Array[Diagnostic] {
  let issues : Array[Diagnostic] = []
  if universe.principals.length() > 4096 ||
    universe.resources.length() > 4096 ||
    universe.requests.length() > 100000 {
    issues.push(diagnostic("U001", Error, "universe exceeds analysis bounds"))
  }
  let principal_ids : Array[String] = []
  for principal in universe.principals {
    if !is_valid_identifier(principal.id) ||
      !is_valid_identifier(principal.tenant) {
      issues.push(diagnostic("U002", Error, "invalid principal or tenant id"))
    }
    principal_ids.push(principal.id)
    validate_attributes(
      principal.attributes,
      "principal \{principal.id}",
      issues,
    )
  }
  for repeated in duplicate_strings(principal_ids) {
    issues.push(diagnostic("U003", Error, "duplicate principal \{repeated}"))
  }
  let resource_ids : Array[String] = []
  for resource in universe.resources {
    if !is_valid_identifier(resource.id) ||
      !is_valid_identifier(resource.kind) ||
      !is_valid_identifier(resource.tenant) {
      issues.push(
        diagnostic("U004", Error, "invalid resource id, kind, or tenant"),
      )
    }
    resource_ids.push(resource.id)
    validate_attributes(resource.attributes, "resource \{resource.id}", issues)
  }
  for repeated in duplicate_strings(resource_ids) {
    issues.push(diagnostic("U005", Error, "duplicate resource \{repeated}"))
  }
  let request_keys : Array[String] = []
  for request in universe.requests {
    if !principal_ids.contains(request.principal_id) {
      issues.push(
        diagnostic(
          "U006",
          Error,
          "request references unknown principal \{request.principal_id}",
        ),
      )
    }
    if !resource_ids.contains(request.resource_id) {
      issues.push(
        diagnostic(
          "U007",
          Error,
          "request references unknown resource \{request.resource_id}",
        ),
      )
    }
    if !is_valid_identifier(request.action) {
      issues.push(diagnostic("U008", Error, "request has invalid action"))
    }
    validate_attributes(request.attributes, "request", issues)
    request_keys.push(
      "\{request.principal_id}/\{request.action}/\{request.resource_id}/\{request.attributes}",
    )
  }
  for repeated in duplicate_strings(request_keys) {
    issues.push(diagnostic("U009", Warning, "duplicate request \{repeated}"))
  }
  if universe.requests.length() == 0 {
    issues.push(diagnostic("U010", Error, "request universe is empty"))
  }
  issues
}

///|
pub fn has_errors(issues : Array[Diagnostic]) -> Bool {
  for issue in issues {
    if issue.severity is Error {
      return true
    }
  }
  false
}
