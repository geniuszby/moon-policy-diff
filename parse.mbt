///|
pub(all) struct ParsedPolicy {
  policy : AccessPolicy
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
pub(all) struct ParsedUniverse {
  universe : RequestUniverse
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
fn fields(line : String) -> Array[String] {
  let result : Array[String] = []
  for item in line.split(" ") {
    let word = item.to_owned().trim().to_owned()
    if word != "" {
      result.push(word)
    }
  }
  result
}

///|
fn comma_list(source : String) -> Array[String] {
  let result : Array[String] = []
  if source == "-" || source == "*" {
    return result
  }
  for item in source.split(",") {
    let word = item.to_owned().trim().to_owned()
    if word != "" {
      result.push(word)
    }
  }
  result
}

///|
fn parse_attributes(source : String) -> Array[(String, String)] {
  let result : Array[(String, String)] = []
  if source == "-" {
    return result
  }
  for item in source.split(",") {
    let parts = item.split("=").collect()
    if parts.length() == 2 {
      result.push((parts[0].to_owned(), parts[1].to_owned()))
    }
  }
  result
}

///|
fn attributes_well_formed(source : String) -> Bool {
  if source == "-" {
    return true
  }
  for item in source.split(",") {
    let parts = item.split("=").collect()
    if parts.length() != 2 || parts[0] == "" || parts[1] == "" {
      return false
    }
  }
  true
}

///|
fn parse_effect(word : String) -> RuleEffect? {
  match word {
    "permit" => Some(Permit)
    "deny" => Some(Deny)
    _ => None
  }
}

///|
fn parse_tenant_relation(word : String) -> TenantRelation? {
  match word {
    "any" => Some(AnyTenant)
    "same" => Some(SameTenant)
    "other" => Some(OtherTenant)
    _ => None
  }
}

///|
fn parse_conditions(source : String) -> Array[AttributeCondition]? {
  let result : Array[AttributeCondition] = []
  if source == "-" {
    return Some(result)
  }
  for item in source.split(",") {
    let parts = item.split(":").collect()
    if parts.length() != 4 {
      return None
    }
    let source_type = match parts[0] {
      "principal" => PrincipalAttribute
      "resource" => ResourceAttribute
      "request" => RequestAttribute
      _ => return None
    }
    let operator = match parts[2] {
      "eq" => Equals
      "neq" => NotEquals
      "exists" => Exists
      "missing" => Missing
      _ => return None
    }
    result.push({
      source: source_type,
      key: parts[1].to_owned(),
      operator,
      value: parts[3].to_owned(),
    })
  }
  Some(result)
}

///|
fn parse_issue(line : Int, message : String) -> Diagnostic {
  { code: "PARSE", severity: Error, message: "line \{line}: \{message}", }
}

///|
/// Policy DSL: policy NAME; inherit CHILD PARENT;
/// rule ID EFFECT ROLES ACTIONS KINDS IDS TENANT CONDITIONS.
/// Lists are comma separated; '-' means unrestricted or empty.
pub fn parse_policy(source : String) -> ParsedPolicy {
  let mut name = ""
  let inheritance : Array[RoleInheritance] = []
  let rules : Array[AccessRule] = []
  let diagnostics : Array[Diagnostic] = []
  let lines = source.split("\n").collect()
  for index, raw in lines {
    let line = raw.to_owned().trim().to_owned()
    if line == "" || line.starts_with("#") {
      continue
    }
    let parts = fields(line)
    match parts[0] {
      "policy" =>
        if parts.length() == 2 && name == "" {
          name = parts[1]
        } else {
          diagnostics.push(parse_issue(index + 1, "expected one policy name"))
        }
      "inherit" =>
        if parts.length() == 3 {
          inheritance.push({ child: parts[1], parent: parts[2], })
        } else {
          diagnostics.push(
            parse_issue(index + 1, "expected inherit CHILD PARENT"),
          )
        }
      "rule" =>
        if parts.length() == 9 {
          match
            (
              parse_effect(parts[2]),
              parse_tenant_relation(parts[7]),
              parse_conditions(parts[8]),
            ) {
            (Some(effect), Some(tenant_relation), Some(conditions)) =>
              rules.push({
                id: parts[1],
                effect,
                roles: comma_list(parts[3]),
                actions: comma_list(parts[4]),
                resource_kinds: comma_list(parts[5]),
                resource_ids: comma_list(parts[6]),
                tenant_relation,
                conditions,
              })
            _ =>
              diagnostics.push(
                parse_issue(
                  index + 1,
                  "invalid rule effect, tenant relation, or condition",
                ),
              )
          }
        } else {
          diagnostics.push(
            parse_issue(
              index + 1,
              "expected rule ID EFFECT ROLES ACTIONS KINDS IDS TENANT CONDITIONS",
            ),
          )
        }
      _ => diagnostics.push(parse_issue(index + 1, "unknown policy directive"))
    }
  }
  if name == "" {
    diagnostics.push(parse_issue(0, "missing policy name"))
  }
  let policy : AccessPolicy = { name, role_inheritance: inheritance, rules, }
  for issue in validate_policy(policy) {
    diagnostics.push(issue)
  }
  { policy, diagnostics, }
}

///|
/// Universe DSL:
/// principal ID TENANT ROLES ATTRS
/// resource ID KIND TENANT ATTRS
/// request PRINCIPAL ACTION RESOURCE ATTRS
pub fn parse_universe(source : String) -> ParsedUniverse {
  let principals : Array[Principal] = []
  let resources : Array[AccessResource] = []
  let requests : Array[AccessRequest] = []
  let diagnostics : Array[Diagnostic] = []
  let lines = source.split("\n").collect()
  for index, raw in lines {
    let line = raw.to_owned().trim().to_owned()
    if line == "" || line.starts_with("#") {
      continue
    }
    let parts = fields(line)
    if parts.length() != 5 {
      diagnostics.push(parse_issue(index + 1, "expected five fields"))
      continue
    }
    if !attributes_well_formed(parts[4]) {
      diagnostics.push(parse_issue(index + 1, "malformed attributes"))
      continue
    }
    match parts[0] {
      "principal" =>
        principals.push({
          id: parts[1],
          tenant: parts[2],
          roles: comma_list(parts[3]),
          attributes: parse_attributes(parts[4]),
        })
      "resource" =>
        resources.push({
          id: parts[1],
          kind: parts[2],
          tenant: parts[3],
          attributes: parse_attributes(parts[4]),
        })
      "request" =>
        requests.push({
          principal_id: parts[1],
          action: parts[2],
          resource_id: parts[3],
          attributes: parse_attributes(parts[4]),
        })
      _ =>
        diagnostics.push(parse_issue(index + 1, "unknown universe directive"))
    }
  }
  let universe : RequestUniverse = { principals, resources, requests, }
  for issue in validate_universe(universe) {
    diagnostics.push(issue)
  }
  { universe, diagnostics, }
}
