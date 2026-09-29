///|
/// The two possible effects of a policy rule. A deny rule overrides permits.
pub(all) enum RuleEffect {
  Permit
  Deny
} derive(Eq, Debug)

///|
pub(all) enum TenantRelation {
  AnyTenant
  SameTenant
  OtherTenant
} derive(Eq, Debug)

///|
pub(all) enum AttributeSource {
  PrincipalAttribute
  ResourceAttribute
  RequestAttribute
} derive(Eq, Debug)

///|
pub(all) enum AttributeOperator {
  Equals
  NotEquals
  Exists
  Missing
} derive(Eq, Debug)

///|
pub(all) struct AttributeCondition {
  source : AttributeSource
  key : String
  operator : AttributeOperator
  value : String
} derive(Eq, Debug)

///|
/// A role name may inherit another role. Inheritance is directed: a holder
/// of `child` receives all permissions granted to `parent`.
pub(all) struct RoleInheritance {
  child : String
  parent : String
} derive(Eq, Debug)

///|
pub(all) struct Principal {
  id : String
  tenant : String
  roles : Array[String]
  attributes : Array[(String, String)]
} derive(Eq, Debug)

///|
pub(all) struct AccessResource {
  id : String
  kind : String
  tenant : String
  attributes : Array[(String, String)]
} derive(Eq, Debug)

///|
pub(all) struct AccessRequest {
  principal_id : String
  action : String
  resource_id : String
  attributes : Array[(String, String)]
} derive(Eq, Debug)

///|
/// Empty selector arrays mean "any". An explicit `*` has the same meaning
/// and is accepted by the text parser for readable policy files.
pub(all) struct AccessRule {
  id : String
  effect : RuleEffect
  roles : Array[String]
  actions : Array[String]
  resource_kinds : Array[String]
  resource_ids : Array[String]
  tenant_relation : TenantRelation
  conditions : Array[AttributeCondition]
} derive(Eq, Debug)

///|
pub(all) struct AccessPolicy {
  name : String
  role_inheritance : Array[RoleInheritance]
  rules : Array[AccessRule]
} derive(Eq, Debug)

///|
/// The universe is explicit so a finite analysis never silently claims
/// coverage of identities or resources that were not provided.
pub(all) struct RequestUniverse {
  principals : Array[Principal]
  resources : Array[AccessResource]
  requests : Array[AccessRequest]
} derive(Eq, Debug)

///|
pub(all) enum DecisionKind {
  Allowed
  Denied
  Unknown
} derive(Eq, Debug)

///|
pub(all) struct RuleTrace {
  rule_id : String
  effect : RuleEffect
  matched : Bool
  reason : String
} derive(Eq, Debug)

///|
pub(all) struct Decision {
  kind : DecisionKind
  decisive_rules : Array[String]
  traces : Array[RuleTrace]
  explanation : String
} derive(Eq, Debug)

///|
pub(all) enum ChangeKind {
  NewGrant
  RevokedGrant
  UnchangedAllow
  UnchangedDeny
  Inconclusive
} derive(Eq, Debug)

///|
pub(all) struct DecisionChange {
  request : AccessRequest
  before : Decision
  after : Decision
  kind : ChangeKind
} derive(Eq, Debug)

///|
pub(all) enum DiagnosticSeverity {
  Info
  Warning
  Error
} derive(Eq, Debug)

///|
pub(all) struct Diagnostic {
  code : String
  severity : DiagnosticSeverity
  message : String
} derive(Eq, Debug)

///|
pub(all) struct AuditReport {
  before_name : String
  after_name : String
  requests_considered : Int
  changes : Array[DecisionChange]
  diagnostics : Array[Diagnostic]
  complete : Bool
} derive(Eq, Debug)

///|
pub fn empty_policy(name : String) -> AccessPolicy {
  { name, role_inheritance: [], rules: [] }
}

///|
pub fn empty_universe() -> RequestUniverse {
  { principals: [], resources: [], requests: [] }
}

///|
pub fn default_deny() -> Decision {
  {
    kind: Denied,
    decisive_rules: [],
    traces: [],
    explanation: "No permit matched; default deny",
  }
}

///|
pub fn unknown_decision(message : String) -> Decision {
  { kind: Unknown, decisive_rules: [], traces: [], explanation: message }
}

///|
pub fn is_valid_identifier(value : String) -> Bool {
  if value == "" {
    return false
  }
  for char in value.to_array() {
    if !((char >= 'a' && char <= 'z') ||
      (char >= 'A' && char <= 'Z') ||
      (char >= '0' && char <= '9') ||
      char == '_' ||
      char == '-' ||
      char == '.' ||
      char == ':' ||
      char == '/') {
      return false
    }
  }
  true
}

///|
pub fn lookup_attribute(attrs : Array[(String, String)], key : String) -> String? {
  for pair in attrs {
    if pair.0 == key {
      return Some(pair.1)
    }
  }
  None
}
