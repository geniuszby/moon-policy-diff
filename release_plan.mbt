///|
pub(all) suberror ReleaseInputError {
  InvalidReleaseInput(String)
} derive(Debug, Eq)

///|
pub(all) struct ReleasePlan {
  config : ReleaseConfig
  domains : Array[ReleaseAttributeDomain]
  max_requests : Int
} derive(Debug)

///|
pub fn default_release_plan() -> ReleasePlan {
  { config: strict_release_config(), domains: [], max_requests: 10000, }
}

///|
fn release_object(
  value : Json,
  allowed : Array[String],
) -> Map[String, Json] raise ReleaseInputError {
  match value {
    Object(fields) => {
      for key, _ in fields {
        if !allowed.contains(key) {
          raise InvalidReleaseInput("Unknown release field: " + key)
        }
      }
      fields
    }
    _ => raise InvalidReleaseInput("Expected release JSON object")
  }
}

///|
fn release_string(value : Json) -> String raise ReleaseInputError {
  match value {
    String(text) => text
    _ => raise InvalidReleaseInput("Expected string")
  }
}

///|
fn release_integer(value : Json) -> Int raise ReleaseInputError {
  match value {
    Number(number, ..) =>
      if number < 0 || number > 100000 || number != number.to_int().to_double() {
        raise InvalidReleaseInput("Expected integer between 0 and 100000")
      } else {
        number.to_int()
      }
    _ => raise InvalidReleaseInput("Expected integer")
  }
}

///|
fn release_array(value : Json) -> Array[Json] raise ReleaseInputError {
  match value {
    Array(items) => items
    _ => raise InvalidReleaseInput("Expected array")
  }
}

///|
fn release_required(
  fields : Map[String, Json],
  key : String,
) -> Json raise ReleaseInputError {
  match fields.get(key) {
    Some(value) => value
    None => raise InvalidReleaseInput("Missing field: " + key)
  }
}

///|
fn release_optional_int(
  fields : Map[String, Json],
  key : String,
  fallback : Int,
) -> Int raise ReleaseInputError {
  match fields.get(key) {
    Some(value) => release_integer(value)
    None => fallback
  }
}

///|
fn release_domain_value(
  value : Json,
) -> @moon_policy.AttributeValue? raise ReleaseInputError {
  if value is Null {
    return None
  }
  // Reuse the upstream decoder for all typed attributes and its nesting
  // checks instead of defining a second interpretation of these values.
  let request = @moon_policy.request_from_json(
    Json::object({
      "subject": Json::string("sample"),
      "action": Json::string("sample"),
      "resource": Json::string("sample"),
      "context": Json::object({ "value": value }),
    }).stringify(),
  ) catch {
    _ =>
      raise InvalidReleaseInput(
        "Domain value rejected by MoonPolicy attribute decoder",
      )
  }
  request.context.get("value")
}

///|
/// Unknown configuration fields are rejected, including misspelled
/// restrictions. JSON null in a domain means an absent attribute.
pub fn parse_release_plan(
  source : String,
) -> ReleasePlan raise ReleaseInputError {
  let root = @json.parse(source) catch {
    error => raise InvalidReleaseInput("Invalid release JSON: \{error}")
  }
  let fields = release_object(root, [
    "max_requests", "action_budgets", "forbid_cross_tenant", "tenant_attribute",
    "forbidden_actions", "domains",
  ])
  let budgets : Array[ActionBudget] = []
  if fields.get("action_budgets") is Some(value) {
    for item in release_array(value) {
      let budget = release_object(item, [
        "action", "max_new_grants", "max_revocations",
      ])
      budgets.push({
        action: release_string(release_required(budget, "action")),
        max_new_grants: release_optional_int(budget, "max_new_grants", 0),
        max_revocations: release_optional_int(budget, "max_revocations", 0),
      })
    }
  }
  let forbidden_actions : Array[String] = []
  if fields.get("forbidden_actions") is Some(value) {
    for item in release_array(value) {
      forbidden_actions.push(release_string(item))
    }
  }
  let forbid_cross_tenant = match fields.get("forbid_cross_tenant") {
    Some(True) => true
    Some(False) => false
    None => true
    _ => raise InvalidReleaseInput("forbid_cross_tenant must be boolean")
  }
  let tenant_attribute = match fields.get("tenant_attribute") {
    Some(value) => release_string(value)
    None => "tenant"
  }
  let domains : Array[ReleaseAttributeDomain] = []
  if fields.get("domains") is Some(value) {
    for item in release_array(value) {
      let domain = release_object(item, ["source", "key", "values"])
      let domain_source = release_string(release_required(domain, "source"))
      let source = match domain_source {
        "subject" => PrincipalAttribute
        "resource" => ResourceAttribute
        "context" => RequestAttribute
        _ =>
          raise InvalidReleaseInput(
            "Domain source must be subject, resource, or context",
          )
      }
      let values : Array[@moon_policy.AttributeValue?] = []
      for value in release_array(release_required(domain, "values")) {
        values.push(release_domain_value(value))
      }
      domains.push({
        source,
        key: release_string(release_required(domain, "key")),
        values,
      })
    }
  }
  {
    config: {
      action_budgets: budgets,
      forbid_cross_tenant,
      tenant_attribute,
      forbidden_actions,
    },
    domains,
    max_requests: release_optional_int(fields, "max_requests", 10000),
  }
}
