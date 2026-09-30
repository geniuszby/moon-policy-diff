///|
/// Release rules layered on MoonPolicy. They do not change authorization
/// semantics. Unlisted actions have a zero change budget.
pub(all) struct ReleaseConfig {
  action_budgets : Array[ActionBudget]
  forbid_cross_tenant : Bool
  tenant_attribute : String
  forbidden_actions : Array[String]
} derive(Debug)

///|
pub fn strict_release_config() -> ReleaseConfig {
  {
    action_budgets: [],
    forbid_cross_tenant: true,
    tenant_attribute: "tenant",
    forbidden_actions: [],
  }
}

///|
pub(all) struct ReleaseFinding {
  code : String
  message : String
  request : @moon_policy.Request?
} derive(Debug)

///|
pub(all) struct ReleaseReport {
  complete : Bool
  requests_evaluated : Int
  changes : Array[@moon_policy.AccessChange]
  findings : Array[ReleaseFinding]
  verdict : GateVerdict
} derive(Debug)

///|
fn release_issue(
  findings : Array[ReleaseFinding],
  code : String,
  message : String,
  request? : @moon_policy.Request,
) -> Unit {
  findings.push({ code, message, request, })
}

///|
/// Canonical object ordering prevents duplicate samples with different
/// attribute insertion orders from consuming multiple units of budget.
fn canonical_release_json(value : Json) -> String {
  match value {
    Object(fields) => {
      let keys = fields.keys().to_array()
      keys.sort()
      let out = StringBuilder()
      out.write_string("{")
      for i, key in keys {
        if i > 0 {
          out.write_string(",")
        }
        out.write_string(json_escape(key))
        out.write_string(":")
        if fields.get(key) is Some(item) {
          out.write_string(canonical_release_json(item))
        }
      }
      out.write_string("}")
      out.to_string()
    }
    Array(items) => "[" + items.map(canonical_release_json).join(",") + "]"
    _ => value.stringify()
  }
}

///|
fn release_request_key(request : @moon_policy.Request) -> String {
  canonical_release_json(request.to_json())
}

///|
fn release_tenant(
  attributes : Map[String, @moon_policy.AttributeValue],
  key : String,
) -> String? {
  match attributes.get(key) {
    Some(@moon_policy.StringValue(value)) =>
      if value == "" {
        None
      } else {
        Some(value)
      }
    _ => None
  }
}

///|
/// Delegates every access decision to the published MoonPolicy engine.
/// Tenant invariants cover all allowed replacement decisions, including
/// unchanged access. Invalid metadata makes the conclusion indeterminate.
pub fn audit_release(
  before : @moon_policy.Policy,
  after : @moon_policy.Policy,
  requests : Array[@moon_policy.Request],
  config : ReleaseConfig,
) -> ReleaseReport {
  let findings : Array[ReleaseFinding] = []
  for policy in [before, after] {
    for issue in policy.validate() {
      release_issue(
        findings,
        "INVALID_POLICY",
        "\{issue.code} at \{issue.location}: \{issue.message}",
      )
    }
  }
  if requests.length() == 0 || requests.length() > 100000 {
    release_issue(findings, "INVALID_CORPUS", "Need 1..100000 request samples")
  }
  if config.forbid_cross_tenant &&
    (
      config.tenant_attribute == "" ||
      config.tenant_attribute == "id" ||
      config.tenant_attribute.contains(".")
    ) {
    release_issue(
      findings, "INVALID_TENANT_KEY", "Tenant key must name one top-level attribute",
    )
  }
  let seen_actions : Map[String, Bool] = Map([])
  for budget in config.action_budgets {
    if budget.action == "" ||
      budget.max_new_grants < 0 ||
      budget.max_revocations < 0 ||
      seen_actions.get(budget.action) is Some(_) {
      release_issue(
        findings, "INVALID_BUDGET", "Invalid or repeated action budget",
      )
    }
    seen_actions.set(budget.action, true)
  }
  for action in config.forbidden_actions {
    if action == "" {
      release_issue(
        findings, "INVALID_ACTION", "Forbidden action cannot be empty",
      )
    }
  }
  for request in requests {
    if request.subject == "" || request.action == "" || request.resource == "" {
      release_issue(
        findings, "INVALID_REQUEST", "Request identifiers cannot be empty",
      )
    }
  }
  if findings.length() > 0 {
    return {
      complete: false,
      requests_evaluated: 0,
      changes: [],
      findings,
      verdict: Indeterminate,
    }
  }
  let unique_requests : Array[@moon_policy.Request] = []
  let seen_requests : Map[String, Bool] = Map([])
  for request in requests {
    let key = release_request_key(request)
    if seen_requests.get(key) is None {
      seen_requests.set(key, true)
      unique_requests.push(request)
    }
  }
  // The upstream API owns diff semantics and the original decision traces.
  let changes = before.access_changes(after, unique_requests)
  let counts : Map[String, (Int, Int)] = Map([])
  for change in changes {
    let (grants, revocations) = counts
      .get(change.request.action)
      .unwrap_or((0, 0))
    counts.set(
      change.request.action,
      if change.current.allowed {
        (grants + 1, revocations)
      } else {
        (grants, revocations + 1)
      },
    )
  }
  for change in changes {
    let budget = budget_for_action(config.action_budgets, change.request.action)
    let (grants, revocations) = counts
      .get(change.request.action)
      .unwrap_or((0, 0))
    if change.current.allowed && grants > budget.max_new_grants {
      release_issue(
        findings,
        "ACTION_GRANT_BUDGET",
        "New grants for \{change.request.action} exceed \{budget.max_new_grants}",
        request=change.request,
      )
    } else if !change.current.allowed && revocations > budget.max_revocations {
      release_issue(
        findings,
        "ACTION_REVOCATION_BUDGET",
        "Revocations for \{change.request.action} exceed \{budget.max_revocations}",
        request=change.request,
      )
    }
  }
  let mut complete = true
  for request in unique_requests {
    if !after.authorize(request).allowed {
      continue
    }
    if config.forbidden_actions.contains(request.action) {
      release_issue(
        findings,
        "FORBIDDEN_ACTION",
        "Replacement policy allows a forbidden action",
        request~,
      )
    }
    if config.forbid_cross_tenant {
      match
        (
          release_tenant(request.subject_attributes, config.tenant_attribute),
          release_tenant(request.resource_attributes, config.tenant_attribute),
        ) {
        (Some(subject_tenant), Some(resource_tenant)) =>
          if subject_tenant != resource_tenant {
            release_issue(
              findings,
              "TENANT_ISOLATION",
              "Replacement policy allows cross-tenant access",
              request~,
            )
          }
        _ => {
          complete = false
          release_issue(
            findings,
            "UNKNOWN_TENANT",
            "Allowed request lacks nonempty string tenant metadata",
            request~,
          )
        }
      }
    }
  }
  {
    complete,
    requests_evaluated: unique_requests.length(),
    changes,
    findings,
    verdict: if !complete {
      Indeterminate
    } else if findings.length() > 0 {
      Fail
    } else {
      Pass
    },
  }
}

///|
/// Replay cases preserve the old outcome for changed requests. Explicit
/// invariant violations override that baseline with an expected denial.
/// These are review artifacts, not automatically applied policy fixes.
pub fn release_regression_cases(
  report : ReleaseReport,
) -> Array[@moon_policy.PolicyCase] {
  if !report.complete {
    return []
  }
  let cases : Array[@moon_policy.PolicyCase] = []
  let positions : Map[String, Int] = Map([])
  for change in report.changes {
    let key = release_request_key(change.request)
    positions.set(key, cases.length())
    cases.push(
      @moon_policy.PolicyCase(
        name="baseline-\{cases.length()}",
        request=change.request,
        expected_allowed=change.previous.allowed,
      ),
    )
  }
  for finding in report.findings {
    if finding.code != "TENANT_ISOLATION" && finding.code != "FORBIDDEN_ACTION" {
      continue
    }
    if finding.request is Some(request) {
      let key = release_request_key(request)
      match positions.get(key) {
        Some(index) =>
          cases[index] = @moon_policy.PolicyCase(
            name="invariant-\{finding.code}-\{index}",
            request~,
            expected_allowed=false,
          )
        None => {
          positions.set(key, cases.length())
          cases.push(
            @moon_policy.PolicyCase(
              name="invariant-\{finding.code}-\{cases.length()}",
              request~,
              expected_allowed=false,
            ),
          )
        }
      }
    }
  }
  cases
}

///|
pub fn release_cases_json(report : ReleaseReport) -> Json {
  Json::array(
    [
      for item in release_regression_cases(report) => {
        Json::object({
          "name": Json::string(item.name),
          "request": item.request.to_json(),
          "expected_allowed": Json::boolean(item.expected_allowed),
        })
      }
    ],
  )
}

///|
pub fn release_report_json(report : ReleaseReport) -> Json {
  Json::object({
    "engine": Json::string("eisem/moon_policy@0.1.0"),
    "complete": Json::boolean(report.complete),
    "requests_evaluated": Json::number(report.requests_evaluated.to_double()),
    "verdict": Json::string(
      match report.verdict {
        Pass => "PASS"
        Fail => "FAIL"
        Indeterminate => "INDETERMINATE"
      },
    ),
    "changes": Json::array(report.changes.map(fn(change) { change.to_json() })),
    "findings": Json::array(
      report.findings.map(fn(finding) {
        Json::object({
          "code": Json::string(finding.code),
          "message": Json::string(finding.message),
          "request": match finding.request {
            Some(request) => request.to_json()
            None => Json::null()
          },
        })
      }),
    ),
    "regression_cases": release_cases_json(report),
  })
}
