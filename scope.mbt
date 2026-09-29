///|
pub(all) struct ScopeCoverage {
  possible_requests : Int
  represented_requests : Int
  missing_requests : Int
  missing_examples : Array[AccessRequest]
  complete : Bool
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
fn request_triple_exists(
  universe : RequestUniverse,
  principal_id : String,
  action : String,
  resource_id : String,
) -> Bool {
  for request in universe.requests {
    if request.principal_id == principal_id &&
      request.action == action &&
      request.resource_id == resource_id {
      return true
    }
  }
  false
}

///|
/// Measures coverage of principal × action × resource triples. Attribute
/// valuations are intentionally excluded; a represented triple may still
/// omit other important attribute combinations.
pub fn analyze_scope(
  universe : RequestUniverse,
  actions : Array[String],
  max_combinations : Int,
) -> ScopeCoverage {
  let diagnostics : Array[Diagnostic] = []
  let examples : Array[AccessRequest] = []
  if max_combinations < 1 || max_combinations > 100000 {
    diagnostics.push({
      code: "S001",
      severity: Error,
      message: "scope limit must be between 1 and 100000",
    })
  }
  if actions.length() == 0 ||
    universe.principals.length() == 0 ||
    universe.resources.length() == 0 {
    diagnostics.push({
      code: "S002",
      severity: Error,
      message: "scope needs principals, resources, and declared actions",
    })
  }
  let unique_actions : Array[String] = []
  for action in actions {
    if !is_valid_identifier(action) {
      diagnostics.push({
        code: "S003",
        severity: Error,
        message: "invalid declared action \{action}",
      })
    } else if !unique_actions.contains(action) {
      unique_actions.push(action)
    }
  }
  if has_errors(diagnostics) {
    return {
      possible_requests: 0,
      represented_requests: 0,
      missing_requests: 0,
      missing_examples: examples,
      complete: false,
      diagnostics,
    }
  }
  let mut possible = 0
  let mut represented = 0
  let mut missing = 0
  for principal in universe.principals {
    for action in unique_actions {
      for resource in universe.resources {
        if possible >= max_combinations {
          diagnostics.push({
            code: "S004",
            severity: Error,
            message: "scope exceeds configured combination limit",
          })
          return {
            possible_requests: possible,
            represented_requests: represented,
            missing_requests: missing,
            missing_examples: examples,
            complete: false,
            diagnostics,
          }
        }
        possible += 1
        if request_triple_exists(universe, principal.id, action, resource.id) {
          represented += 1
        } else {
          missing += 1
          if examples.length() < 10 {
            examples.push({
              principal_id: principal.id,
              action,
              resource_id: resource.id,
              attributes: [],
            })
          }
        }
      }
    }
  }
  {
    possible_requests: possible,
    represented_requests: represented,
    missing_requests: missing,
    missing_examples: examples,
    complete: true,
    diagnostics,
  }
}

///|
pub fn render_scope(scope : ScopeCoverage) -> String {
  let out = StringBuilder()
  out.write_string("Scope calculation complete: \{scope.complete}\n")
  out.write_string("Possible triples: \{scope.possible_requests}\n")
  out.write_string("Represented triples: \{scope.represented_requests}\n")
  out.write_string("Missing triples: \{scope.missing_requests}\n")
  out.write_string("Attribute combinations are not enumerated by this check.\n")
  for example in scope.missing_examples {
    out.write_string(
      "Missing: \{example.principal_id} \{example.action} \{example.resource_id}\n",
    )
  }
  for issue in scope.diagnostics {
    out.write_string("\{issue.code}: \{issue.message}\n")
  }
  out.to_string()
}
