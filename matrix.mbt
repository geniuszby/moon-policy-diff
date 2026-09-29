///|
pub(all) struct MatrixExpansion {
  universe : RequestUniverse
  generated_requests : Int
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
fn matrix_key(request : AccessRequest) -> String {
  "\{request.principal_id}|\{request.action}|\{request.resource_id}"
}

///|
/// Adds all principal × action × resource requests. The caller must supply
/// a bound; overflow fails without returning a partial expanded universe.
pub fn expand_request_matrix(
  universe : RequestUniverse,
  actions : Array[String],
  max_requests : Int,
) -> MatrixExpansion {
  let diagnostics : Array[Diagnostic] = []
  let requested : Array[AccessRequest] = []
  let seen : Map[String, Bool] = Map([])
  for existing in universe.requests {
    requested.push(existing)
    if existing.attributes.length() == 0 {
      seen.set(matrix_key(existing), true)
    }
  }
  if max_requests < 1 || max_requests > 100000 {
    diagnostics.push({
      code: "M001",
      severity: Error,
      message: "matrix limit must be between 1 and 100000",
    })
  }
  if universe.principals.length() == 0 ||
    universe.resources.length() == 0 ||
    actions.length() == 0 {
    diagnostics.push({
      code: "M002",
      severity: Error,
      message: "matrix requires principals, resources, and actions",
    })
  }
  for action in actions {
    if !is_valid_identifier(action) {
      diagnostics.push({
        code: "M003",
        severity: Error,
        message: "invalid matrix action \{action}",
      })
    }
  }
  if has_errors(diagnostics) {
    return { universe, generated_requests: 0, diagnostics, }
  }
  let mut generated = 0
  for principal in universe.principals {
    for action in actions {
      for resource in universe.resources {
        let request : AccessRequest = {
          principal_id: principal.id,
          action,
          resource_id: resource.id,
          attributes: [],
        }
        let key = matrix_key(request)
        if seen.get(key) is None {
          if requested.length() >= max_requests {
            diagnostics.push({
              code: "M004",
              severity: Error,
              message: "matrix exceeds configured request limit",
            })
            return { universe, generated_requests: 0, diagnostics, }
          }
          requested.push(request)
          seen.set(key, true)
          generated += 1
        }
      }
    }
  }
  {
    universe: {
      principals: universe.principals,
      resources: universe.resources,
      requests: requested,
    },
    generated_requests: generated,
    diagnostics,
  }
}

///|
/// Returns a summary of how many distinct subject/target tenant pairs occur
/// in the explicit universe. This helps reviewers judge sample breadth.
pub fn tenant_pairs(universe : RequestUniverse) -> Array[(String, String)] {
  let pairs : Array[(String, String)] = []
  for request in universe.requests {
    let subject = principal_tenant(universe, request.principal_id)
    let target = resource_tenant(universe, request.resource_id)
    if subject == "" || target == "" {
      continue
    }
    let mut found = false
    for pair in pairs {
      if pair.0 == subject && pair.1 == target {
        found = true
        break
      }
    }
    if !found {
      pairs.push((subject, target))
    }
  }
  pairs
}
