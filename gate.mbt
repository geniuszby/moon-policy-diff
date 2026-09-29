///|
pub(all) enum GateVerdict {
  Pass
  Fail
  Indeterminate
} derive(Eq, Debug)

///|
pub(all) struct GateConfig {
  max_new_grants : Int
  max_revocations : Int
  forbid_cross_tenant_grants : Bool
  permitted_principals : Array[String]
  permitted_actions : Array[String]
} derive(Debug)

///|
pub(all) struct GateFinding {
  code : String
  request : AccessRequest
  message : String
} derive(Debug)

///|
pub(all) struct GateResult {
  verdict : GateVerdict
  findings : Array[GateFinding]
} derive(Debug)

///|
pub fn strict_gate() -> GateConfig {
  {
    max_new_grants: 0,
    max_revocations: 0,
    forbid_cross_tenant_grants: true,
    permitted_principals: [],
    permitted_actions: [],
  }
}

///|
fn request_is_exception(request : AccessRequest, config : GateConfig) -> Bool {
  config.permitted_principals.contains(request.principal_id) &&
  config.permitted_actions.contains(request.action)
}

///|
fn is_cross_tenant(universe : RequestUniverse, request : AccessRequest) -> Bool {
  let mut principal_tenant : String? = None
  let mut resource_tenant : String? = None
  for principal in universe.principals {
    if principal.id == request.principal_id {
      principal_tenant = Some(principal.tenant)
      break
    }
  }
  for resource in universe.resources {
    if resource.id == request.resource_id {
      resource_tenant = Some(resource.tenant)
      break
    }
  }
  match (principal_tenant, resource_tenant) {
    (Some(a), Some(b)) => a != b
    _ => false
  }
}

///|
/// Exceptions require both the principal and action to be explicitly listed.
/// They affect only the general grant count, never cross-tenant violations.
pub fn check_gate(
  report : AuditReport,
  universe : RequestUniverse,
  config : GateConfig,
) -> GateResult {
  let findings : Array[GateFinding] = []
  if !report.complete || config.max_new_grants < 0 || config.max_revocations < 0 {
    return { verdict: Indeterminate, findings, }
  }
  let mut new_grants = 0
  let mut revocations = 0
  for change in report.changes {
    match change.kind {
      NewGrant => {
        if !request_is_exception(change.request, config) {
          new_grants += 1
        }
        if config.forbid_cross_tenant_grants &&
          is_cross_tenant(universe, change.request) {
          findings.push({
            code: "CROSS_TENANT",
            request: change.request,
            message: "New cross-tenant access",
          })
        }
      }
      RevokedGrant => revocations += 1
      _ => ()
    }
  }
  if new_grants > config.max_new_grants {
    for change in report.changes {
      if change.kind is NewGrant &&
        !request_is_exception(change.request, config) {
        findings.push({
          code: "NEW_GRANT",
          request: change.request,
          message: "New grant exceeds configured budget",
        })
      }
    }
  }
  if revocations > config.max_revocations {
    for change in report.changes {
      if change.kind is RevokedGrant {
        findings.push({
          code: "REVOCATION",
          request: change.request,
          message: "Revocation exceeds configured budget",
        })
      }
    }
  }
  { verdict: if findings.length() == 0 { Pass } else { Fail }, findings, }
}
