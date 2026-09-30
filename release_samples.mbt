///|
/// A finite top-level attribute domain. None removes the attribute; Some
/// uses MoonPolicy's typed value. Domains do not enumerate unknown values.
pub(all) struct ReleaseAttributeDomain {
  source : AttributeSource
  key : String
  values : Array[@moon_policy.AttributeValue?]
} derive(Debug)

///|
pub(all) struct ReleaseSamples {
  requests : Array[@moon_policy.Request]
  complete : Bool
  candidate_count : Int
  diagnostics : Array[String]
} derive(Debug)

///|
fn domain_source_name(source : AttributeSource) -> String {
  match source {
    PrincipalAttribute => "subject"
    ResourceAttribute => "resource"
    RequestAttribute => "context"
  }
}

///|
fn apply_release_attribute(
  request : @moon_policy.Request,
  domain : ReleaseAttributeDomain,
  value : @moon_policy.AttributeValue?,
) -> @moon_policy.Request {
  // Copy all top-level maps so applying another variant cannot mutate an
  // earlier request or the caller's seed. Nested values are never modified.
  let subject_attributes = request.subject_attributes.copy()
  let resource_attributes = request.resource_attributes.copy()
  let context = request.context.copy()
  let attributes = match domain.source {
    PrincipalAttribute => subject_attributes
    ResourceAttribute => resource_attributes
    RequestAttribute => context
  }
  match value {
    Some(item) => attributes.set(domain.key, item)
    None => attributes.remove(domain.key)
  }
  { ..request, subject_attributes, resource_attributes, context, }
}

///|
/// Generates the product of declared domains for each seed, preserving seed
/// and domain order. Overflow or invalid configuration returns no samples.
/// Exact duplicate requests are removed after generation.
pub fn generate_release_samples(
  seeds : Array[@moon_policy.Request],
  domains : Array[ReleaseAttributeDomain],
  limit : Int,
) -> ReleaseSamples {
  let diagnostics : Array[String] = []
  if limit < 1 || limit > 100000 {
    diagnostics.push("Sample limit must be between 1 and 100000")
  }
  if seeds.length() == 0 || seeds.length() > 100000 {
    diagnostics.push("Need 1..100000 seed requests")
  }
  if domains.length() > 32 {
    diagnostics.push("At most 32 attribute domains are supported")
  }
  let seen_domains : Map[(String, String), Bool] = Map([])
  let normalized : Array[ReleaseAttributeDomain] = []
  for domain in domains {
    let key = (domain_source_name(domain.source), domain.key)
    if domain.key == "" ||
      domain.key.contains(".") ||
      (domain.source != RequestAttribute && domain.key == "id") {
      diagnostics.push("Domain key must be a non-reserved top-level attribute")
    }
    if seen_domains.get(key) is Some(_) {
      diagnostics.push("Duplicate attribute domain")
    }
    seen_domains.set(key, true)
    if domain.values.length() == 0 || domain.values.length() > 64 {
      diagnostics.push("Each domain needs 1..64 explicit values")
    }
    let values : Array[@moon_policy.AttributeValue?] = []
    for value in domain.values {
      if !values.contains(value) {
        values.push(value)
      }
    }
    normalized.push({ ..domain, values, })
  }
  if diagnostics.length() > 0 {
    return { requests: [], complete: false, candidate_count: 0, diagnostics, }
  }
  let mut candidate_count = seeds.length()
  for domain in normalized {
    // Division before multiplication avoids integer overflow.
    if candidate_count > limit / domain.values.length() {
      diagnostics.push("Attribute product exceeds configured sample limit")
      return { requests: [], complete: false, candidate_count: 0, diagnostics, }
    }
    candidate_count *= domain.values.length()
  }
  if candidate_count > limit {
    diagnostics.push("Seed count exceeds configured sample limit")
    return { requests: [], complete: false, candidate_count: 0, diagnostics, }
  }
  let requests : Array[@moon_policy.Request] = []
  let seen_requests : Map[String, Bool] = Map([])
  for seed in seeds {
    let mut variants = [seed]
    for domain in normalized {
      let next : Array[@moon_policy.Request] = []
      for variant in variants {
        for value in domain.values {
          next.push(apply_release_attribute(variant, domain, value))
        }
      }
      variants = next
    }
    for request in variants {
      let key = release_request_key(request)
      if seen_requests.get(key) is None {
        seen_requests.set(key, true)
        requests.push(request)
      }
    }
  }
  { requests, complete: true, candidate_count, diagnostics, }
}
