///|
fn same_rule_scope(a : AccessRule, b : AccessRule) -> Bool {
  a.roles == b.roles &&
  a.actions == b.actions &&
  a.resource_kinds == b.resource_kinds &&
  a.resource_ids == b.resource_ids &&
  a.tenant_relation == b.tenant_relation &&
  a.conditions == b.conditions
}

///|
fn broad_selector(values : Array[String]) -> Bool {
  values.length() == 0 || values.contains("*")
}

///|
fn rule_is_broad_permit(rule : AccessRule) -> Bool {
  rule.effect is Permit &&
  rule.tenant_relation is AnyTenant &&
  broad_selector(rule.roles) &&
  broad_selector(rule.actions) &&
  broad_selector(rule.resource_kinds) &&
  broad_selector(rule.resource_ids) &&
  rule.conditions.length() == 0
}

///|
/// Static and sample-scoped lint. Lint warnings do not change evaluation.
pub fn lint_policy(
  policy : AccessPolicy,
  universe : RequestUniverse,
) -> Array[Diagnostic] {
  let issues : Array[Diagnostic] = []
  for rule in policy.rules {
    if rule_is_broad_permit(rule) {
      issues.push({
        code: "L001",
        severity: Warning,
        message: "rule \{rule.id} permits every supplied role, action, resource, and tenant",
      })
    } else if rule.effect is Permit &&
      rule.tenant_relation is AnyTenant &&
      broad_selector(rule.resource_ids) {
      issues.push({
        code: "L002",
        severity: Info,
        message: "rule \{rule.id} may grant across tenants",
      })
    }
  }
  for i in 0..<policy.rules.length() {
    for j in (i + 1)..<policy.rules.length() {
      let left = policy.rules[i]
      let right = policy.rules[j]
      if same_rule_scope(left, right) {
        if left.effect == right.effect {
          issues.push({
            code: "L003",
            severity: Warning,
            message: "rules \{left.id} and \{right.id} have identical scope and effect",
          })
        } else {
          issues.push({
            code: "L004",
            severity: Warning,
            message: "rules \{left.id} and \{right.id} conflict; deny wins",
          })
        }
      }
    }
  }
  if has_errors(validate_policy(policy)) ||
    has_errors(validate_universe(universe)) {
    return issues
  }
  let coverage = measure_policy_coverage(policy, universe)
  for rule in unmatched_rules(coverage) {
    issues.push({
      code: "L005",
      severity: Info,
      message: "rule \{rule} is not matched by the supplied requests",
    })
  }
  for rule in shadowed_rules(coverage) {
    issues.push({
      code: "L006",
      severity: Info,
      message: "rule \{rule} matches but never decides within the supplied requests",
    })
  }
  issues
}

///|
pub fn count_lint(
  issues : Array[Diagnostic],
  severity : DiagnosticSeverity,
) -> Int {
  let mut count = 0
  for issue in issues {
    if issue.severity == severity {
      count += 1
    }
  }
  count
}

///|
pub fn render_lint(issues : Array[Diagnostic]) -> String {
  let out = StringBuilder()
  out.write_string("Policy lint\n")
  out.write_string("Warnings: \{count_lint(issues, Warning)}\n")
  for issue in issues {
    out.write_string("\{issue.code}: \{issue.message}\n")
  }
  out.to_string()
}
