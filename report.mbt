///|
pub fn change_name(kind : ChangeKind) -> String {
  match kind {
    NewGrant => "NEW_GRANT"
    RevokedGrant => "REVOKED_GRANT"
    UnchangedAllow => "UNCHANGED_ALLOW"
    UnchangedDeny => "UNCHANGED_DENY"
    Inconclusive => "INCONCLUSIVE"
  }
}

///|
pub fn verdict_name(verdict : GateVerdict) -> String {
  match verdict {
    Pass => "PASS"
    Fail => "FAIL"
    Indeterminate => "INDETERMINATE"
  }
}

///|
pub fn render_report(report : AuditReport, gate : GateResult) -> String {
  let out = StringBuilder()
  out.write_string("MoonPolicyDiff audit\n")
  out.write_string("Before: \{report.before_name}\n")
  out.write_string("After: \{report.after_name}\n")
  out.write_string(
    "Coverage: \{report.requests_considered} explicit requests\n",
  )
  out.write_string("Complete: \{report.complete}\n")
  out.write_string("Gate: \{verdict_name(gate.verdict)}\n")
  out.write_string("New grants: \{count_changes(report, NewGrant)}\n")
  out.write_string("Revocations: \{count_changes(report, RevokedGrant)}\n")
  for diagnostic in report.diagnostics {
    out.write_string("DIAGNOSTIC \{diagnostic.code}: \{diagnostic.message}\n")
  }
  for change in report.changes {
    if change.kind is NewGrant ||
      change.kind is RevokedGrant ||
      change.kind is Inconclusive {
      out.write_string(
        "\{change_name(change.kind)} \{change.request.principal_id} \{change.request.action} \{change.request.resource_id}\n",
      )
      out.write_string("  before: \{change.before.explanation}; rules: ")
      write_ids(out, change.before.decisive_rules)
      out.write_string("\n")
      out.write_string("  after: \{change.after.explanation}; rules: ")
      write_ids(out, change.after.decisive_rules)
      out.write_string("\n")
    }
  }
  for finding in gate.findings {
    out.write_string(
      "FINDING \{finding.code}: \{finding.request.principal_id} \{finding.request.action} \{finding.request.resource_id}\n",
    )
  }
  out.to_string()
}

///|
fn write_ids(out : StringBuilder, ids : Array[String]) -> Unit {
  if ids.length() == 0 {
    out.write_string("(none)")
    return
  }
  for index, id in ids {
    if index > 0 {
      out.write_string(",")
    }
    out.write_string(id)
  }
}
