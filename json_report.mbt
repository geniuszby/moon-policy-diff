///|
fn json_hex_digit(n : Int) -> Char {
  "0123456789abcdef".to_array()[n]
}

///|
fn json_escape(value : String) -> String {
  let out = StringBuilder()
  out.write_char('"')
  for c in value {
    match c {
      '"' => out.write_string("\\\"")
      '\\' => out.write_string("\\\\")
      '\n' => out.write_string("\\n")
      '\r' => out.write_string("\\r")
      '\t' => out.write_string("\\t")
      _ => {
        let n = c.to_int()
        if n < 32 {
          out.write_string("\\u00")
          out.write_char(json_hex_digit(n / 16))
          out.write_char(json_hex_digit(n % 16))
        } else {
          out.write_char(c)
        }
      }
    }
  }
  out.write_char('"')
  out.to_string()
}

///|
fn json_bool(value : Bool) -> String {
  if value {
    "true"
  } else {
    "false"
  }
}

///|
fn decision_name(kind : DecisionKind) -> String {
  match kind {
    Allowed => "allowed"
    Denied => "denied"
    Unknown => "unknown"
  }
}

///|
fn write_json_strings(out : StringBuilder, values : Array[String]) -> Unit {
  out.write_char('[')
  for index, value in values {
    if index > 0 {
      out.write_char(',')
    }
    out.write_string(json_escape(value))
  }
  out.write_char(']')
}

///|
fn write_json_request(out : StringBuilder, request : AccessRequest) -> Unit {
  out.write_string("{\"principal\":")
  out.write_string(json_escape(request.principal_id))
  out.write_string(",\"action\":")
  out.write_string(json_escape(request.action))
  out.write_string(",\"resource\":")
  out.write_string(json_escape(request.resource_id))
  out.write_string(",\"attributes\":{")
  for index, pair in request.attributes {
    if index > 0 {
      out.write_char(',')
    }
    out.write_string(json_escape(pair.0))
    out.write_char(':')
    out.write_string(json_escape(pair.1))
  }
  out.write_string("}}")
}

///|
fn write_json_decision(out : StringBuilder, decision : Decision) -> Unit {
  out.write_string("{\"kind\":")
  out.write_string(json_escape(decision_name(decision.kind)))
  out.write_string(",\"explanation\":")
  out.write_string(json_escape(decision.explanation))
  out.write_string(",\"decisive_rules\":")
  write_json_strings(out, decision.decisive_rules)
  out.write_string(",\"traces\":[")
  for index, trace in decision.traces {
    if index > 0 {
      out.write_char(',')
    }
    out.write_string("{\"rule\":")
    out.write_string(json_escape(trace.rule_id))
    out.write_string(",\"effect\":")
    out.write_string(
      json_escape(
        match trace.effect {
          Permit => "permit"
          Deny => "deny"
        },
      ),
    )
    out.write_string(",\"matched\":")
    out.write_string(json_bool(trace.matched))
    out.write_string(",\"reason\":")
    out.write_string(json_escape(trace.reason))
    out.write_char('}')
  }
  out.write_string("]}")
}

///|
pub fn render_report_json(report : AuditReport, gate : GateResult) -> String {
  let out = StringBuilder()
  out.write_string("{\"schema_version\":1,\"before\":")
  out.write_string(json_escape(report.before_name))
  out.write_string(",\"after\":")
  out.write_string(json_escape(report.after_name))
  out.write_string(",\"complete\":")
  out.write_string(json_bool(report.complete))
  out.write_string(",\"requests_considered\":\{report.requests_considered}")
  out.write_string(",\"gate\":")
  out.write_string(json_escape(verdict_name(gate.verdict)))
  out.write_string(",\"new_grants\":\{count_changes(report, NewGrant)}")
  out.write_string(",\"revocations\":\{count_changes(report, RevokedGrant)}")
  out.write_string(",\"diagnostics\":[")
  for index, issue in report.diagnostics {
    if index > 0 {
      out.write_char(',')
    }
    out.write_string("{\"code\":")
    out.write_string(json_escape(issue.code))
    out.write_string(",\"severity\":")
    out.write_string(
      json_escape(
        match issue.severity {
          Info => "info"
          Warning => "warning"
          Error => "error"
        },
      ),
    )
    out.write_string(",\"message\":")
    out.write_string(json_escape(issue.message))
    out.write_char('}')
  }
  out.write_string("],\"changes\":[")
  for index, change in report.changes {
    if index > 0 {
      out.write_char(',')
    }
    out.write_string("{\"kind\":")
    out.write_string(json_escape(change_name(change.kind)))
    out.write_string(",\"request\":")
    write_json_request(out, change.request)
    out.write_string(",\"before\":")
    write_json_decision(out, change.before)
    out.write_string(",\"after\":")
    write_json_decision(out, change.after)
    out.write_char('}')
  }
  out.write_string("],\"findings\":[")
  for index, finding in gate.findings {
    if index > 0 {
      out.write_char(',')
    }
    out.write_string("{\"code\":")
    out.write_string(json_escape(finding.code))
    out.write_string(",\"message\":")
    out.write_string(json_escape(finding.message))
    out.write_string(",\"request\":")
    write_json_request(out, finding.request)
    out.write_char('}')
  }
  out.write_string("]}")
  out.to_string()
}
