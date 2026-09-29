///|
pub(all) struct DecisionExpectation {
  principal_id : String
  action : String
  resource_id : String
  expected : DecisionKind
} derive(Debug)

///|
pub(all) struct ParsedExpectations {
  expectations : Array[DecisionExpectation]
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
pub(all) struct ExpectationResult {
  expectation : DecisionExpectation
  actual : DecisionKind
  matched_requests : Int
  passed : Bool
} derive(Debug)

///|
pub(all) struct VerificationReport {
  policy_name : String
  passed : Int
  failed : Int
  inconclusive : Int
  results : Array[ExpectationResult]
  diagnostics : Array[Diagnostic]
} derive(Debug)

///|
fn parse_expected_decision(word : String) -> DecisionKind? {
  match word {
    "allow" => Some(Allowed)
    "deny" => Some(Denied)
    _ => None
  }
}

///|
/// Each line: expect PRINCIPAL ACTION RESOURCE allow|deny.
pub fn parse_expectations(source : String) -> ParsedExpectations {
  let expectations : Array[DecisionExpectation] = []
  let diagnostics : Array[Diagnostic] = []
  let lines = source.split("\n").collect()
  for index, raw in lines {
    let line = raw.to_owned().trim().to_owned()
    if line == "" || line.has_prefix("#") {
      continue
    }
    let parts = fields(line)
    if parts.length() != 5 || parts[0] != "expect" {
      diagnostics.push({
        code: "E001",
        severity: Error,
        message: "line \{index + 1}: expected expect PRINCIPAL ACTION RESOURCE allow|deny",
      })
      continue
    }
    match parse_expected_decision(parts[4]) {
      Some(expected) =>
        expectations.push({
          principal_id: parts[1],
          action: parts[2],
          resource_id: parts[3],
          expected,
        })
      None =>
        diagnostics.push({
          code: "E002",
          severity: Error,
          message: "line \{index + 1}: expected allow or deny",
        })
    }
  }
  if expectations.length() == 0 {
    diagnostics.push({
      code: "E003",
      severity: Error,
      message: "no valid expectations supplied",
    })
  }
  { expectations, diagnostics, }
}

///|
fn same_expectation_request(
  expectation : DecisionExpectation,
  request : AccessRequest,
) -> Bool {
  expectation.principal_id == request.principal_id &&
  expectation.action == request.action &&
  expectation.resource_id == request.resource_id
}

///|
/// A request match must be unique. Two sampled requests with different
/// attributes but the same three identifiers are ambiguous for this format.
pub fn verify_expectations(
  policy : AccessPolicy,
  universe : RequestUniverse,
  expectations : Array[DecisionExpectation],
) -> VerificationReport {
  let diagnostics : Array[Diagnostic] = []
  for issue in validate_policy(policy) {
    diagnostics.push(issue)
  }
  for issue in validate_universe(universe) {
    diagnostics.push(issue)
  }
  let results : Array[ExpectationResult] = []
  if has_errors(diagnostics) {
    return {
      policy_name: policy.name,
      passed: 0,
      failed: 0,
      inconclusive: expectations.length(),
      results,
      diagnostics,
    }
  }
  let mut passed = 0
  let mut failed = 0
  let mut inconclusive = 0
  for expectation in expectations {
    let mut count = 0
    let mut actual = Unknown
    for request in universe.requests {
      if same_expectation_request(expectation, request) {
        count += 1
        actual = evaluate_request(policy, universe, request).kind
      }
    }
    let success = count == 1 && actual == expectation.expected
    if count != 1 || actual is Unknown {
      inconclusive += 1
      diagnostics.push({
        code: "E004",
        severity: Error,
        message: "expectation for \{expectation.principal_id}/\{expectation.action}/\{expectation.resource_id} does not match exactly one evaluated request",
      })
    } else if success {
      passed += 1
    } else {
      failed += 1
    }
    results.push({
      expectation,
      actual,
      matched_requests: count,
      passed: success,
    })
  }
  {
    policy_name: policy.name,
    passed,
    failed,
    inconclusive,
    results,
    diagnostics,
  }
}

///|
pub fn render_verification(report : VerificationReport) -> String {
  let out = StringBuilder()
  out.write_string("Policy verification: \{report.policy_name}\n")
  out.write_string(
    "Passed: \{report.passed}, failed: \{report.failed}, inconclusive: \{report.inconclusive}\n",
  )
  for result in report.results {
    out.write_string(
      "\{result.expectation.principal_id} \{result.expectation.action} \{result.expectation.resource_id}: ",
    )
    if result.matched_requests != 1 {
      out.write_string("INCONCLUSIVE\n")
    } else if result.passed {
      out.write_string("PASS\n")
    } else {
      out.write_string("FAIL\n")
    }
  }
  for issue in report.diagnostics {
    out.write_string("\{issue.code}: \{issue.message}\n")
  }
  out.to_string()
}
