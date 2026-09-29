///|
test "JSON report includes machine-readable gate and witnesses" {
  let universe = parse_universe(
      "principal alice a reader -\nresource doc document a -\nrequest alice read doc -",
    ).universe
  let after = parse_policy(
      "policy new\nrule allow permit reader read document - same -",
    ).policy
  let report = compare_policies(empty_policy("old"), after, universe)
  let output = render_report_json(
    report,
    check_gate(report, universe, strict_gate()),
  )
  assert_true(output.contains("\"schema_version\":1"))
  assert_true(output.contains("\"gate\":\"FAIL\""))
  assert_true(output.contains("\"rule\":\"allow\""))
  assert_true(output.contains("\"kind\":\"NEW_GRANT\""))
}

///|
test "JSON quoting escapes names and control characters" {
  assert_eq(json_escape("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"")
}
