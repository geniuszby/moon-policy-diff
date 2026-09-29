///|
test "report states explicit scope and incomplete status" {
  let universe = empty_universe()
  let report = compare_policies(
    empty_policy("old"),
    empty_policy("new"),
    universe,
  )
  let gate = check_gate(report, universe, strict_gate())
  let output = render_report(report, gate)
  assert_true(output.contains("Complete: false"))
  assert_true(output.contains("Gate: INDETERMINATE"))
  assert_true(output.contains("Coverage: 0 explicit requests"))
}
