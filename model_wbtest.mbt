///|
test "empty policy has no grants" {
  let policy = empty_policy("baseline")
  assert_eq(policy.rules.length(), 0)
  assert_eq(default_deny().kind, Denied)
}

///|
test "identifiers reject parser metacharacters" {
  assert_true(is_valid_identifier("team.alpha/read"))
  assert_false(is_valid_identifier(""))
  assert_false(is_valid_identifier("bad value"))
  assert_false(is_valid_identifier("bad=key"))
}

///|
test "attributes distinguish missing from empty" {
  let attrs = [("team", "finance"), ("empty", "")]
  assert_eq(lookup_attribute(attrs, "team"), Some("finance"))
  assert_eq(lookup_attribute(attrs, "empty"), Some(""))
  assert_eq(lookup_attribute(attrs, "region"), None)
}
