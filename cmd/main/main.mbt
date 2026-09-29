///|
fn usage() -> Unit {
  println("MoonPolicyDiff: offline policy change audit")
  println("Usage: moon run cmd/main -- audit BEFORE AFTER UNIVERSE [text|json]")
  println("       moon run cmd/main -- coverage POLICY UNIVERSE")
  println("       moon run cmd/main -- lint POLICY UNIVERSE")
  println("Exit: 0 pass, 1 gate failure, 2 invalid input")
}

///|
fn load(path : String) -> String? {
  Some(@fs.read_file_to_string(path)) catch {
    _ => {
      println("Cannot read \{path}")
      None
    }
  }
}

///|
fn inspect(policy_path : String, universe_path : String, lint : Bool) -> Unit {
  match (load(policy_path), load(universe_path)) {
    (Some(policy_text), Some(universe_text)) => {
      let policy = @lib.parse_policy(policy_text)
      let universe = @lib.parse_universe(universe_text)
      if @lib.has_errors(policy.diagnostics) ||
        @lib.has_errors(universe.diagnostics) {
        for issue in policy.diagnostics {
          println("\{issue.code}: \{issue.message}")
        }
        for issue in universe.diagnostics {
          println("\{issue.code}: \{issue.message}")
        }
        @sys.exit(2)
        return
      }
      if lint {
        println(
          @lib.render_lint(@lib.lint_policy(policy.policy, universe.universe)),
        )
      } else {
        println(
          @lib.render_coverage(
            @lib.measure_policy_coverage(policy.policy, universe.universe),
          ),
        )
      }
    }
    _ => @sys.exit(2)
  }
}

///|
fn main {
  let args = @env.args()
  if args.length() == 5 && args[2] == "coverage" {
    inspect(args[3], args[4], false)
    return
  }
  if args.length() == 5 && args[2] == "lint" {
    inspect(args[3], args[4], true)
    return
  }
  if (args.length() != 6 && args.length() != 7) || args[2] != "audit" {
    usage()
    @sys.exit(2)
    return
  }
  match (load(args[3]), load(args[4]), load(args[5])) {
    (Some(before_text), Some(after_text), Some(universe_text)) => {
      let before = @lib.parse_policy(before_text)
      let after = @lib.parse_policy(after_text)
      let universe = @lib.parse_universe(universe_text)
      if @lib.has_errors(before.diagnostics) ||
        @lib.has_errors(after.diagnostics) ||
        @lib.has_errors(universe.diagnostics) {
        for item in before.diagnostics {
          println("\{item.code}: \{item.message}")
        }
        for item in after.diagnostics {
          println("\{item.code}: \{item.message}")
        }
        for item in universe.diagnostics {
          println("\{item.code}: \{item.message}")
        }
        @sys.exit(2)
        return
      }
      let report = @lib.compare_policies(
        before.policy,
        after.policy,
        universe.universe,
      )
      let gate = @lib.check_gate(report, universe.universe, @lib.strict_gate())
      let format = if args.length() == 7 { args[6] } else { "text" }
      match format {
        "text" => println(@lib.render_report(report, gate))
        "json" => println(@lib.render_report_json(report, gate))
        _ => {
          usage()
          @sys.exit(2)
          return
        }
      }
      match gate.verdict {
        @lib.Pass => ()
        @lib.Fail => @sys.exit(1)
        @lib.Indeterminate => @sys.exit(2)
      }
    }
    _ => @sys.exit(2)
  }
}
