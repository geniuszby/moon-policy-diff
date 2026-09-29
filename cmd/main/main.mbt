///|
/// Entry point for the CLI or runnable program in this template.
/// Keep main focused; move logic into the library package.
/// Run with `moon run cmd/main` from the project root.
fn usage() -> Unit {
  println("MoonPolicyDiff: offline policy change audit")
  println("Usage: moon run cmd/main -- audit BEFORE AFTER UNIVERSE")
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
fn main {
  let args = @env.args()
  if args.length() != 6 || args[2] != "audit" {
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
      println(@lib.render_report(report, gate))
      match gate.verdict {
        @lib.Pass => ()
        @lib.Fail => @sys.exit(1)
        @lib.Indeterminate => @sys.exit(2)
      }
    }
    _ => @sys.exit(2)
  }
}
