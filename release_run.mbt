///|
pub(all) struct ReleaseRun {
  samples : ReleaseSamples
  report : ReleaseReport
} derive(Debug)

///|
pub fn run_release_plan(
  before : @moon_policy.Policy,
  after : @moon_policy.Policy,
  seeds : Array[@moon_policy.Request],
  plan : ReleasePlan,
) -> ReleaseRun {
  let samples = generate_release_samples(seeds, plan.domains, plan.max_requests)
  if !samples.complete {
    let findings : Array[ReleaseFinding] = []
    for message in samples.diagnostics {
      release_issue(findings, "INCOMPLETE_SAMPLE_DOMAIN", message)
    }
    return {
      samples,
      report: {
        complete: false,
        requests_evaluated: 0,
        changes: [],
        findings,
        verdict: Indeterminate,
      },
    }
  }
  {
    samples,
    report: audit_release(before, after, samples.requests, plan.config),
  }
}

///|
pub fn run_moonpolicy_json(
  before : String,
  after : String,
  seeds : String,
  plan : ReleasePlan,
) -> ReleaseRun raise ReleaseInputError {
  let before_policy = @moon_policy.policy_from_json(before) catch {
    _ => raise InvalidReleaseInput("Before policy rejected by MoonPolicy")
  }
  let after_policy = @moon_policy.policy_from_json(after) catch {
    _ => raise InvalidReleaseInput("After policy rejected by MoonPolicy")
  }
  let requests = @moon_policy.requests_from_json(seeds) catch {
    _ => raise InvalidReleaseInput("Seed requests rejected by MoonPolicy")
  }
  run_release_plan(before_policy, after_policy, requests, plan)
}

///|
pub fn release_run_json(run : ReleaseRun) -> Json {
  Json::object({
    "sampling": Json::object({
      "complete": Json::boolean(run.samples.complete),
      "candidate_count": Json::number(run.samples.candidate_count.to_double()),
      "unique_requests": Json::number(run.samples.requests.length().to_double()),
      "scope": Json::string(
        "Only supplied seeds and declared finite attribute values",
      ),
      "diagnostics": Json::array(run.samples.diagnostics.map(Json::string)),
    }),
    "audit": release_report_json(run.report),
  })
}

///|
/// Uses MoonPolicy's native case loader and runner for replay.
pub fn replay_moonpolicy_json(
  policy : String,
  cases : String,
) -> Json raise ReleaseInputError {
  let policy = @moon_policy.policy_from_json(policy) catch {
    _ => raise InvalidReleaseInput("Replay policy rejected by MoonPolicy")
  }
  let cases = @moon_policy.cases_from_json(cases) catch {
    _ => raise InvalidReleaseInput("Replay cases rejected by MoonPolicy")
  }
  if cases.length() == 0 || cases.length() > 100000 {
    raise InvalidReleaseInput("Replay needs 1..100000 cases")
  }
  policy.run_cases(cases).to_json()
}
