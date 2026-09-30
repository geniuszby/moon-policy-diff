# Public overlap scan and product boundary

Scan date: 2026-09-29. Searches covered public GitHub and Mooncakes entries for
MoonBit RBAC, ABAC, permission policy, access-control simulators and policy
diffs. The scan cannot see private applications or future submissions. It is
evidence of a public search, not a uniqueness certificate.

## Correction after review — 2026-09-30

The September 29 scan missed two directly relevant authorization libraries.
It is insufficient evidence that the current project avoids topic overlap.
The review notice identifies MoonPolicy as an existing conflicting project.
The public Mooncakes manifest identifies eisem/moon_policy 0.1.0, published
September 21, 2026, with a successful build. Its repository is titled MoonPolicy.
The notice itself does not contain an upstream URL, so this identification
should still be confirmed with the organizers.

Sources checked:

- [MoonPolicy public repository](https://github.com/Eisem/moon_policy)
- [Mooncakes published manifest](https://mooncakes.io/api/v0/manifest/eisem/moon_policy)
- [MoonPolicy current API](https://github.com/Eisem/moon_policy/blob/master/pkg.generated.mbti)
- [MoonPolicyKit impact analysis](https://github.com/jhshuai/MoonPolicyKit/blob/main/impact.mbt)

The capability comparison below uses the current public repositories; it
does not assert that every current API is present in a particular published
archive.

| Existing project | Directly overlapping capabilities |
| --- | --- |
| MoonPolicy | RBAC inheritance, attribute conditions, explicit deny/default deny, policy revision access changes, explanation traces, baseline cases, coverage and lint |
| MoonPolicyKit 0.2.0 | Explainable relationship authorization and old/new decision comparison with newly allowed/newly denied counts |

Version 0.2.0 now depends on the published eisem/moon_policy 0.1.0 package.
The release-audit path uses its native Policy/Request types, JSON loaders,
authorize/access_changes methods, and PolicyCase replay. There is no semantic
translation from the old DSL. The original independent evaluator remains
only as the 0.1 compatibility path; counterfactual attribution and grouped
witnesses have not been ported to the upstream integration.

The implemented extension adds finite typed attribute domains with missing
values and all-or-nothing bounds; checks tenant isolation and forbidden
actions on every allowed replacement request, including unchanged grants;
applies per-action budgets; and exports upstream replay cases. Evidence is
in release_samples.mbt, release_audit.mbt, release_run.mbt, release_wbtest.mbt,
and examples/moonpolicy. These APIs are additional layers on the observed
upstream interface, not a claim that the general ideas are novel or that no
other submission overlaps. Acceptance remains the organizers' decision.

| Project | Observed capability | MoonPolicyDiff boundary |
| --- | --- | --- |
| [mooncred](https://mooncakes.io/docs/moonbitstack/mooncred) | JWT/JWS/JWK and token-claim verification | Compare old and new access decisions over explicit requests; no token cryptography |
| [CanaryRing](https://github.com/EJJ-ai-nb/canaryring) | Canary rollout and blast-radius simulation | Permission grants and revocations, not traffic rollout |
| [MoonBit Target Parity](https://github.com/zhangbowen2006/MoonBitTargetParity) | Compare behavior across compiler targets | Compare authorization policy revisions, not runtimes |
| [moon-data-contract](https://mooncakes.io/docs/lyjttio/moon-data-contract) | Schema compatibility and migration governance | Access decisions for subjects/actions/resources, not data schemas |
| [MoonModGuard](https://mooncakes.io/docs/Noverberrain/moonmodguard) | MoonBit manifest and dependency supply-chain policy audit | Application authorization behavior before and after a policy revision, not package manifests |
| [RoboPolicy Intent Gate](https://github.com/JQ-ai-nb/robopolicy) | Robots rules and AI crawler intent review for URLs | Role, tenant, attribute, action, and resource authorization changes in application policies, not crawler consent |

Role hierarchies, attribute rules, deny precedence, and counterexample search
are established access-control ideas. The implementation does not claim these
algorithms were invented here. The delivered MoonBit policy review engine
provides explicit limits, runnable examples, and reproducible witnesses.
