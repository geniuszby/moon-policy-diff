# Public overlap scan and product boundary

Scan date: 2026-09-29. Searches covered public GitHub and Mooncakes entries for
MoonBit RBAC, ABAC, permission policy, access-control simulators and policy
diffs. The scan cannot see private applications or future submissions. It is
evidence of a public search, not a uniqueness certificate.

| Project | Observed capability | MoonPolicyDiff boundary |
| --- | --- | --- |
| [mooncred](https://mooncakes.io/docs/moonbitstack/mooncred) | JWT/JWS/JWK and token-claim verification | Compare old and new access decisions over explicit requests; no token cryptography |
| [CanaryRing](https://github.com/EJJ-ai-nb/canaryring) | Canary rollout and blast-radius simulation | Permission grants and revocations, not traffic rollout |
| [MoonBit Target Parity](https://github.com/zhangbowen2006/MoonBitTargetParity) | Compare behavior across compiler targets | Compare authorization policy revisions, not runtimes |
| [moon-data-contract](https://mooncakes.io/docs/lyjttio/moon-data-contract) | Schema compatibility and migration governance | Access decisions for subjects/actions/resources, not data schemas |

Role hierarchies, attribute rules, deny precedence, and counterexample search
are established access-control ideas. The implementation will not claim these
algorithms were invented here. The deliverable is a reusable MoonBit policy
review engine with explicit limits and reproducible, actionable evidence.
