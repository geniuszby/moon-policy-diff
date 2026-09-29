# MoonPolicyDiff

MoonPolicyDiff is an offline MoonBit toolkit for reviewing access-policy changes.
It evaluates the same bounded request space against two policy revisions and
reports grants, revocations, and concrete requests that explain each difference.

The intended users are maintainers of SaaS APIs, internal tools, data platforms,
and agent tool permissions. A policy review should answer **who can do what after
this change**, not only whether the policy file parses.

## Scope

- Deterministic policy evaluation with explicit deny precedence and default deny.
- Roles, role inheritance, tenant and resource matching, and bounded attributes.
- Old/new comparison over an explicit finite request universe.
- Explainable counterexamples, policy lint, and JSON or text reports.
- MoonBit library, command-line demonstration, tests, and CI.

The bounded universe is an input to the analysis. A clean report does not prove
behavior for identities, resources, actions, or attributes outside that universe.
The project does not implement OAuth, authentication, token issuance, an online
authorization server, or a complete Cedar/Casbin interpreter.

## Status

Development is in progress for the September 2026 MoonBit Hackathon. Completed
features and exact verification results will be recorded here as they land.
The public repository is https://github.com/geniuszby/moon-policy-diff.

## Development

```sh
moon check --target js
moon test --target js
moon build --target js
moon fmt --check
```

## Originality and related work

This is an original MoonBit implementation. It is not a port of an existing
policy engine. Existing MoonBit JWT packages verify credentials, while the
proposed focus here is **offline before/after policy behavior and witnesses**.
The standard role/attribute policy concepts are common prior art; the value
must be demonstrated by working analysis, tests, and concrete scenarios.
See [RELATED_WORK.md](RELATED_WORK.md) for the scope of the public overlap scan.

License: Apache-2.0.
