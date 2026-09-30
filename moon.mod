// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "geniuszby/moon-policy-diff"

version = "0.2.0"

readme = "README.mbt.md"

repository = "https://github.com/geniuszby/moon-policy-diff"

license = "Apache-2.0"

keywords = [ "authorization", "policy", "rbac", "abac", "change-audit" ]

preferred_target = "js"

description = "MoonPolicy extension for finite attribute sampling, tenant invariants and release regression gates"

import {
  "moonbitlang/x@0.4.49",
  "eisem/moon_policy@0.1.0",
}
