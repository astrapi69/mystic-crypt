# Quality gates

## The bar

100% branch coverage and the documented PIT mutation score are the release
gate. Every uncovered line and every surviving mutant has a stated reason in
`docs/COVERAGE_EXCEPTIONS.md` - reasons are argued per case, never asserted
in general. Meaningful coverage is the goal: assertions on real behavior
properties, regression pins for known bug classes - not line execution.
Numbers are re-measured and the docs updated before every release
(docs-and-numbers.md).

## Cadence

- `./gradlew clean build` (tests + Jacoco + Spotless) after every change -
  the everyday gate.
- `./gradlew pitest` after a feature phase and before a release - not on
  every commit. Kill what is killable; document the rest with its reason.
- A weakened assertion that a mutant survives (e.g. `contains("1 entries")`
  also matching "-1 entries") is fixed by sharpening the assertion, never by
  excluding the mutant.

## Gates fail closed

A check that cannot check must never report green. Absent tool, missing
baseline, empty input set: that is a failure or an explicit skip with a
reason, never a pass. "I could not check" is not "there is nothing to find".
A gate that scans a set reports the size of the set - "0 findings" and
"0 files looked at" must not print the same green.

## Checks are disabled by declaration, not by silence

Turning any check, hook or workflow off (or letting it degrade into a
warn-and-return no-op) happens only visibly: in the diff, with a reason.
A rule weakened inside a diff framed as cleanup/reflow is never accepted -
either the change is content-neutral or it is declared and reviewed as a
content change.

## Wired is not working

A new CI workflow, scheduled job or hook is triggered at least once in the
same session it is wired, and the result of that first run is confirmed and
noted. A workflow that ships without a known-good first run is a hypothesis,
not a feature. (Concretely: `publish.yml` triggers on `RELEASE-*` tag pushes -
after a manual Central publish, pushing that tag re-runs it as a duplicate.)

## Stale is not flaky

A test that fails deterministically on unchanged code is stale, not flaky:
isolate it, time it, check whether the asserted element/behavior still exists
(`git log <last-tag>..HEAD -- <spec>` proves whether the current diff touched
it). Retries and timeouts are band-aids that mask stale assertions. When a
feature is removed or changed by design, its tests are updated in the SAME
change.

## Real interfaces, real data

Test tools through the interface they actually use (the CLI through
`execute(...)`, key stores through real files in `@TempDir`), not through
mocks of it - mocks hide the resolution and encoding behavior where the real
bugs live. When a change rests on a prediction about data shape (a format, a
heuristic, a mapping), run it against real data before landing and report
what was found - a spec is a hypothesis, not a contract.
