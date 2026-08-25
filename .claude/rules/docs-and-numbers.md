# Documentation and numeric claims

## Single source of truth for volatile numbers

Test counts, coverage and mutation numbers live in ONE canonical place:
the metrics table in `docs/TESTING.md` (with the commit hash each number was
measured on) plus the survivor list in `docs/COVERAGE_EXCEPTIONS.md`. Other
documents (README badge and contributing section, CHANGELOG) either reference
them or are updated in the same commit that updates the table. Norms do not
age, state assertions do: prose mentions the principle or the pointer, not a
raw number that will go stale.

## Numeric claims are measured, not remembered

Any number reported anywhere (docs, commit messages, PR bodies, chat
summaries) is verified by running the authoritative command in the same
session:

- Test count: sum of `tests` attributes in `build/test-results/test/*.xml`
  after a full `./gradlew clean build`.
- Line/branch coverage: `build/reports/jacoco/test/jacocoTestReport.xml`
  counters.
- Mutation score and survivors: `build/reports/pitest/mutations.xml` after
  `./gradlew pitest` (note: a PIT run deletes
  `src/test/resources/crypt/test.txt` - restore it and check `git status`
  before staging anything).

Grep output, memory of a previous count, or a number the user quoted are
starting points, never authoritative. If the command cannot be run, mark the
number "as of <date>".

## CHANGELOG discipline

The CHANGELOG entry for a release is part of the release commit, not an
afterthought: rename the pending SNAPSHOT header to the version, fold in
never-released SNAPSHOT sections, list the actual changes. (Both crypt-data
and mystic-crypt had accumulated releases with untouched CHANGELOGs - this
rule exists so that stops.)

## Doc values are read from code, not from memory

Every nameable reference in documentation - a Gradle task, a file path, a
class or option name - is checked against the repo before it is written.

## Definition of done

A task is done when: the code is merged (or the PR is open per PR-PFLICHT),
`./gradlew clean build` is green, tests for the change exist, the docs whose
numbers or statements it touches are updated, and nothing needed for the
change is left dangling.

## Self-clarification

When a question arises mid-task, in order: (1) answer it from repo evidence
(git history, adjacent files, these rules) and note the basis; (2) park it -
take the conservative assumption, mark the spot
(`<!-- TODO(clarify): ... -->` or a code comment), continue; (3) stop and ask
ONLY when it blocks meaningful progress or risks a destructive change. The
final report lists parked questions and the assumptions taken - no silent
guess ever ships.
