# Test-Driven Development

Code changes with behavior (a new code path, a condition, a calculation, a
validation, a mapping) follow Red-Green-Refactor:

1. **RED** - write a test that describes the change; it MUST fail first.
2. **GREEN** - the minimal code that makes it pass. YAGNI: nothing "for later".
3. **REFACTOR** - clean up; tests stay green.

## Four-test target per feature or fix

1. **Reproduction test** - the failing test before the fix/feature.
2. **Happy path** - the expected normal case.
3. **Edge cases** - empty/missing/unexpected inputs.
4. **Boundary values** - the edges of the valid range.

Edge + boundary cases are normally ONE parameterized test (JUnit
`@ParameterizedTest` with records/`@MethodSource`/`@CsvSource` and speaking
case names - `test[3]` tells nobody what broke). No artificial tests just for
counting; every test asserts a real behavior property, ideally paired with
its matching negative case.

## Bug fixes

ALWAYS write the reproducing test first (RED, proves the bug), then fix until
GREEN. The reproduction test stays in the repo as a regression guard.

## Repo-specific conventions

- CLI tests drive `MysticCryptCli.execute(...)` and assert the exit code and
  captured stdout/stderr (`AbstractCliTest`), never `main`.
- File-based tests use `@TempDir` with real files - no mocked file systems,
  no mocked KeyStores. Test through the interface the user actually hits.
- Every test class registers Bouncy Castle itself
  (`SecurityProviderSupport.ensureBouncyCastle()` in `@BeforeAll`) - never
  rely on another test class having done it.
- Never delete, comment out or weaken an existing test to make the build
  green.

## Exceptions

No TDD for: pure documentation, pure configuration without logic, mechanical
refactors covered by the existing suite (which must stay green). None of the
exceptions lift the hard rule that `./gradlew build` stays green after every
change.
