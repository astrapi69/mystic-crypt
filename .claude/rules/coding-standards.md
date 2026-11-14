# Coding Standards

Developer: Asterios Raptis (solo, AI-assisted). Goal: pragmatic, maintainable
library code. No over-engineering. When unclear: ask rather than guess.

## Java

- JDK 25 toolchain, Gradle, JPMS module (`module-info.java` - a new public
  package needs an `exports` entry there, and the consumer side must actually
  resolve it: crypt-data packages are usable only if its module exports them).
- Formatting and license headers via Spotless (`./gradlew spotlessApply`);
  never hand-format against it.
- Javadoc on every public type and member, in the established style of the
  file's neighbors (including the explicit no-arg-constructor javadoc pattern
  in the CLI package).
- No emojis in code or comments. No em-dash; use hyphens or commas.

## Naming

- No generic names: `data`, `info`, `result`, `temp`, `item`, `obj`, `val`,
  `tmp`, `x` are forbidden (exception: loop indices and lambdas). Name the
  thing: `signatureBytes`, `keyAlgorithm`, `storeFile`.
- No I-prefix for interfaces.
- Test names describe behavior, not implementation:
  `deletesExactlyTheGivenAliasAndKeepsTheStoreType`, not `testDelete`.

## Function design and cohesion

- One responsibility per method; over ~40 lines is a refactoring signal.
- "Step 1 / Step 2" comments inside one method mean: split it.
- Do not mix abstraction levels in one method; a high-level method calls
  small, individually testable helpers.
- Crash early: guard clauses at the top, not deeply nested if/else.
- Shared data travels in a record, not in loose maps.
- Hard to test is a design verdict, not a testing problem: a method that
  needs a pile of scaffolding to exercise is cut wrong.

## DRY and the Boy Scout Rule

- Same logic or constant in two places: extract. Three duplicates: refactor
  now, not later.
- Leave touched code cleaner than found - if a touched function violates
  these rules, fix the violation along with the change.

## Git

- Conventional Commits with scope where clear: `feat(cli): ...`,
  `fix(keystore): ...`, `build:`, `docs:`, `test:`, `chore:`.
- One commit per logical change - but atomic means "green individually", not
  "one conceptual thing": when splitting would break an intermediate state
  (source and test edits that only compile together), it is one commit.

## Errors

- Exceptions carry the reason and the offending value, precise enough that an
  issue built from the message is actionable without follow-up questions:
  `"unknown key algorithm 'X'. Use ..."` - never a bare `"failed"`.
- Never swallow an exception; rethrow with context or let it propagate.
- CLI exit codes are the contract; document them and keep error exits
  distinguishable from domain results (see `verify-signature`: 0 valid,
  1 invalid, 2 error).

## Dependencies

New dependencies only after asking, with a manual check on maintenance
status and security. Prefer the existing stack: JDK, Bouncy Castle,
crypt-api/crypt-data, picocli, JUnit 5. See library-first.md.

## Security

- Never commit keys, passwords or tokens - including test fixtures: test key
  material is generated at test runtime, never checked in.
- Secrets stay out of process argument lists where a stdin variant exists
  (`--password-stdin` pattern) and are never echoed into logs or build
  output.
