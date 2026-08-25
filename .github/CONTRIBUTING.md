# How to contribute

Contributions are welcome - as GitHub issues and as pull requests.

- **Found a bug?** Open an issue first, with enough context that the fix is
  actionable (input, expected and actual behavior, stack trace). The fix then
  starts with a failing test that reproduces the bug.
- **Pull requests** go against the `develop` branch, one concern per PR, with
  tests for every behavior change. `./gradlew clean build` must be green -
  it runs the tests, the coverage gate and the Spotless format check.
- **Conventions** for tests and code live in
  [docs/TESTING.md](../docs/TESTING.md#conventions-for-contributors) and the
  contributing section of the [README](../README.md#contributing); the
  current coverage and mutation numbers are documented there as well.
