# mystic-crypt

Java cryptography library (JDK 25, Gradle, JPMS module
`io.github.astrapisixtynine.mystic.crypt`), published to Maven Central as
`io.github.astrapi69:mystic-crypt`. Current version: see `gradle.properties`
(`projectVersion`).

Top of a three-repo family, released in this order:

1. `crypt-api` - interfaces, enums (KeyPairGeneratorAlgorithm, KeystoreType, ...)
2. `crypt-data` - factories, key readers/writers, extensions
3. `mystic-crypt` - this repo: encryptors/decryptors, obfuscation, PQC
   (ML-KEM, ML-DSA, SLH-DSA), SRP/JPAKE, and the picocli CLI

All three live side by side under `~/dev/git/hub/astrapi69/`. A downstream
release commit is pushed only when the upstream version is resolvable on
Maven Central.

## Layout

- `src/main/java/.../mystic/crypt/` - one package per concern: `key` (signers,
  verifiers, KEM, key exchange), `cli` (picocli commands, root
  `MysticCryptCli`), `pw` (password hashing), `obfuscation`, `file`, `sha`,
  `ssl`, `provider` (Bouncy Castle registration), ...
- `docs/TESTING.md` - canonical test/coverage/mutation numbers (with the
  commit they were measured on); `docs/COVERAGE_EXCEPTIONS.md` - every
  uncovered line and surviving PIT mutant with its reason.
- `gradle/*.gradle` - split build config (dependencies, testing,
  mutation-testing, formatting, publishing, tagging).

## Commands

`make help` lists the same things as named targets; the Gradle calls below are
what those targets run.

```
./gradlew clean build      # tests + Jacoco + Spotless check - the everyday gate
./gradlew spotlessApply    # format + license headers (run before committing)
./gradlew pitest           # PIT mutation testing (minutes; restores needed:
                           #   git checkout -- src/test/resources/crypt/test.txt)
./gradlew publishAllPublicationsToCentralPortal   # Central upload (USER_MANAGED;
                           # needs CENTRAL_PORTAL_TOKEN_USERNAME/PASSWORD env)
./gradlew tagRelease       # RELEASE-X tag (tag push triggers publish.yml!)
```

`make pitest` restores `src/test/resources/crypt/test.txt` itself and keeps PIT's
exit code; `make publish-central` and `make tag-release` refuse to run without
`CONFIRM=yes`, because in this repo the tag is what uploads.

## Conventions (details in .claude/rules/)

- Gitflow on `develop`; every pushed change gets a PR (workflow.md).
- Bug fixes: GitHub issue first, failing test first (tdd.md).
- Quality bar: 100% branch coverage, ~99% PIT score, exceptions documented
  per case (quality-gates.md).
- Numbers in docs are measured, never remembered (docs-and-numbers.md).
- Never hand-roll crypto primitives; JDK -> Bouncy Castle -> crypt family ->
  new dependency, in that order (library-first.md).
- Spotless owns formatting; no `git add -A` (PIT leftovers); no
  `Co-Authored-By` trailers for non-human collaborators.

## Session start

1. `git fetch` and compare with origin before building on the local state -
   this repo family has had a diverged never-pushed local line once.
2. `git log --oneline -5` for recent context.
3. `./gradlew build` for a green baseline before changing anything.
