# Testing strategy

How `mystic-crypt`, `crypt-data` and `crypt-api` are tested, what that found, and what the numbers
mean. The READMEs and [CRYPTO_CAPABILITIES.md](CRYPTO_CAPABILITIES.md) link here rather than
repeating it.

Crypto bugs are usually silent: the round trip still works and the output is still wrong. Every
item below is a consequence of that.

---

## What the strategy found this cycle

These defects were in code that compiled and, in most cases, had passing tests. That is the
starting point, not a footnote: the old suite was passing on broken code, which is why the
process now measures the *whole* suite - old tests included - with mutation testing, and why each
fix ships with a test that is verified to fail without it.

| Where | What was wrong | How it was caught |
|---|---|---|
| `KeyCommittingAeadEncryptor` | The superclass eagerly built a cipher at construction time using the *default* PBE transformation while the subclass's `newCipher` built a GCM parameter spec - every instantiation threw `InvalidKeyException`. Its 19 tests all failed. | The class had been merged with its failing tests; a later full run of the suite during review surfaced them. |
| `FeldmanVSS.splitSecret` | `secret.mod(q-1).add(1)` silently split `secret + 1`. The sibling test compared the reconstruction against the already-mutated internal value and passed. | A round-trip test comparing against the *original input bytes* failed on the last byte. |
| `Blake2bHasher.hashWithKey` / `Blake2sHasher.hashWithKey` | Bouncy Castle's keyed constructor hardcodes the output length; any call with a key and a non-default digest length threw `OutputLengthException`. The classes had no tests. | A throwaway probe test written before the real suite. Probes are deleted by design, so history shows only the fix (`519393f3`). |
| `BcryptHasher` | Called `BCrypt.gensalt/hashpw/checkpw` - the jBCrypt API shape, which does not exist on Bouncy Castle's `BCrypt`. Could not compile. | First compile of the branch. |
| `ScryptHasher.hash(...)` | Generated a random salt internally and *discarded* it, returning only the derived key - unverifiable. | Review of the never-compiled branch; a hash-then-verify round trip was added as the regression test. |
| `SRP6aClient` / `SRP6aServer` | **Security.** Neither side checked the peer's public value against zero mod N (RFC 5054 §2.5.3 / §2.5.4) - a malicious client could force a session key independent of the password. Every hash step also used signed, inconsistently padded `BigInteger.toByteArray()`, and `DEFAULT_N` was a hex string parsed as decimal - the class crashed on every use, and since the branch did not compile its tests had never run. | Review against Bouncy Castle's reference `SRP6Util`; the hand-rolled math was replaced by BC's implementation, zero-key regression tests added. |
| `PBEFileEncryptor` / `PBEFileDecryptor` | The encryptor computed the decorated file content and *discarded* it - `CryptObjectDecorator`s never affected file encryption. The decryptor re-read the file per loop iteration, so with more than one decorator only the innermost was stripped. Every round-trip test passed: "never added" and "never removed" agree. | Mutation testing: a mutant on the encryptor's decorator loop survived; tracing why nothing could notice led to the discarded return value. The regression test decrypts *without* the decorators to see what was really encrypted; each half was verified to fail separately against the old code. |
| `KeyPairInfo.isValid` (`crypt-data`) | The registered-algorithm check was inverted: `RSA`/2048 and `EC`/256 were reported *invalid*; unknown names fell through into key-size probing and escaped as `InvocationTargetException`, which the existing test had enshrined as expected. | Coverage pass: the `return false` was uncovered, the condition was judged a defect rather than something to pin with a test, and the fix was made first. |
| `SimpleObfuscatorExtensions.disentangle` | A spurious extra condition meant any substitution whose replacement was not itself an original character was never reversed. The existing tests used a shift cipher, which happens to satisfy the condition. | Code review; a regression test with replacements that are *not* original characters shipped with the fix. |
| `Pkcs11FactoryTest` guard | The "skip if no PKCS#11 module" guard used `new File(configPath).exists()`; with the property unset Gradle forwards an empty string, and `new File("").exists()` is `true` - the tests ran against an empty path and failed instead of skipping. | Empirical check of the JDK behaviour; guard now requires a non-blank path that `isFile()`. |
| `SecurityProvider.fromName` (`crypt-api`) | Never tested - every existing test exercised the enum's built-in `valueOf`. | Coverage report: the only uncovered lines in the repo. |
| `BaseByteArrayEncryptor(SecretKey)` / `BaseByteArrayDecryptor(SecretKey)` | The convenience constructor was unusable: `AbstractCryptor` builds a cipher during construction from `newAlgorithm()`, which defaults to the legacy PBE transformation, so every raw AES or ChaCha20 key was rejected with `InvalidKeyException: Algorithm requires a PBE key`. The existing test enshrined the exception as expected behaviour. | Writing `ReadmeExamplesTest`: the simplest example in the README did not run. |
| `PrivateKeyBruteForceProcessor.resolvePassword` | **Non-termination.** For an unencrypted PKCS#8 key `isPrivateKeyPasswordProtected` is false, so the `while (true)` loop was entered anyway; the reader then threw `PEMException` on every attempt, and because `PEMException extends IOException` the loop's catch swallowed it as a wrong-password signal and grew the attempt space forever. No input made it terminate. | Coverage pass: asking *why* no test could reach a branch exposed the loop. The regression test hangs against the old code, hence its preemptive 10 s timeout. |
| `ObfuscatorExtensions.inverseToMap` | Threw `NullPointerException` for its own declared `Character` key type: it cloned the key via `CloneObjectExtensions.clone`, which returns `null` for `Character`, then passed that to `Optional.of`. An existing test documented this as known-broken instead of failing on it. | Same coverage pass; `Character` is immutable, so the key is used directly and only the rule value is cloned. |
| `CryptObjectDecoratorExtensions.undecorateWithBytearrayDecorator` | **Silent data loss.** `ArrayUtils.removeElements(result, prefix)` deletes the prefix bytes from *anywhere* in the content, not just the start: `hello` with prefix `he`/suffix `lo` came back as `llo`, `secret` with `se`/`et` as `cret`, `ab` with `ab`/`cd` as the empty string. Same shape as the `PBEFileEncryptor` defect above. | Mutation pass: a mutant on the prefix check survived; a round trip comparing against the original bytes failed. |
| `CryptObjectDecoratorExtensions.startsWith` / `endsWith` (private) | `startsWith` indexed `array[i]` without checking the array is at least as long as the prefix (`ArrayIndexOutOfBoundsException`). `endsWith` fell through to an unconditional `return true` whether every suffix byte matched *or* the array simply ran out first, so `removeFromEnd` then computed a negative length (`NegativeArraySizeException`) - and the existing test asserted that exception as correct. The fourth bug-enshrining test of the cycle. | Same mutation pass. |
| `SRP6aClient.computeSessionKey` / `SRP6aVerifierGenerator.generateVerifier` | Not a defect in the code, but an untested security property: both wipe the UTF-8 `passwordBytes` they derive, and no test could tell whether they did. Declared an equivalent mutant in the first pass; the adversarial verifier disproved that - Bouncy Castle's `SRP6Util.calculateX` hands the array to `Digest.update` *by reference*, so a recording digest observes the production buffer. | Adversarial verification of an equivalence claim. `SrpPasswordBytesWipeTest` now asserts the buffer reads all zeroes. |
| `Argon2SupportTest.verify_answersFalseForATamperedHash` (test suite) | Flaky by construction: it flipped the *last* base64 character of the 43-character unpadded hash, of which only 4 bits are significant - whenever that character was `A`, the `A→B` flip decoded to identical bytes, `verify` correctly answered `true`, and the test failed. One run in sixteen. The sibling PBKDF2 test already carried a comment warning about exactly this. | First reported as "could not be reproduced in eight runs"; root-caused during the mutation pass when it failed on a clean tree. Now tampers the first character. |

---

## How the numbers were produced, and by whom

For `crypt-data` and `mystic-crypt` the coverage and mutation work ran as a scripted loop in an
isolated git worktree per repository, so concurrent work on `develop` could not contaminate the
measurement. The stages were performed by AI agents (Claude, orchestrated by a workflow script),
each stage in a fresh context with no access to the previous stage's notes; the author
(Asterios Raptis) reviewed the resulting diffs and merged them through pull requests. `crypt-api`
had one uncovered method and 78 mutants and was closed directly on `develop` in a single reviewed
commit; it did not go through the loop.

1. **Coverage** - write tests until the per-class report plateaus; every remaining miss must come
   with a specific reason.
2. **Verification** - a second agent, instructed to distrust stage 1: re-runs the test and coverage
   tasks itself, re-reads the totals from the JaCoCo XML, confirms nothing under `src/main` or the
   build configuration was touched, reads every new or modified test for tests that cannot fail
   (no assertion, `assertTrue(true)`, a value compared with itself, parameterised cases that all
   hit the same branch), flags any test slower than a few seconds, and challenges every
   "uncoverable" claim against the source.
3. **Fix** - stage 2's findings are addressed and stage 2 runs again; up to two fix rounds. This
   cycle `crypt-data` needed one, `mystic-crypt` none.
4. **Mutation** - PIT runs over the whole suite; each surviving mutant is traced to the assertion
   that would kill it and that assertion is added. Survivors left standing need a stated reason
   (equivalent mutant, unreachable code). For the final `mystic-crypt` pass the 33 survivors were
   split into six clusters, one agent each in its own worktree, and every claimed kill had to be
   proven the same way: apply the mutation to the production source by hand, watch the named test
   fail, revert. A second agent per cluster then re-did every one of those mutations itself,
   attacked every equivalence argument with the source, and read each new test for ones that
   cannot fail. That pass found 0 false kills and 0 vacuous tests - and disproved two equivalence
   claims (the SRP `passwordBytes` wipes), which then got the tests they needed.
5. **Final verification** - an independent full build and coverage re-measurement, a recount of
   killed/total from stage 4's PIT report (PIT is not re-run), and a re-read of the
   mutation-hardening diff with the stage 2 criteria. For `mystic-crypt` this stage also tightened
   two weak assertions it found in older tests.

Stage 2 exists because a suite optimised for the coverage number alone can reach 100% with tests
that would not notice the code being deleted. Stage 4 measures how well that worked; it does not
prove the absence of weak tests.

---

## Numbers

Measured 2026-08-23. *Mutation score* divides killed mutants by all mutants, including ones in code
no test executes; *test strength* divides only by mutants in executed code, so it answers "of the
code the tests do run, how much would they notice being broken?".

| Repo | Measured on | Tests | Line | Branch | Mutation score (killed / generated) | Test strength |
|---|---|---|---|---|---|---|
| `crypt-api` | `develop` @ `cf35381` (released as 10.0.0) | 271 | 100.00% | 100.00% | 100.0% (78 / 78) | 100.0% |
| `crypt-data` | `develop` @ `7effa34` (PR #5) | 1018 | 100.00% | 100.00% | 99.6% (779 / 782) | 99.6% |
| `mystic-crypt` | `develop` @ `d2fa0824` (PR #76) | 752 | 99.91% | 100.00% | 98.8% (997 / 1009) | 98.9% |

Regenerate with the commands under [How to run](#how-to-run); the reports are
`build/reports/jacoco/test/jacocoTestReport.xml` and `build/reports/pitest/`.

`crypt-api` is the only one of the three at a literal 100% mutation score. The other two are not
at 100% because the remaining survivors cannot be killed without making the code worse - see
["Why not literal 100%"](COVERAGE_EXCEPTIONS.md#why-not-literal-100) in
[COVERAGE_EXCEPTIONS.md](COVERAGE_EXCEPTIONS.md) for the per-mutant reasoning. Two rounds of this
cycle's work (PR #69/#76 for `mystic-crypt`, PR #5 for `crypt-data`) went specifically after every
surviving mutant: the first round killed what was killable and documented the rest, a second pass
re-examined every documented survivor and found seven that were dead code rather than genuinely
untestable code - removing the redundant guard around them killed the mutant and simplified the
method at the same time. What is left after both rounds is the floor, not something left undone.

**What these numbers do not tell you.** The two uncovered lines in `mystic-crypt` are
`MysticCryptCli.main`, which is `System.exit(execute(args))`: no in-process test can execute it
and survive, and all CLI logic lives in the covered `execute`. The PKCS#11 tests run on CI against
a SoftHSM2 token set up by the workflow, so `Pkcs11Factory` counts towards the `crypt-data` number
everywhere, not only on a developer machine with SoftHSM2 installed. There has been no external
audit and no fuzzing. Known-answer vectors exist only where the primitive is deterministic and a
reference was at hand (SHA-3, generated with OpenSSL); for randomised primitives the tests assert
properties, not bytes. The "equivalent mutant" judgements in
[COVERAGE_EXCEPTIONS.md](COVERAGE_EXCEPTIONS.md) are reasoning from the source, checked by an
adversarial verification stage, not a formal proof.

Every remaining surviving mutant is listed with its reason in
[COVERAGE_EXCEPTIONS.md](COVERAGE_EXCEPTIONS.md). In short: a mutation that rewrites a constant
return as itself, boundary mutants whose two variants behave identically for every reachable
input, a `System.exit`, and a handful of calls with no observable effect.

---

## Principles

1. **Verify before implementing.** Before wiring in a JDK or Bouncy Castle primitive, a throwaway
   probe test confirms the API behaves the way the implementation is about to assume; the probe is
   deleted and the real suite written against the confirmed behaviour. One defect this cycle (the
   Blake2 keyed-output length) was caught at that point.
2. **Test first for new primitives.** The intent is test-before-class; history shows that was not
   always done (the Blake2 hashers landed without tests), which is what principle 1 is there to
   catch.
3. **Assert the property, not the bytes.** Most output is randomised per call (fresh IV, salt,
   ephemeral key), so tests assert round trips, determinism where required and non-determinism
   where required, "different key fails", and "both parties derive the same secret". Known-answer
   vectors are used where the primitive is deterministic and a reference exists.
4. **Negative cases are not optional.** Tampered ciphertext, IV, tag and associated data; wrong key
   and wrong password; too few secret shares; a zero public value in SRP; out-of-range and null
   parameters.
5. **A fix ships with a test that fails without it** and says what it guards against, in its
   Javadoc or an inline comment - e.g. the SRP zero-key tests, the `disentangle` regression test,
   `PBEFileDecoratorRoundTripTest`.
6. **Coverage is the floor, mutation score is the bar.** A covered line only proves it ran.

---

## Test layers and tooling

| Layer | Shape | Where |
|---|---|---|
| Unit / parameterised | `@ParameterizedTest` + `@MethodSource` over a `Stream` of a Java `record` per case | all three |
| Round-trip / property | encrypt→decrypt, obfuscate→disentangle, split→combine, sign→verify, encapsulate→decapsulate | `mystic-crypt`, `crypt-data` |
| Negative | tamper one byte and expect failure; wrong key/AAD/password; zero public value; boundary values on both sides of every limit | `mystic-crypt`, `crypt-data` |
| Security property | password `char[]` is zeroed after hashing; a fresh random salt/IV per call. (Constant-time comparison via `MessageDigest.isEqual` is a code-review invariant in production code - a unit test cannot observe it.) | `mystic-crypt` |
| Model contracts | [meanbean](https://github.com/meanbeanlib/meanbean) getter/setter/equals/hashCode (`crypt-data`, `mystic-crypt`); record-driven equals/hashCode/toString sweeps for Lombok model classes (`crypt-data`) | |
| Integration | real PEM/DER/PKCS#8/PKCS#12/JKS fixtures under `src/test/resources`; an optional PKCS#11 run against SoftHSM2 that skips when no module is configured | `crypt-data`, `mystic-crypt` |
| End-to-end UI | AssertJ-Swing driving the real Swing application and its PF4J plugins | [mystic-crypt-ui](https://github.com/astrapi69/mystic-crypt-ui) |

Tooling: JUnit Jupiter 6 with `junit-jupiter-params`; meanbean; Mockito in `crypt-data` only,
used to stub `PrivateKey`/`PublicKey`/`X509Certificate` where only `getEncoded()`/`getAlgorithm()`
matter; JaCoCo 0.8.15 (XML + HTML, `check` depends on `jacocoTestReport`, uploaded to Codecov);
PIT 1.25.9 via `info.solidsoft.pitest`, opt-in (`./gradlew pitest`, not part of `check`/`build`
because a run takes minutes); Spotless as part of `build`; GitHub Actions running `./gradlew build`
on JDK 25 (Temurin) for pushes and pull requests, with Maven Central publishing on push events only.

---

## How to run

```bash
./gradlew build                       # tests + coverage + formatting check (what CI runs)
./gradlew test jacocoTestReport       # coverage only -> build/reports/jacoco/test/
./gradlew pitest                      # mutation testing, opt-in, minutes -> build/reports/pitest/
./gradlew spotlessApply               # fix formatting
```

`JAVA_HOME` only needs to point at a JDK that can launch Gradle; the compile target (JDK 25) is
resolved through the Gradle toolchain from `gradle.properties#projectSourceCompatibility`.

---

## Deliberate gaps

- **PKCS#11 / HSM** - `Pkcs11FactoryTest` needs a real module. It runs end-to-end against
  [SoftHSM2](https://github.com/opendnssec/SoftHSMv2) (token init, on-token EC key pair, sign and
  verify) and skips via a JUnit `Assumption` unless `-DPKCS11_TEST_CONFIG=<sunpkcs11.cfg>` is
  given. The `crypt-data` CI workflow installs SoftHSM2, initialises a token and passes that
  property, so the tests run on every CI build and count towards the published number; on a
  developer machine without SoftHSM2 they skip. `Pkcs11FactorySoftHsmTest` auto-detects a local
  installation the same way. A real HSM from a vendor has never been tested.
- **Brute-force processors** - tested with a tiny alphabet and a one-to-two character target so
  the search finishes in milliseconds; runtime at realistic sizes is deliberately not part of the
  unit suite.
- **`SignatureAlgorithmResolver`** (`crypt-data`) brute-forces real certificate generation across
  algorithm/key-size combinations. The parameterised test constrains the search to the smallest set
  that reaches every branch; the two exhaustive sweeps in `SignatureAlgorithmResolverTest` are
  `@Disabled` and exist for local exploration.
- **TLS handshake** - `SecureServer`/`SecureClient` exercise a real `SSLSocket` handshake in test
  sources only; the shipped library stops at `KeyTrustExtensions`, which is unit-tested.
- **UI wiring** of these primitives lives in `mystic-crypt-ui` and is covered by its own
  AssertJ-Swing suite, not here.

## Known issues in the test setup

- A `./gradlew pitest` run in `mystic-crypt` can leave `src/test/resources/crypt/test.txt`
  deleted (a file-based test's cleanup interacting with PIT's forked execution - noted in
  `gradle/mutation-testing.gradle`, not yet root-caused); `git checkout -- src/test/resources/crypt/test.txt`
  restores it. **Check `git status` before committing after a PIT run** - a `git add -A` at that
  point commits the deletion, which is exactly what happened once while preparing PR #69 and
  showed up as 13 failing tests on the next full build.
- A few file-based tests write their output next to their fixtures under `src/test/resources`
  (`mystic-crypt`: `crypt/*.enc`, `der/keystore.jks`; `crypt-data`: `der/certificate.der`,
  `pem/certificate.cert`, `pem/converted-public.pem`) and clean up afterwards; when PIT kills a
  forked JVM before that cleanup runs, the files stay behind. In `mystic-crypt` those paths are now
  in `.gitignore`; in `crypt-data` they are untracked and safe to delete. Moving those tests onto
  `@TempDir` is the proper fix.

---

## Conventions for contributors

- A test class mirrors its class under test (`…mystic.crypt.sha.Blake2bHasher` →
  `src/test/java/…/mystic/crypt/sha/Blake2bHasherTest.java`); additional focused classes such as
  `FileCryptorEdgeCasesTest` sit next to it in the same package.
- Multiple input variants → one parameterised test with a `record` per case, named after what
  varies (`FromNameCase`, `BoundaryCase`).
- Assert the property, then the negative. A round-trip test without the matching
  "wrong key / tampered input fails" test is half a test.
- Do not lower a coverage or mutation number with a change. If a new line genuinely cannot be
  tested, give the same kind of per-line reason as in [COVERAGE_EXCEPTIONS.md](COVERAGE_EXCEPTIONS.md).
- New file-based tests use `@TempDir`, not `src/test/resources`.
- Do not commit a new private key as a fixture, even a throwaway one that guards nothing - a secret
  scanner cannot tell it from a leaked key, and it will block the pull request (it blocked PR #64).
  Generate it into a `@TempDir` in `@BeforeAll` instead, as `PrivateKeyBruteForceProcessorTest`
  does. The PEM and DER fixtures already under `src/test/resources` predate this rule and stay.
- When tampering with an encoded hash in a negative test, flip a character that carries
  significant bits. The last character of an unpadded base64 string may carry only two or four;
  `java.util.Base64` discards the rest, and the "tampered" value decodes to the original.
- `./gradlew spotlessApply` before committing; `./gradlew build` before pushing; `./gradlew pitest`
  before a release and whenever a change touches validation logic, boundary arithmetic or anything
  that zeroes secrets.
