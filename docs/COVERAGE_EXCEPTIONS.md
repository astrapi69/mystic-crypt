# Coverage and mutation exceptions

Every line, branch and mutant that the suites do not cover or kill, with the reason. Companion to
[TESTING.md](TESTING.md); measured on the same trees as the numbers there (2026-08-26). The
"equivalent mutant" judgements are reasoning from the source, checked by an adversarial
verification stage that tried to construct a distinguishing test for each one - not a formal proof,
except where noted below as verified by bytecode inspection (`javap -c`) or exhaustive fuzzing,
which are.

A mutant is listed here only if a test that kills it was actually attempted and the attempt
explained why it cannot work. "Hard to test" is not a reason; "the mutated instruction pushes the
same constant it just discarded" is. And a survivor is listed here only after checking it is not
actually dead code in disguise - see ["Why not literal 100%"](#why-not-literal-100) for what that
check found.

## `crypt-api`

Nothing. Every line, branch and mutant. 78 mutants generated, 78 killed.

## `crypt-data` - 0 lines / 0 branches uncovered; 0 surviving mutants of 779

Every line and branch is covered; no JaCoCo exclusions were added to get there. Nothing survives
either: 779 mutants generated, 779 killed.

The three mutants that used to survive here were cleared in PR #8, and two of them only because
the reasoning that had retired them was re-read rather than re-quoted:

- `EncryptedPrivateKeyReader.getKeyPair` (line 104, `PEMParser.close()`): documented below as a
  leak worth accepting because observing it "would be flaky and platform-dependent". Both halves
  were wrong. The leak is not on the happy path the note assumed but on the exception path, where
  `close()` is never reached at all, so a malformed PEM file leaks a descriptor per call - a real
  defect, filed as `crypt-data` issue #7. And the observation is deterministic: counting the
  entries under `/proc/self/fd` that point at one named file is not the flaky total-descriptor
  heuristic the note had in mind. The fix is `try`-with-resources, which also makes the method
  match `PemObjectReader`, the only other place in `src/main` that opens a PEM parser.
- `EncryptedPrivateKeyReader.getPrivateKey(File, String)` (line 275) and
  `PrivateKeyReader.getPrivateKey(byte[])` (line 474): the fall-through `return optionalPrivateKey`
  after every algorithm attempt has failed. The note below called restructuring these "cosmetic".
  It was cheap rather than cosmetic: the local was initialised to `Optional.empty()`, reassigned in
  every success branch and returned there immediately, so it could never be observed holding
  anything else. Returning `Optional.of(...)` per branch and `Optional.empty()` at the end says so
  in the source, and PIT's own equivalent-constant filter then stops generating the mutant.

Two more used to survive here - `CertFactory.newX509CertificateV3(...)` ×2 and
`HashExtensions.hash(...)` ×2 - until a second look found the guarded conditions were redundant
(`Arrays.stream` on an empty array already no-ops; `MessageDigest.getInstance` already returns a
reset digest). Removing the guards killed the mutants and simplified the method at the same time
(PR #5). See ["Why not literal 100%"](#why-not-literal-100) for how the remaining three were told
apart from those two.

## `mystic-crypt` - 2 lines / 0 branches uncovered; 5 surviving mutants of 1076

Uncovered lines:

- `MysticCryptCli.main`, both lines: `System.exit(execute(args))`. `System.exit` terminates the
  JVM, so no in-process JUnit test can execute it and survive. All CLI logic lives in `execute`,
  which is covered. This is a permanent gap, not an exclusion - no `@Generated` and no JaCoCo
  `excludes` were added. The `VoidMethodCall` mutant on that line (`removed call to System.exit`)
  is the one survivor with no coverage.

Surviving mutants, each with its argument:

**A constant rewritten as itself:**

- `KeystoreVerifier.isKeystoreFile` (line 115): `return true;` after a successful `KeyStore.load`,
  split by try-with-resources into `iconst_1`/`istore 5` … `iload 5`/`ireturn`. Slot 5 has exactly
  one store, the constant, confirmed with `javap -c -l` (round four re-verified this directly rather
  than trusting the write-up). The `return false` in the catch is killed.

  `Argon2Support.verify` and `Pbkdf2Support.verify` used to survive here the same way (their
  `return false;` for a malformed hash shared a `try`/`finally` with the password-zeroing cleanup,
  which routes the value through a local and defeats PIT's equivalent-constant filter). Round four
  extracted the decode-and-compare logic into a `finally`-free private method
  (`decodeAndCompare`); `javap -c` confirms its `return false` now compiles as a direct
  `iconst_0`/`ireturn`, and a full PIT run confirms it is now exercised as a genuine, killable
  mutation point - not merely filtered out. See the round-four commit for the bytecode listings.

**Boundary mutants whose two variants behave identically for every reachable input:**

- `FeldmanVSS.reconstructSecretBytes` (lines 616, 622, 628, `ConditionalsBoundaryMutator`): the
  leading-zero strip and the pad/truncate boundaries around `expectedLength`. Each variant produces
  a byte-for-byte identical array: stripping a leading zero never changes the big-endian value, the
  pad branch re-adds it, and the truncate branch keeps the trailing `expectedLength` bytes either
  way. The only difference at the equality boundaries is array *identity*, and `bytes` is a fresh
  allocation from `BigInteger.toByteArray()` or `Arrays.copyOfRange` that nothing aliases.

  Round four fuzzed a faithful reimplementation of the original and all three boundary variants
  over 5,000,000 random `(bytes, expectedLength)` pairs, including negative `expectedLength` (see
  the sibling `NegateConditionals` mutants below, which negative lengths DID kill) - zero
  divergence for these three. The equivalence is structural: it holds for any `byte[]`, not only
  ones `BigInteger.toByteArray()` can produce, because padding always zero-fills the front
  regardless of what was stripped, and truncation always keeps exactly the trailing
  `expectedLength` bytes regardless of what was removed from the front.

  The two `NegateConditionalsMutator` variants on the same line 616 condition (negating
  `bytes.length > expectedLength` and negating `bytes[0] == 0`) are **no longer in this list** -
  round four killed both. The method is `public` and accepts an arbitrary `expectedLength`; a
  negative one makes the final truncate throw `Arrays.copyOfRange`'s own
  `IllegalArgumentException`, whose message names the exact copy window requested - `"1 > 0"` if
  the leading zero byte was stripped first, `"2 > 1"` if it was not. That message is the one place
  the strip condition is observable from outside the method; see
  `FeldmanVSSEdgeCasesTest.reconstructSecretBytes_withANegativeExpectedLength_failsAfterTheLeadingZeroStrip`.

`KemCommand.call` (line 107, `EmptyObjectReturnValsMutator`, `return report(...)` → `return 0`) is
also **no longer in this list**. It used to be reasoned as equivalent because both branches of
`call()` derive `senderSecret`/`recipientSecret` from the same freshly generated key pair, so by
KEM correctness they can never differ - true for a correct provider, but the JCA `KEM.getInstance`
lookup `MlKemKeyExchange`/`KemFactory` uses is provider-agnostic, and provider substitution is the
standard, supported way to inject a defective implementation without touching production code.
Round four registers a test-only `Provider` at highest precedence whose `KEMSpi` deliberately
returns different secrets from encapsulation and decapsulation, killing the mutant; see
`KemCommandTest.kemProviderWhoseDecapsulationDisagreesSurfacesAsExitCodeOne`.

Three more used to survive here on `KeyCommittingAeadEncryptor` (lines 167, 204, 276):
`associatedData.length > 0` → `>= 0`, guarding `ArrayUtils.addAll(x, associatedData)`. A second look
found `ArrayUtils.addAll` with an empty second array already returns a content-identical copy of
the first, so the length check never changed the outcome. Removing it killed all three mutants and
simplified three call sites at once (PR #76). See ["Why not literal 100%"](#why-not-literal-100).

## What was *not* accepted as equivalent

For the record, because the line between "equivalent" and "uncovered" is where mutation testing
earns its keep:

- `SRP6aClient:206` and `SRP6aVerifierGenerator:153`, `Arrays.fill(passwordBytes, 0)`: first
  declared equivalent because the wiped array is a local that never leaves the method. The
  adversarial pass showed that Bouncy Castle's `SRP6Util.calculateX` passes that array to
  `Digest.update(byte[], int, int)` by reference, so a recording digest holds the production
  buffer and can read it after the call. Now killed by `SrpPasswordBytesWipeTest`.
- `CryptObjectDecoratorExtensions:184`, the `array.length < prefix.length` guard added with the
  `startsWith` fix: `<=` survived the first run because no case fed an input exactly as long as the
  prefix. Now killed by the "input exactly as long as the prefix" case.
- `CertFactory.newX509CertificateV3(...)` ×2 and `HashExtensions.hash(...)` ×2 (`crypt-data`), and
  `KeyCommittingAeadEncryptor` ×3 (`mystic-crypt`): all seven were first written up as boundary
  mutants whose two variants "behave identically for every reachable input" - true, but for the
  wrong reason. The two variants were identical not because the *code* needed both, but because the
  guard they belonged to did nothing at all. Distinguishing "this condition is unobservable" from
  "this condition is redundant" needed reading one level up, to the caller of the guarded call. Both
  are listed here rather than under "surviving mutants" above because the fix already shipped
  (PR #5, PR #76) - the record is kept as a reminder to ask the second question, not just the first.
- `ScryptHasher.isPowerOfTwo:318` and `CryptObjectDecoratorExtensions.endsWith:141`: the equivalence
  argument through each method's one caller was correct and still is - `validateParameters`
  independently rejects `n == 0`, and `removeFromEnd` on an empty suffix returns a
  content-identical copy either way. What was wrong was stopping there. Both are `private` methods
  invokable via reflection, the same technique already used for the SRP wipe tests above, at zero
  cost to production code. A reflective call asserting `isPowerOfTwo(0) == false` and
  `endsWith(x, []) == false` tests the primitive's own contract directly, independent of whether
  today's one caller happens to make the distinction unobservable - and kills both mutants. Fixed
  once the question "could a test reach this without touching `src/main`" was actually asked
  instead of assumed unaskable.
- `FeldmanVSS.reconstructSecretBytes:616` (both `NegateConditionalsMutator` variants): "equivalent
  for every reachable input" was true for the inputs actually checked - but the method is `public`
  and takes an arbitrary `expectedLength`, and every prior check (including this round's own first
  pass, fuzzed over 5,000,000 cases) used only non-negative values. A negative `expectedLength`,
  legal input the method never validates, drives the final truncate into `Arrays.copyOfRange`'s own
  bounds exception, whose message reveals whether the leading-zero strip ran. The unstated
  assumption was the domain, not the algebra - same shape as the `CertFactory`/`HashExtensions`
  case above, one level more subtle.
- `KemCommand.call:107`: "the two secrets can never differ, by KEM correctness" is true for a
  *correct* KEM provider - the argument silently assumed the provider was fixed, when
  `KEM.getInstance(algorithm)` is a provider-agnostic JCA lookup by design. Registering a
  deliberately defective test-only provider at highest precedence is not touching production code
  any more than any other `Security.addProvider` call this suite already makes for Bouncy Castle -
  it is the supported mechanism for substituting an implementation, used here to make the
  documented-as-unreachable branch reachable.

## Why not literal 100%

`crypt-api` and `crypt-data` are at 100.0%. `mystic-crypt` is at 99.5% (5 survivors of 1076). This
section is the answer to "why not push those to 100% too" - worked through for every one of the 5
remaining survivors, not asserted in general. It was written
after four rounds of exactly that push: the first round (PR #69) killed everything killable and
argued the rest was equivalent; the second round (PR #5, PR #76) went back over every argued
survivor a second time and found seven that were not equivalent at all, but dead code that
*looked* like an equivalent mutant because nothing exercised the difference; a third round, prompted
by asking whether a low-risk experiment could still find something, found two more that were
killable through reflection alone, at zero cost to production code; a fourth round on
`mystic-crypt` found three more killable (two by testing outside the input domain a prior
"equivalent" argument had implicitly assumed, one by substituting a defective JCA provider) and
turned two more from unkillable into killable by extracting a `finally`-free helper method so PIT's
own equivalent-constant filter could apply (see above); a fifth round on `crypt-data` (PR #8)
cleared its last three, two of them by re-reading a retirement argument instead of re-quoting it
(see the `crypt-data` section above). What follows is what was left after all five rounds, sorted
by why it stays.

**Provably impossible - not a matter of effort.**

- `MysticCryptCli.main` / `System.exit` (`VoidMethodCallMutator`, no coverage): `System.exit`
  terminates the JVM. JDK 25 removed the `SecurityManager` API that older JVMs used to intercept it
  in tests, so there is no supported way to observe this call from inside the same process and
  survive to assert on it. Not "hard" - there is no API for it anymore.

**Killable only by making the design worse.**

- `FeldmanVSS.reconstructSecretBytes` (3 `ConditionalsBoundaryMutator` mutants, lines 616/622/628):
  the two variants of each boundary produce byte-identical output arrays for any `byte[]` and any
  `expectedLength` - fuzzed over 5,000,000 random pairs (round four) with zero divergence, on top
  of the algebraic proof from the original round (PR #69 commit message, worked numeric examples).
  The only way to make them distinguishable is for the method to leak whether it took the
  strip/pad/truncate path - e.g. returning a marker or exposing the intermediate array by
  reference. That would add an observable side channel to a secret-reconstruction method purely to
  satisfy a mutation testing tool. Refused.
- `KeystoreVerifier.isKeystoreFile:115` (`BooleanTrueReturnValsMutator`): already `public`, so
  unlike `ScryptHasher.isPowerOfTwo` and `CryptObjectDecoratorExtensions.endsWith` (fixed above),
  reflection cannot change anything here - there is no private primitive further in for a test to
  reach. `javap -c -l` shows the survivor is fed by the same `iconst_1` that a successful
  `KeyStore.load` already produces on every execution of the success path, mutated or not; that
  identity comes specifically from how `try`-with-resources compiles, not from encapsulation.
  Killable only by abandoning `try`-with-resources for manual resource management, trading
  automatic cleanup for a mutation score. (This is exactly the trap `Argon2Support.verify` /
  `Pbkdf2Support.verify` used to be in with their own `finally` block - fixed in round four by
  moving the guarded logic out of the `finally`-carrying method entirely. The same move is not
  available here: the `try`-with-resources *is* the guarded logic, there is nothing to extract it
  from.)
Two entries stood here until round five and no longer do, both from `crypt-data`:
`EncryptedPrivateKeyReader.getKeyPair:104` was filed under this heading as an acceptable leak whose
test would be too flaky to be worth it, and the two `getPrivateKey` fall-through returns under a
heading calling their removal cosmetic. Both retirements were wrong, for different reasons, and the
`crypt-data` section above records why. What that says about this list: an argument for keeping a
survivor ages exactly as badly as any other state assertion in these docs.

Conclusion: of the 5 individual surviving mutants, 1 is impossible under the current JDK
(`System.exit`) and 4 can only be killed by weakening a real design property (a
bytecode-compilation artifact of `try`-with-resources, absence of side channels - the 3
`FeldmanVSS` mutants count as one design property, secret-reconstruction arithmetic). None of the
five is a case of "nobody got around to it yet" - and eight mutants that briefly *were* exactly
that (`ScryptHasher.isPowerOfTwo`, `CryptObjectDecoratorExtensions.endsWith` in round three;
`FeldmanVSS.reconstructSecretBytes`'s two `NegateConditionalsMutator` variants and
`KemCommand.call` in round four; `EncryptedPrivateKeyReader.getKeyPair` and the two `getPrivateKey`
fall-through returns in round five) are why this list gets re-checked rather than taken as final.
Round
four also demonstrates a second way a survivor disappears: `Argon2Support.verify` and
`Pbkdf2Support.verify` moved out of this document entirely not because a new test targets them
directly, but because extracting the guarded logic out of the `finally`-carrying method changed
*which* bytecode the mutation lands on. The expectation going in was that PIT's own
equivalent-constant filter would then suppress the mutant's generation outright (per the mechanism
described in earlier rounds); the actual PIT run showed something different but equally final - the
mutant is still generated, just at the new call site, and the suite's existing match/mismatch tests
now kill it directly, because that call site's return value genuinely varies with the comparison
result. Either way the survivor is gone; the assumption about *why* it would be gone was wrong, and
is corrected here rather than left standing.
