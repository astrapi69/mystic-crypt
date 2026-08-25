# Coverage and mutation exceptions

Every line, branch and mutant that the suites do not cover or kill, with the reason. Companion to
[TESTING.md](TESTING.md); measured on the same trees as the numbers there (2026-08-23). The
"equivalent mutant" judgements are reasoning from the source, checked by an adversarial
verification stage that tried to construct a distinguishing test for each one - not a formal proof.

A mutant is listed here only if a test that kills it was actually attempted and the attempt
explained why it cannot work. "Hard to test" is not a reason; "the mutated instruction pushes the
same constant it just discarded" is. And a survivor is listed here only after checking it is not
actually dead code in disguise - see ["Why not literal 100%"](#why-not-literal-100) for what that
check found.

## `crypt-api`

Nothing. Every line, branch and mutant. 78 mutants generated, 78 killed.

## `crypt-data` - 0 lines / 0 branches uncovered; 3 surviving mutants of 782

Every line and branch is covered; no JaCoCo exclusions were added to get there.

Surviving mutants:

- `EncryptedPrivateKeyReader.getKeyPair` (line 104): an explicit `PEMParser.close()` after the PEM
  object has already been read - removing it leaks a reader but changes no result.
- `EncryptedPrivateKeyReader.getPrivateKey(File, String)` (line 275) and
  `PrivateKeyReader.getPrivateKey(byte[])` (line 474): the fall-through `return` after every
  algorithm attempt has failed, reached only when a preceding attempt that succeeds on every JDK
  shipped does not.

Two more used to survive here - `CertFactory.newX509CertificateV3(...)` ×2 and
`HashExtensions.hash(...)` ×2 - until a second look found the guarded conditions were redundant
(`Arrays.stream` on an empty array already no-ops; `MessageDigest.getInstance` already returns a
reset digest). Removing the guards killed the mutants and simplified the method at the same time
(PR #5). See ["Why not literal 100%"](#why-not-literal-100) for how the remaining three were told
apart from those two.

## `mystic-crypt` - 2 lines / 0 branches uncovered; 10 surviving mutants of 1074

Uncovered lines:

- `MysticCryptCli.main`, both lines: `System.exit(execute(args))`. `System.exit` terminates the
  JVM, so no in-process JUnit test can execute it and survive. All CLI logic lives in `execute`,
  which is covered. This is a permanent gap, not an exclusion - no `@Generated` and no JaCoCo
  `excludes` were added. The `VoidMethodCall` mutant on that line (`removed call to System.exit`)
  is the one survivor with no coverage.

Surviving mutants, each with its argument:

**A constant rewritten as itself** - PIT's `BooleanFalse/TrueReturnVals` mutators replace the
return value with a constant; when the original *is* that constant the mutant is the original
program. PIT only filters these when the `ireturn` is fed directly by an `iconst`; a `try`/`finally`
or try-with-resources makes `javac` route the value through a local, and the filter misses it.

- `Argon2Support.verify` (line 118) and `Pbkdf2Support.verify` (line 123): the literal
  `return false;` in the `catch (RuntimeException malformed)` branch. Confirmed with `javap -c -l`:
  the method has two `ireturn`s, the survivor is the one fed by `iconst_0`/`istore`, and the other
  one - the actual password comparison on `MessageDigest.isEqual` - is killed by the positive and
  negative tests. *A build where password verification always fails would not pass the suite.*
- `KeystoreVerifier.isKeystoreFile` (line 115): `return true;` after a successful `KeyStore.load`,
  split by try-with-resources into `iconst_1`/`istore 5` … `iload 5`/`ireturn`. Slot 5 has exactly
  one store, the constant. The `return false` in the catch is killed.

**Boundary mutants whose two variants behave identically for every reachable input:**

- `FeldmanVSS.reconstructSecretBytes` (lines 616 ×3, 622, 628): the leading-zero strip and the
  pad/truncate boundaries around `expectedLength`. Each variant produces a byte-for-byte identical
  array: stripping a leading zero never changes the big-endian value, the pad branch re-adds it,
  and the truncate branch keeps the trailing `expectedLength` bytes either way. The only
  difference at the equality boundaries is array *identity*, and `bytes` is a fresh allocation
  from `BigInteger.toByteArray()` or `Arrays.copyOfRange` that nothing aliases. Worked examples
  are in the `mutants/vss` commit message.

**Observationally equivalent for another reason:**

- `KemCommand.call` (line 107): `return report(...)` → `return 0`. `report` returns `match ? 0 : 1`
  where `match` compares the sender's and recipient's shared secrets - and both branches of `call`
  derive those from the same freshly generated key pair and the same ciphertext, so by KEM
  correctness they cannot differ and `report` never returns 1 from this call site. The `1` path of
  `report` itself is killed through a direct test.

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

## Why not literal 100%

`crypt-api` is at 100.0%. `crypt-data` is at 99.6% (3 survivors of 782) and `mystic-crypt` at
99.1% (10 survivors of 1074). This section is the answer to "why not push those to 100% too" -
worked through for every one of the 13 remaining survivors, not asserted in general. It was written
after three rounds of exactly that push: the first round (PR #69) killed everything killable and
argued the rest was equivalent; the second round (PR #5, PR #76) went back over every argued
survivor a second time and found seven that were not equivalent at all, but dead code that
*looked* like an equivalent mutant because nothing exercised the difference; a third round, prompted
by asking whether a low-risk experiment could still find something, found two more that were
killable through reflection alone, at zero cost to production code (see above). What follows is
what was left after all three passes, sorted by why it stays.

**Provably impossible - not a matter of effort.**

- `MysticCryptCli.main` / `System.exit` (`VoidMethodCallMutator`, no coverage): `System.exit`
  terminates the JVM. JDK 25 removed the `SecurityManager` API that older JVMs used to intercept it
  in tests, so there is no supported way to observe this call from inside the same process and
  survive to assert on it. Not "hard" - there is no API for it anymore.
- `Argon2Support.verify:118` and `Pbkdf2Support.verify:123` (`BooleanFalseReturnValsMutator`):
  proven via `javap -c -l` to be the exact same bytecode instruction before and after the mutation
  (`return false` → `return false`). No test, however written, distinguishes a program from itself.

**Killable only by making the design worse.**

- `FeldmanVSS.reconstructSecretBytes` (5 mutants): the two variants of each boundary produce
  byte-identical output arrays; algebraically proven in the PR #69 commit message, with worked
  numeric examples. The only way to make them distinguishable is for the method to leak whether it
  took the strip/pad/truncate path - e.g. returning a marker or exposing the intermediate array by
  reference. That would add an observable side channel to a secret-reconstruction method purely to
  satisfy a mutation testing tool. Refused.
- `KemCommand.report` reached via `KemCommand.call:107` (`EmptyObjectReturnValsMutator`): both
  branches of `call` feed `report` two shared secrets that ML-KEM's correctness property guarantees
  are equal. The only way to make the `match=false` path reachable from `call` is for the KEM
  implementation to sometimes disagree with itself - a real defect, not a test improvement.
- `KeystoreVerifier.isKeystoreFile:115` (`BooleanTrueReturnValsMutator`): already `public`, so
  unlike `ScryptHasher.isPowerOfTwo` and `CryptObjectDecoratorExtensions.endsWith` (fixed above),
  reflection cannot change anything here - there is no private primitive further in for a test to
  reach. `javap -c -l` shows the survivor is fed by the same `iconst_1` that a successful
  `KeyStore.load` already produces on every execution of the success path, mutated or not; that
  identity comes specifically from how `try`-with-resources compiles, not from encapsulation.
  Killable only by abandoning `try`-with-resources for manual resource management, trading
  automatic cleanup for a mutation score.
- `EncryptedPrivateKeyReader.getKeyPair:104` (`PEMParser.close()`, `VoidMethodCallMutator`): this
  is the one case in the list that is **not dead code** - removing the call introduces a real
  resource leak. It survives because a leaked file descriptor is not something a unit test observes
  without OS-level introspection (open file counts, `lsof`-style checks), which would be flaky and
  platform-dependent. Kept exactly as-is; killing this mutant is not worth what the test would cost
  in reliability.

**Already dead code for an unrelated reason - restructuring would be cosmetic.**

- `EncryptedPrivateKeyReader.getPrivateKey(File, String):275` and
  `PrivateKeyReader.getPrivateKey(byte[]):474` (`EmptyObjectReturnValsMutator`): fall-through
  returns after every preceding attempt already returns on success. Provably unreachable given the
  current algorithm list, not merely unobservable. Restructuring to remove the fall-through would
  change nothing about test coverage and is a separate refactor, not a mutation-testing exercise.

Conclusion: of the 13 individual surviving mutants, 3 are impossible under the current JDK and
language (`System.exit`, and the two bytecode-identical `verify` mutants), 8 can only be killed by
weakening a real design property (resource safety, a bytecode-compilation artifact of
`try`-with-resources, absence of side channels, KEM correctness - the 5 `FeldmanVSS` mutants count
as one design property, secret-reconstruction arithmetic), and the remaining 2 are unreachable dead
code whose removal would be cosmetic. None of the thirteen is a case of "nobody got around to it
yet" - and two mutants that briefly *were* exactly that (`ScryptHasher.isPowerOfTwo`,
`CryptObjectDecoratorExtensions.endsWith`, both fixable by reflection alone) are why this list gets
re-checked rather than taken as final.
