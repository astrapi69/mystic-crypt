# Coverage and mutation exceptions

Every line, branch and mutant that the suites do not cover or kill, with the reason. Companion to
[TESTING.md](TESTING.md); measured on the same trees as the numbers there (2026-08-22). The
"equivalent mutant" judgements are reasoning from the source, checked by an adversarial
verification stage that tried to construct a distinguishing test for each one - not a formal proof.

A mutant is listed here only if a test that kills it was actually attempted and the attempt
explained why it cannot work. "Hard to test" is not a reason; "the mutated instruction pushes the
same constant it just discarded" is.

## `crypt-api`

Nothing. Every line, branch and mutant. 78 mutants generated, 78 killed.

## `crypt-data` - 0 lines / 0 branches uncovered; 7 surviving mutants of 788

Every line and branch is covered; no JaCoCo exclusions were added to get there.

Surviving mutants:

- `CertFactory.newX509CertificateV3(...)` ×2 (lines 440, 654): `0 < length` vs `0 <= length` on a
  varargs length - both produce the same certificate for an empty array.
- `HashExtensions.hash(...)` ×2 (lines 246, 275): `MessageDigest.reset()` on a freshly created,
  never-used instance. Removing the call changes nothing the digest produces.
- `EncryptedPrivateKeyReader.getKeyPair` (line 104): an explicit `PEMParser.close()` after the PEM
  object has already been read - removing it leaks a reader but changes no result.
- `EncryptedPrivateKeyReader.getPrivateKey(File, String)` (line 275) and
  `PrivateKeyReader.getPrivateKey(byte[])` (line 474): the fall-through `return` after every
  algorithm attempt has failed, reached only when a preceding attempt that succeeds on every JDK
  shipped does not.

## `mystic-crypt` - 2 lines / 0 branches uncovered; 15 surviving mutants of 1015

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
- `CryptObjectDecoratorExtensions.endsWith` (line 141): the `return false;` inside
  `if (ArrayUtils.isEmpty(suffix))`. The method is private with one caller, which on `true` would
  call `removeFromEnd` with a zero-length suffix - `Arrays.copyOf(result, result.length)`, a
  content-identical copy. The *other* `return false` (suffix does not match) is killed.

**Boundary mutants whose two variants behave identically for every reachable input:**

- `KeyCommittingAeadEncryptor` (lines 167, 204, 276): `associatedData.length > 0` → `>= 0`. The
  only effect is `ArrayUtils.addAll(x, new byte[0])`, which returns a content-identical fresh
  array, and the only consumer is `Cipher.updateAAD`, which reads its argument and never writes it.
  Applying all three at once to the whole suite: 712 tests, 0 failures.
- `FeldmanVSS.reconstructSecretBytes` (lines 616 ×3, 622, 628): the leading-zero strip and the
  pad/truncate boundaries around `expectedLength`. Each variant produces a byte-for-byte identical
  array: stripping a leading zero never changes the big-endian value, the pad branch re-adds it,
  and the truncate branch keeps the trailing `expectedLength` bytes either way. The only
  difference at the equality boundaries is array *identity*, and `bytes` is a fresh allocation
  from `BigInteger.toByteArray()` or `Arrays.copyOfRange` that nothing aliases. Worked examples
  are in the `mutants/vss` commit message.
- `ScryptHasher.isPowerOfTwo` (line 318): `n > 0` → `n >= 0`. Private, one caller
  (`validateParameters`: `!isPowerOfTwo(n) || n < MIN_N`, `MIN_N == 2`). The answer changes only
  for `n == 0`, where the second clause throws the identical `IllegalArgumentException`.

**Observationally equivalent for another reason:**

- `KemCommand.call` (line 107): `return report(...)` → `return 0`. `report` returns `match ? 0 : 1`
  where `match` compares the sender's and recipient's shared secrets - and both branches of `call`
  derive those from the same freshly generated key pair and the same ciphertext, so by KEM
  correctness they cannot differ and `report` never returns 1 from this call site. The `1` path of
  `report` itself is killed through a direct test.

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
