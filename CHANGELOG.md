## Change log
----------------------

Version 12.3-SNAPSHOT
-------------

(nothing released yet)


Version 12.2
-------------

ADDED:

- ECIES, so an EC key pair can encrypt and decrypt and not only sign: EcPublicKeyEncryptor and
  EcPrivateKeyDecryptor on bytes, EcPublicKeyHexEncryptor and EcPrivateKeyHexDecryptor on hex
  strings, in the shape of the RSA pair they sit beside. An EC key has no direct encryption
  primitive the way an RSA key does; ECIES derives a shared secret by ECDH against an ephemeral key
  pair generated for that one message and encrypts under it, so every encryption carries a fresh
  public value and no two are alike. The transformation is ECIESwithSHA256, which needs no
  parameter spec - the block cipher variants require both sides to be handed the same nonce, which
  would have to travel beside the ciphertext. A key of another algorithm is refused by name. (#112)

CHANGED:

- the dependency org.bouncycastle:bcprov-ext-jdk18on is gone. It was pinned at 1.78.1 while
  bcprov-jdk18on is at 1.85.2, and Bouncy Castle publishes no release after 1.78.1 for it, so the
  two could never be brought level. Nothing needed it: without it the suite is green, keygen still
  answers for 27 of the 28 algorithm constants and for all 101 named curves, signing and verifying
  still work across RSA, EC, DSA, ML-DSA and SLH-DSA, and the shadow uber-jar comes out
  byte-identical, all 9296 Bouncy Castle entries with the same CRC. (#120)
- dependency and plugin versions raised through the version catalog: crypt-api 10.0.0 to 10.1,
  checksum-up 3.1 to 3.2, picocli 4.7.6 to 4.7.7, randomizer 10.3 to 10.4, silly-collection 28.1 to
  28.2, test-object 9 to 9.1, and the build plugins nmcp 1.6.1 to 1.6.2, shadow 9.0.0 to 9.6.1,
  spotless 8.10.0 to 8.10.2 and the PIT engine 1.25.9 to 1.30.0. guava stays on 33.7.1-jre: the
  update tool proposed '999.0.0-HEAD-jre-SNAPSHOT', which is guava's placeholder version and not a
  release.

FIXED:

- 'keygen --print-details' named the encoding that was requested rather than the one that was
  written. An EC key and a DSA key asked for PKCS#1 got their traditional label on disk, RFC 5915
  and OpenSSL's DSA form, while the run reported the PKCS#8 label; a key with no traditional form
  at all, ML-DSA among them, was written as PKCS#8 and still reported as PKCS#1. The details line
  now reads the format and the label out of the PEM that was actually written, so it cannot drift
  from the file again, and a DSA key reports its size instead of 'fixed parameter set'. (#114)


Version 12.1
-------------

ADDED:

- The commands whose result is a stream write it to standard output when the output path is '-':
  'encrypt', 'decrypt', 'convert' and both halves of 'share'. It is the same marker '--in' already
  reads standard input from, and it means what leaving the option out means; it exists so that the
  intent can be said out loud in a pipeline. 'convert --to der' still refuses, because DER is
  binary and there is nothing to print. (#104)

CHANGED:

- crypt-data 12.0.0 to 12.2, and KeyFileWriter gives the conversions back to it. The class existed
  because crypt-data wrote PKCS#1 under a PKCS#8 header; that is fixed at its source since 12.1, so
  what is left here is the shape the commands want - text and bytes rather than a stream - and the
  conversions are crypt-data's again.
- The traditional form of a key now carries the label of its own algorithm. The workaround labelled
  everything but RSA 'PRIVATE KEY', which means PKCS#8, over content with the wrapper stripped - a
  file readable as neither format. An EC key gets 'EC PRIVATE KEY' and a DSA key 'DSA PRIVATE KEY';
  a key with no traditional form of its own keeps its PKCS#8 encoding under the header that names
  it. A test had held the wrong premise - "an EC key has no traditional label of its own" - and is
  corrected with the code.
- The message 'sign --signature -' answers with is the shared one now. It names the option and says
  what would have happened, where it used to say only that standard output is not supported. (#101)
- In those commands a remark about the result no longer shares the stream with the result. 'wrote
  23 bytes to out.bin', 'wrote 3 shares to ...' and the description 'convert' prints before
  converting go to standard error, so standard output carries the bytes alone and a pipeline gets
  exactly them. With '--describe' the description IS the answer and stays on standard output. A
  script that parsed these lines out of standard output has to read standard error now. (#104)
- 'encrypt', 'decrypt', 'convert' and 'share' no longer refuse '-' as an output path; that refusal
  from #101 was what kept the trap closed until this meaning existed. 'keygen', 'keyx' and 'sign'
  keep it: a private key, a key exchange secret and a raw signature are not streams a pipeline
  wants. (#104)

FIXED:

- Every command that writes to a file refused nothing when handed '-' as the path: a file literally
  called '-' appeared in the working directory, the command reported success, and the bytes the
  caller expected in a pipe were on disk instead. For 'keygen --out-private' those bytes are a
  private key. The input side reads standard input from '-', which is where the expectation comes
  from, and standard output is already reachable on the output side by leaving the option out - so
  '-' is refused now rather than given a second meaning. 'sign --signature' had guarded itself from
  the start; that guard moved to CliSupport and is used by all twelve output options. (#101)


Version 12.0.0
-------------

ADDED:

- CLI commands `encrypt` and `decrypt` for a file or a piece of text with a passphrase. AES-GCM
  over a key derived with PBKDF2-HMAC-SHA256 at 600000 iterations and a salt that is fresh per
  call, sealed with the key-committing AEAD so a wrong passphrase is rejected by the commitment
  rather than producing plausible rubbish. The output carries a marker, a format version and the
  iteration count, so an encrypted file is recognisable without opening it and raising the default
  later does not strand what the old default produced. Backed by the new public
  `PassphraseCryptor`.
- CLI commands `share split` and `share combine`, exposing Shamir secret sharing. The scheme has
  no integrity check of its own - combining fewer shares than the threshold, or shares of another
  split, silently yields a wrong secret - so the share line carries a random split identifier, the
  threshold and a per-share checksum, and both cases are now statements the tool makes. The
  checksum covers the share and not the secret, so holding one share does not let its holder test
  guesses offline. Backed by the new public `SecretShare` and `SecretSharing`.
- CLI command family `keyx` with `new`, `send` and `receive`: the key exchange as two people use
  it, in three separate runs, each side holding only its own half. ML-KEM 512/768/1024, X25519 and
  the hybrid of X25519 with ML-KEM-768. X25519 has no ciphertext, so there the handshake carries
  the sender's ephemeral public key instead, and every envelope names its algorithm so nobody has
  to know which of the three they hold. Both sides print an eight character fingerprint of the
  derived secret. Backed by the new public `KeyExchangeSupport`. Where `kem` plays both sides
  against itself and shows the mathematics, this is the usable exchange.
- CLI command `convert`, which replaces `der2pem`: it examines a key or certificate file, names
  what it found, and converts between PEM and DER and between PKCS#1 and PKCS#8, for private keys,
  public keys and X.509 certificates. `--describe` asks only what a file is. `der2pem` remains as
  a deprecated alias. Backed by the new public `KeyFileDescription`, `KeyFileReader` and
  `KeyFileWriter`.
- `checksum --hmac` computes a keyed MAC next to the plain digest, so the CLI can answer "was this
  changed by someone without the key" and not only "was this changed". The key is read from
  standard input.
- `hash` offers bcrypt and scrypt alongside Argon2id and PBKDF2. scrypt needed an encoding first:
  `ScryptHasher` produces raw bytes, so the salt and the three cost parameters had to live
  somewhere else, which a stored password hash cannot rely on. The new `PasswordHashFormat` reads
  from a stored hash which algorithm produced it.
- `sign` and `verify-signature` accept RSA, ECDSA and DSA next to Ed25519, ML-DSA and SLH-DSA, and
  read the key from DER as readily as from PEM. Signing, verifying and key decoding all go through
  Bouncy Castle: an EC key on a named curve is rejected by the JDK's own provider when it signs,
  and verification with such a key returns false rather than throwing, so a valid signature would
  read as an invalid one with nothing saying why.
- `cert` writes basic constraints, key usage and subject alternative names, with `--critical`
  naming which of them to mark critical. Backed by the new public `SelfSignedCertificateFactory`,
  which also refuses to sign an RSASSA-PSS key with a plain RSA signature: RFC 4055 requires PSS,
  and a certificate signed the other way is rejected by some verifiers without saying why.
- `keygen` takes `--curve` for elliptic curve keys, `--format` for PKCS#8 or PKCS#1, and
  `--print-details`, which names the algorithm, the size or curve and the encoding actually
  written.
- `obfuscate` and `disentangle` take rules that carry an operation and the positions it applies at
  (`--rule a=x:UPPERCASE@0,3`) next to the plain substitution.

CHANGED:

- BREAKING for the command line: `verify` no longer accepts `--algorithm`. Every encoding this
  library writes says what produced it, so the algorithm is read from the hash; naming it a second
  time was only a way to get it wrong, and the wrong name turned "this is a bcrypt hash" into "the
  password does not match". A hash whose encoding belongs to no known algorithm is now exit code 2
  with the encodings it knows, not the negative answer 1.
- BREAKING for the command line: `checksum` prints the value followed by which of the two
  questions it answered, in the shape `sha256sum` uses. The value is still the first
  whitespace-separated field.
- `PasswordAlgorithm` gained the constants `bcrypt` and `scrypt`. It is a public enum in an
  exported package, so a consumer whose `switch` covered all of its constants no longer compiles.
- requires crypt-data 12.0.0, whose `EncryptedPrivateKeyReader#getKeyPair` no longer leaks a file
  descriptor for every malformed PEM file
- the quality gates fail closed rather than warning, and the rule set the repository works under is
  written down in `CLAUDE.md` and `.claude/rules/`
- a CI workflow publishes the tested-use-case count as a badge
- test quality: 1234 tests (up from 883), 99.94% line and 100% branch coverage, PIT mutation score
  99.6% (1498 of 1504 mutants killed). The command line work added roughly four hundred mutants;
  the six that survive are argued one by one in docs/COVERAGE_EXCEPTIONS.md, and four of the
  thirty-five that first survived were answered by removing code that decided the same thing twice
  rather than by adding a test for it

FIXED:

- `ObfuscatorExtensions#disentangle(BiMap, String)` did not reverse what `obfuscateWith` produced.
  A replacement that was not itself an original character was never reversed, an unmatched
  character that happened to be a rule key was dropped from the output entirely rather than kept,
  and a match kept walking the remaining rules so a second one could append again. It also wrote
  the operated character onto the shared rules while reading, carrying state from one position
  into the next. (#95)

DEPRECATED:

- `ObfuscatorExtensions#disentangleImproved(BiMap, String)`: it reverses through `inverse(BiMap)`,
  which tries to clone the rule map first and throws a `NullPointerException` for a map
  implementation it cannot clone. Making the clone optional does not repair it - `inverse` then
  inverts the caller's own rules in place, so every later call with them answers wrongly. Use
  `disentangle`, which has neither limitation.
- CLI command `der2pem`: use `convert`, which detects what the file is and converts in both
  directions.

Version 11.2
-------------

ADDED:

- CLI command family `keystore` for managing PKCS12, JKS and JCEKS key stores: `list` (alias,
  entry kind, algorithm, subject, validity end, SHA-256 fingerprint), `create`, `add-keypair`
  (generates a key pair plus a self-signed certificate; RSA, RSASSA-PSS, EC, DSA and
  ML-DSA-44/65/87, with key-exchange algorithms rejected as certificate signers), `import-cert`
  (PEM and DER), `export-cert` (PEM) and `delete`. Store writes go through a temp file with an
  atomic move so a failed write cannot truncate the store, existing aliases and store files are
  never silently overwritten, and an RSASSA-PSS key is certified with a PSS signature
  (SHA256withRSAandMGF1) per RFC 4055.
- CLI commands `sign` and `verify-signature` for Ed25519, ML-DSA-44/65/87 and every SLH-DSA
  parameter set behind one string-keyed algorithm name: PEM keys, data from a file or standard
  input (`--in -`), raw signature bytes in a file. The exit code of `verify-signature` is the
  contract: 0 valid, 1 invalid, 2 an error before verification.

CHANGED:

- requires crypt-data 11.2 for the newly exported io.github.astrapi69.crypt.data.key package
  (KeyStoreExtensions, CertificateExtensions)
- test quality: 883 tests (up from 754), 99.92% line / 100% branch coverage, PIT mutation score
  99.1% (1064 of 1074 mutants killed); the new CLI classes contribute no surviving mutants

Version 11.0.0
-------------

A major release: the minimum JDK moves from 21 to 25, which is a breaking change for every
consumer still on JDK 21-24, and the library is built against the matching majors of its own
stack, crypt-api 10.0.0 and crypt-data 11.0.0. Everything below that was previously listed under
10.2-SNAPSHOT and 10.5-SNAPSHOT ships here; neither of those was ever released.

ADDED:

- Command-line interface: `java -jar mystic-crypt-11.0.0-all.jar` (the uber-jar, new) runs a
  picocli CLI with the subcommands hash, verify, keygen, kem, cert, checksum, der2pem,
  obfuscate and disentangle. The exit code is the result; stdout is the contract.
- SHA-3 hashing: new class Sha3Hasher (package sha) for SHA3-224/256/384/512 (FIPS 202) via the
  JDK's built-in MessageDigest - no Bouncy Castle involved. API mirrors Blake2bHasher; the variant
  is chosen via the existing crypt-api MessageDigestAlgorithm.SHA3_* constants, and any non-SHA-3
  constant is rejected with IllegalArgumentException. Verified against OpenSSL-generated
  known-answer vectors for all four variants.
- BLAKE2b and BLAKE2s hashing: Blake2bHasher/Blake2sHasher (package sha), with configurable digest
  length and a keyed (MAC) mode. Bouncy Castle-backed.
- bcrypt and scrypt password hashing: BcryptHasher (OpenBSD format, cost 4-31) and ScryptHasher
  (returns salt||derivedKey with a matching verify), both Bouncy Castle-backed, for interop with
  systems that store those formats. Argon2id remains the recommendation for new password storage.
- SRP-6a password-authenticated key exchange (RFC 5054): SRP6aClient, SRP6aServer and
  SRP6aVerifierGenerator (package srp), delegating the group arithmetic to Bouncy Castle's
  SRP6Util and rejecting a zero public value from either peer (RFC 5054 sections 2.5.3/2.5.4).
  Both sides wipe the caller's char[] password and the UTF-8 buffer derived from it.
- Key-committing AEAD: KeyCommittingAeadEncryptor (package aead) binds the ciphertext to exactly
  one key, so a ciphertext cannot decrypt to two different valid plaintexts under two keys
  ("invisible salamanders").
- Feldman verifiable secret sharing: FeldmanVSS (package secret) - Shamir shares plus public
  commitments, so a dealer handing out a bad share is caught by the receiver.
- Hybrid post-quantum key exchange: HybridKemKeyExchange combines X25519 with ML-KEM, so the
  shared secret stays secure as long as either primitive does.
- SecurityProviderSupport.ensureBouncyCastle(), one idempotent registration used by every class
  that needs the Bouncy Castle provider.
- docs/TESTING.md and docs/COVERAGE_EXCEPTIONS.md: the testing strategy, the numbers with the
  commit each was measured on, every surviving mutant with its argument, and the defects the
  process caught. docs/KEY_AGREEMENT_EVOLUTION.md: from book ciphers to the Double Ratchet.

CHANGED:

- Minimum required JDK raised from 21 to 25 (LTS). build.gradle's toolchain resolves off
  gradle.properties#projectSourceCompatibility; CI's setup-java step matches. Published bytecode
  targets JDK 25. BREAKING for consumers on JDK 21-24.
- Built against crypt-api 10.0.0 and crypt-data 11.0.0 (were 9.7 and 10.3).
- module-info: the five modules whose types appear in this module's public API (crypt-api,
  crypt-data, Bouncy Castle provider, Guava, silly-bean) are now "requires transitive", so a
  consumer no longer has to require them itself. New exports: aead, secret, srp, cli.
- Tests: 752; 100% branch coverage, 99.91% line (the two lines are
  System.exit in the CLI main), PIT mutation score 98.5% with every survivor argued in
  docs/COVERAGE_EXCEPTIONS.md. No JaCoCo or PIT exclusions were added to get there.
- Build: zero javac warnings with -Xlint:all (426 before), zero javadoc errors and warnings, and
  javadoc errors fail the build again - the previous failOnError setting wrote into an
  extra-properties map and was never read, so six errors shipped in the published javadoc jar.
  Zero Gradle 10 deprecations: the com.github.hierynomus.license plugin (last release 0.16.1,
  reads Task.project at execution time) is replaced by Spotless's licenseHeaderFile, which also
  turns out to be the first time the header was enforced at all - the old tasks were excluded on
  every build; the nmcp settings plugin is replaced by the per-project plugin (single-project
  build, nothing to aggregate); and tagRelease captures the version at configuration time.
- Publishing: Central Portal publishingType is USER_MANAGED, matching crypt-api and crypt-data - a
  release push uploads and validates, and the version waits for manual approval instead of going
  public the moment validation passes.
- README rewritten: keyword-rich description, six runnable examples (all compiled and executed by
  ReadmeExamplesTest, so a snippet that stops working fails the build), a CLI table and a
  documentation table. Dead oss.sonatype.org links replaced by the Central Portal. Every crypto
  donation address except Monero removed, as was the Flattr button.

FIXED:

- BaseByteArrayEncryptor(SecretKey)/BaseByteArrayDecryptor(SecretKey) were unusable: the
  inherited newAlgorithm() defaulted to the legacy PBE transformation, so every raw AES or
  ChaCha20 key was rejected at construction with "InvalidKeyException: Algorithm requires a PBE
  key" - and the existing test asserted that exception as expected. The key-only constructor now
  picks AES/GCM or ChaCha20-Poly1305 from the key's algorithm; PBE keys keep the PBE path.
- PrivateKeyBruteForceProcessor.resolvePassword never terminated for an unencrypted PKCS#8 key:
  the reader threw PEMException (an IOException) on every attempt, the loop treated that as a
  wrong password and grew the attempt space forever. A key that needs no password is now read
  directly.
- ObfuscatorExtensions.inverseToMap threw NullPointerException for its own declared Character key
  type (it tried to clone an immutable Character). An existing test documented this as
  known-broken instead of failing on it.
- CryptObjectDecoratorExtensions.undecorateWithBytearrayDecorator silently lost content: it
  removed the prefix bytes from anywhere in the content, not just the start ("hello" with prefix
  "he" and suffix "lo" came back as "llo"). Its private startsWith read past the end of an input
  shorter than the prefix (ArrayIndexOutOfBoundsException) and endsWith reported a match when the
  array simply ran out first, so removeFromEnd computed a negative length
  (NegativeArraySizeException) - which the existing test asserted as correct.
- PBEFileEncryptor/PBEFileDecryptor and FileEncryptor/FileDecryptor: the encryptor computed the
  decorated file content and discarded it, so CryptObjectDecorators had no effect on file
  encryption; the decryptor re-read the file per iteration, so only the innermost decorator was
  ever stripped. Both went unnoticed because an encrypt-then-decrypt round trip passes either way.
  Found by a surviving PIT mutant. The tests that had enshrined the old behaviour were corrected.
- SimpleObfuscatorExtensions.disentangle(BiMap, String) now reverses a replacement whenever the
  obfuscated character matches a rule's replaceWith. Previously it also required the replacement
  to itself be an original character, so a normal substitution like a->x was never disentangled;
  shift ciphers happened to work because their replacements are original characters too.
- KeyCommittingAeadEncryptor threw InvalidKeyException on every instantiation (the superclass
  built a PBE cipher at construction time); FeldmanVSS.splitSecret silently split secret+1;
  Blake2bHasher/Blake2sHasher.hashWithKey threw OutputLengthException for any non-default digest
  length; BcryptHasher used the jBCrypt API shape that does not exist on Bouncy Castle and could
  not compile; ScryptHasher.hash discarded its own salt, making the result unverifiable. All
  caught before this release, none ever shipped.
- Argon2id verify(): a zero m/t/p parameter in an encoded hash is rejected as malformed (returns
  false) instead of reaching Bouncy Castle, which threw IllegalArgumentException.
- Restored projectSourceCompatibility to 25 and the curated .gitignore, both of which an automated
  commit had reverted (to JDK 21 and a generic template) after the JDK 25 upgrade.
- Test suite: Argon2SupportTest.verify_answersFalseForATamperedHash was flaky by construction -
  it flipped the last base64 character of the hash, which carries only four significant bits, so
  one run in sixteen the "tampered" hash decoded to the original. A test fixture that was a real
  (throwaway) PKCS#8 private key is now generated at runtime instead of committed.

Version 10.1
-------------

ADDED:

- Argon2id password hashing: PasswordEncryptor#hashPasswordArgon2id(String)/
  matchArgon2id(String, String), storing salt and parameters together with the hash in the
  standard PHC string format. hashPassword(...) (general-purpose, deliberately fast hashing)
  is unchanged and remains available for non-password use cases.
- Ed25519 digital signatures: new classes Ed25519Signer/Ed25519Verifier. Natively supported
  by the JDK since JDK 15, no Bouncy Castle involved.
- X25519 key agreement: new class X25519KeyExchange, deriving a properly-sized shared AES key
  via HKDF from the raw X25519 shared secret (natively supported by the JDK since JDK 11).
  The derived key can be used directly with BaseByteArrayEncryptor/BaseByteArrayDecryptor.
- fixed PasswordEncryptor#match(String, String) using a plain String.equals() comparison
  (not constant-time) instead of MessageDigest.isEqual
- Post-quantum cryptography: MlKemKeyExchange (ML-KEM, FIPS 203 key encapsulation),
  MlDsaSigner/MlDsaVerifier (ML-DSA, FIPS 204 signatures), SlhDsaSigner/SlhDsaVerifier
  (SLH-DSA, FIPS 205 hash-based signatures, all 12 pure parameter sets). All Bouncy
  Castle-backed; require BC registered as a security provider.
- ChaCha20-Poly1305: MysticSymmetricAlgorithm.CHACHA20_POLY1305, wired as a selectable
  authenticated cipher into every class that already supported AES/GCM/NoPadding
  (BaseByteArrayEncryptor/Decryptor, HexableEncryptor/Decryptor, PublicKeyEncryptor/
  PrivateKeyDecryptor). Natively supported by the JDK (SunJCE); requires a 256-bit key.
- PBKDF2-HMAC-SHA256 password hashing: PasswordEncryptor#hashPasswordPbkdf2(String)/
  matchPbkdf2(String, String), 600k iterations by default (OWASP 2023 guidance). Argon2id
  remains the recommended default; this is for interop with systems that require PBKDF2.
- J-PAKE password-authenticated key exchange: new class JpakeKeyExchange, wrapping Bouncy
  Castle's JPAKEParticipant. Unlike the other key-exchange classes here, this is a 3-round
  interactive protocol - see the class Javadoc for a full usage example.
- Key zeroing: Argon2Support/Pbkdf2Support now zero their password char[] argument after use;
  X25519KeyExchange zeroes the raw ECDH shared secret after HKDF derivation.

CHANGED:

- requires crypt-api 9.7 and crypt-data 10.3 (new PQC algorithm constants, KemFactory,
  Pkcs11Factory)
- updated file-worker to 19.0 and pinned jacoco to 0.8.15; fixed module-info.java for
  file-worker's renamed JPMS module (now io.github.astrapisixtynine.file.worker) and updated
  test imports for FileInfo's new package (io.github.astrapi69.file.create.model)
- Ed25519Verifier#verify no longer declares SignatureException: SignatureFactory#verify now
  returns false for malformed/tampered signatures instead of letting the exception escape
- migrated Maven Central publishing to the Central Portal (the legacy oss.sonatype.org
  endpoints this project's pipeline still pointed at were sunset 2025-06-30 and would have
  silently failed on the next release)
- added PIT mutation testing (opt-in, run via `./gradlew pitest`), not wired into check/build
- fixed the dead Maven Central README badge (maven-badges.herokuapp.com is gone)

Version 10.0.0
-------------

This release fixes multiple cryptographic weaknesses in the default configuration of
PBE- and AES-based encryptors: a hardcoded fixed salt, an iteration count of 19, silent
use of AES/ECB with no IV, PBEWithMD5AndDES as the default cipher, and a reversible
"hash" helper that encrypted with a hardcoded, publicly known key. Ciphertext produced
with the previous defaults cannot be decrypted with the new defaults without explicitly
reconstructing the old configuration; see MIGRATION below.

ADDED:

- new class MysticSymmetricAlgorithm providing an AES/GCM/NoPadding Algorithm constant
- AES/GCM/NoPadding support (with a fresh nonce per call) in HexableEncryptor/HexableDecryptor, PublicKeyEncryptor/PrivateKeyDecryptor and BaseByteArrayEncryptor/BaseByteArrayDecryptor
- new explicit symmetricAlgorithm constructor parameter on PrivateKeyDecryptor, PrivateKeyHexDecryptor and PrivateKeyHexStringDecryptor, for reading data encrypted with a non-default symmetric transformation
- new PasswordEncryptor#hashAndHexPassword(String, String, String, HashAlgorithm, Charset) overload requiring an explicit key
- new AbstractCryptorTest, HexableEncryptorTest and coverage for the previously-untested salt/iterationCount/algorithm factory-method branches in AbstractCryptor

CHANGED:

- SECURITY: AbstractCryptor now generates a cryptographically random 8-byte salt and defaults to 65536 PBE iterations when the caller does not supply them, instead of the fixed CompoundAlgorithm.SALT and ITERATIONCOUNT=19; the default PBE algorithm changed from PBEWithMD5AndDES to PBEWITHSHA1AND128BITAES-CBC-BC (Bouncy Castle, now registered as a static security provider)
- SECURITY: HexableEncryptor/HexableDecryptor and PublicKeyEncryptor/PrivateKeyDecryptor now default to AES/GCM/NoPadding with a random per-message nonce instead of bare "AES" (which silently resolved to AES/ECB/PKCS5Padding); the legacy AesAlgorithm.AES transformation remains fully usable via explicit configuration
- SECURITY: fixed PBEFileEncryptor/PBEFileDecryptor silently discarding caller-supplied salt/iterationCount, always falling back to CompoundAlgorithm's hardcoded defaults
- SECURITY: removed Hasher#hashAndHex(String, String, HashAlgorithm, Charset) and PasswordEncryptor#hashAndHexPassword(String, String) / (String, String, HashAlgorithm, Charset), which silently used the hardcoded, publicly known key CompoundAlgorithm.PASSWORD ("privatetopsecret") to reversibly encrypt what was presented as a one-way hash; use PasswordEncryptor#hashPassword(...) for a genuine one-way hash, or the new explicit-key hashAndHexPassword overload
- rewrote PasswordByteEncryptor/PasswordByteDecryptor and PasswordFileEncryptor/PasswordFileDecryptor onto a shared PbeCipherSupport helper, removing duplicated cipher-initialization boilerplate; their constructors no longer eagerly build a cipher, so they no longer swallow checked exceptions internally
- rewrote SimpleEncryptor/SimpleDecryptor as thin delegates to PasswordByteEncryptor/PasswordByteDecryptor, matching the existing PasswordStringEncryptor/PasswordStringDecryptor pattern
- replaced deprecated StringUtils.removeStart/removeEnd with Strings.CS equivalents in CryptObjectDecoratorExtensions
- update of dependency randomizer to the new minor version 10.3

MIGRATION:

- data encrypted under the previous defaults can still be decrypted by explicitly reconstructing the old configuration: for PBE-based classes, build a CryptModel with .salt(CompoundAlgorithm.SALT).iterationCount(CompoundAlgorithm.ITERATIONCOUNT).algorithm(SunJCEAlgorithm.PBEWithMD5AndDES); for HexableEncryptor/HexableDecryptor and PublicKeyEncryptor/PrivateKeyDecryptor, pass AesAlgorithm.AES explicitly (PrivateKeyDecryptor, PrivateKeyHexDecryptor and PrivateKeyHexStringDecryptor now take this as an explicit constructor parameter). Re-encrypt under the new defaults for storage going forward.

Version 9.1
-------------

ADDED:

- new module-info.java file for modularization
- new libs.versions.toml file for new automatic catalog versions update
- new test dependency org.junit.jupiter:junit-jupiter in version 5.11.0-M2
- new verifier class KeystoreVerifier that checks if a given Keystore file is valid

CHANGED:

- remove of test dependency testng
- update gradle to new version 8.9
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 7.0.0.BETA1
- update of dependency commons-codec to the new patch version 1.17.1
- update of dependency commons-lang3 dependency version to 3.15.0
- update of dependency commons-io dependency version to 2.16.1
- update of dependency crypt-api to the new minor version 9.3
- update of dependency crypt-data to the new minor version 9.5
- update of dependency file-worker to new version to 17.3
- update of dependency xml-base to new version to 2
- update of dependency guava version to new version 33.2.1-jre
- update of dependency silly-collection to new version to 27.1
- update of dependency silly-strings to new minor version 9.1
- update of dependency throwable to new major version 3
- update of test dependency silly-io to new version 3.1
- remove of test dependency testng
- migrate from testng to new junit-jupiter
- javadoc extended
- replaced obsolete package.html with package-info.java files
- replace obsolete dependency jobj-clone with new dependency jobj-cloner
- removed all deprecated calls

Version 9
-------------

ADDED:

- new class PublicKeyStringEncryptor that can encrypt strings with the given public key
- new class PublicKeyHexStringEncryptor that can encrypt and hex characters with the given public key
- new class PrivateKeyStringDecryptor that decrypts encrypted strings the was encrypted with the corresponding public key
- new class PrivateKeyHexStringDecryptor that decrypts encrypted hex strings the was encrypted with the corresponding public key

CHANGED:

- update jdk to version 17
- update gradle to new version 8.7
- update of gradle-plugin dependency 'com.github.ben-manes.versions.gradle.plugin' to new version 0.51.0
- update of gradle-plugin dependency 'org.ajoberstar.grgit:grgit-gradle' to new version 5.2.2
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 6.25.0
- update of crypt-api dependency to the new major version 9
- update of crypt-data dependency to the new major version 9
- update of dependency commons-codec dependency version to 1.16.1
- update of dependency commons-io dependency version to 2.16.0
- update of dependency commons-lang3 dependency version to 3.14.0
- update of dependency randomizer to new version 10.2
- update of dependency file-worker to new version to 17.1
- update of dependency silly-collection to new version to 27
- update of dependency jobj-core to new version 8.2
- update of dependency guava version to new version 33.1.0-jre
- update of dependency silly-strings to new major version 9
- update of test dependency json-extensions to new version 3
- update of test dependency checksum-up to new version 3
- update of test dependency test-object to new version 8.2
- update of test dependency silly-io to new version 3
- update of test dependency 'com.github.meanbeanlib:meanbean' to new version 3.0.0-M9
- update of test dependency testng to new version to 7.9.0

Version 8.1
-------------

ADDED:

- new constructor to SharedSecretEncryptor with corresponding model
- new constructor to SharedSecretDecryptor with corresponding model

CHANGED:

- update gradle to new version 8.2.1
- update of gradle-plugin dependency 'com.github.ben-manes.versions.gradle.plugin' to new version 0.47.0
- update of gradle-plugin dependency 'org.ajoberstar.grgit:grgit-gradle' to new version 5.2.0
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 6.19.0
- update of crypt-api dependency version to 8.6
- update of crypt-data dependency version to 8.5
- update of dependency commons-codec dependency version to 2.13.0
- update of dependency commons-io dependency version to 1.16.0
- update of dependency guava version to new version 32.1.1-jre
- update of dependency randomizer to new version 9
- update of dependency file-worker to new version to 11.6
- update of dependency silly-collection to new version to 21
- update of dependency jobj-core to new version 7.1
- update of dependency guava version to new version 32.0.1-jre
- update of test dependency json-extensions to new version 2.4
- update of test dependency checksum-up to new version 2.2
- update of test dependency test-object to new version 7.2
- update of test dependency silly-io to new version 2.2
- update of test dependency testng to new version to 7.8.0

Version 8
-------------

CHANGED:

- update to jdk version 11
- rename of main package from 'io.github.astrapi69.crypto.*' to new 'io.github.astrapi69.mystic.crypt.*'
- update gradle to new version 7.5.1
- update of gradle-plugin dependency 'com.diffplug.spotless:spotless-plugin-gradle' to new minor version 6.10.0
- update of crypt-api dependency version to 8.3
- update of crypt-data dependency version to 8.1
- update of dependency file-worker to new version to 11.1
- update of dependency silly-collection to new version to 20
- update of test dependency test-object to new version 7.1
- update of test dependency jobj-core to new version 6.1
- update of test dependency checksum-up to new version 2.1

Version 7.11
-------------

ADDED:

- new constructor with private key in class PrivateKeyDecryptor
- new constructor with private key in class PrivateKeyGenericDecryptor
- new constructor with public key in class PublicKeyEncryptor
- new constructor with public key in class PublicKeyGenericEncryptor

CHANGED:

- update gradle to new version 7.4
- update of dependency randomizer to new version 8.5
- refactored class PublicKeyHexEncryptor and PrivateKeyHexDecryptor and removed deprecated status

Version 7.10
-------------

ADDED:

- new workflow for build repository with github action 'Java CI with Gradle'
- new gradle-plugin dependency of 'com.diffplug.spotless:spotless-plugin-gradle' for format source code
- new gradle-plugin dependency of 'org.ajoberstar.grgit:grgit-gradle' for create git release tags

CHANGED:

- update gradle to new version 7.3.3
- update gradle-plugin dependency of com.github.ben-manes.versions.gradle.plugin to new version 0.42.0
- update of crypt-api dependency version to 7.7
- update of crypt-data dependency version to 7.11.1
- update of dependency jobj-core to new version 5.3
- update of dependency bouncycastle to new version 1.70
- update of test dependency test-objects to new version 5.7
- update of test dependency silly-io to new version 1.7
- update of test dependency testng to new version to 7.5

Version 7.9
-------------

ADDED:

- new encryptor class CharacterSetEncryptor that can encrypt string objects with the character set key
- new decryptor class CharacterSetDecryptor that can decrypt integer list with the character set key algorithm
- new dependency silly-strings in new version 8.1
- improve gradle build performance by adding new gradle parameters for caching, parallel, configure on demand and file
  watch

CHANGED:

- update gradle to new version 7.3
- update of crypt-api dependency version to 7.6.1
- update of crypt-data dependency version to 7.9
- update of dependency file-worker to new version 8.1

Version 7.8
-------------

ADDED:

- new encryptor class OneTimePadEncryptor that can encrypt byte array with the one time pad algorithm
- new decryptor class OneTimePadDecryptor that can decrypt byte array with the one time pad algorithm
- new generic encryptor class PublicKeyGenericEncryptor that can encrypt serializable objects
- new generic decryptor class PrivateKeyGenericDecryptor that can decrypt the byte array back to the serializable object
- new encryptor class BaseByteArrayEncryptor that can encrypt byte array
- new decryptor class BaseByteArrayDecryptor that can decrypt byte array
- new test dependency json-extensions in version 1.1
- new field in class PBEFileEncryptor for set a custom file extension for the encrypted file
- new flag field in class PBEFileEncryptor if true the given file that will be given for encryption will be deleted
- new field in class PBEFileDecryptor for set a custom file extension for the decrypted file
- new flag field in class PBEFileDecryptor if true the given encrypted file that will be given for decryption will be deleted

CHANGED:

- update gradle to new version 7.1
- changed all dependencies from groupid de.alpharogroup to new groupid io.github.astrapi69
- update gradle-plugin dependency of gradle.plugin.com.hierynomus.gradle.plugins:license-gradle-plugin to new version 0.16.1
- update of dependency randomizer version to 8.3
- update of dependency file-worker to new version 5.9
- update of dependency jobj-core to new version 3.9
- update of dependency crypt-data to new version 7.7
- update of test dependency test-objects to new version 5.5
- update of dependency commons-io to new version 2.11.0
- removed unused test dependency xml-extensions

Version 7.7
-------------

ADDED:

- new encryptor classes that can encrypt byte arrays with a password and the counterpart of it the decryptor
- new encryptor classes that can encrypt String object with a password and the counterpart of it the decryptor
- new encryptor classes that can encrypt File object with a password and the counterpart of it the decryptor

CHANGED:

- update of crypt-api dependency version to 7.5
- update of crypt-data dependency version to 7.6
- update of dependency commons-io dependency version to 2.10.0

Version 7.6
-------------

ADDED:

- new dependency guava in version 30.1.1-jre
- new methods created for most common operations on a keystore object in class KeyStoreExtensions
- new dependency commons-io in version 2.9.0
- new dependency commons-lang3 in version 3.12.0
- new dependency silly-beans in version 1.1

CHANGED:

- update of gradle version to 6.9
- changed to new package io.github.astrapi69
- update of file-worker dependency version to 5.7
- update of crypt-api dependency version to 7.4
- update of crypt-data dependency version to 7.5
- update of checksum-up dependency to version 1.2
- update of bouncycastle dependency version to 1.69
- update of xml-extensions test dependency version to 7.1
- update of testng test dependency version to 7.4.0
- update of test-objects test dependency version to 5.4
- update of com.github.ben-manes.versions.gradle.plugin to new version 0.39.0

Version 7.5
-------------

ADDED:

- new class DigitalSignaturesExtensions that signs and verify byte arrays with MessageDigest
- new class SignatureExtensions that signs and verify byte arrays with Signature
- new class KeyStoreExtensions for handle issues with keyStore objects
- new area 'gradle-plugins versions' for hold the versions of the gradle plugins in gradle.properties
- new jar task for build manifest file

CHANGED:

- update of gradle version to 6.7
- update of commons-codec version to 1.15
- update of silly-collections version to 8.4
- update of bouncycastle version to 1.66
- update of jobj-core version to 3.6
- update of randomizer version to 8
- update of testng test dependency version to 7.3.0
- update of checksum-up test dependency version to 1.1
- update of com.github.ben-manes.versions.gradle.plugin to new version 0.34.0
- extracted project gradle plugin versions to gradle.properties

Version 7.4
-------------

CHANGED:

- removed all lombok dependent imports
- update of silly-collections version to 8
- update of randomizer version to 6.8
- update of file-worker dependency version to 5.5
- update of jobj-core version to 3.5
- update of testng test dependency version to 7.1.1
- removed of junit test dependency
- removed of mockito-core test dependency

Version 7.3
-------------

ADDED:

- new idea run configurations for gradle builds created

CHANGED:

- update of silly-collections version to 5.8
- update of randomizer version to 6.4
- update of file-worker dependency version to 5.4
- update of xml-extensions version to 7.1
- update of testng test dependency version to 7.1.0
- update of junit test dependency version to 4.13-rc-2
- update of mockito-core test dependency version to 3.2.0
- moved xml specific classes to project xml-extensions

Version 7.2
-------------

ADDED:

- new encryption and decryption strings with character set over indexes
- new classes created for create checksums for files, serializable and string objects

Version 7.1.2
-------------

CHANGED:

- update of build.gradle and changed from explicit project name with property reference

Version 7.1.1
-------------

CHANGED:

- update of silly-collections version to 5.4
- update of jobj-core version to 3.3
- removed maven related files and directories
- added new gradle plugins for migration of the maven plugins like license update, publish and version check

Version 7.1
-------------

ADDED:

- gradle as build system
- new encryptor class created for encrypting java object in a generic way
- new decryptor class created for decrypt an encrypted {@link File} object that was previously encrypted and return the decrypted result as generic java object
- feature request for decorating crypt objects initial version implemented

CHANGED:

- update of commons-codec version to 1.13
- update of dependency crypt-api version to 7.2
- update of dependency crypt-data version to 7.2
- update of bouncycastle version to 1.64
- update of randomizer version to 6.3
- update of xml-extensions version to 6.2.1

Version 7
-------------

CHANGED:

- removed depracated class CryptConst
- changed from modules to simple project
- moved crypt-api to own project
- moved crypt-data to own project
- moved crypt-core to the top of this project so crypt-core is now mystic-crypt
- new method in the utility class Hasher with private key parameter created

Version 6
-------------

ADDED:

- new dependency jobj-core in version 3.2.1 added
- new dependency jaxb-api in version 2.3.1 added
- new dependency jobj-contract-verifier in version 3.2 added

CHANGED:

- update of parent version to 5.2
- constant class CryptConst tags as deprecated, will be removed in next minor release
- update of guava version to 27.1-jre
- update of commons-codec version to 1.12
- update of bouncycastle version to 1.62
- update of file-worker version to 5.2
- update of jcommons-lang version to 5.2.2
- update of test-objects version to 5.2
- update of silly-collections version to 5.2.1
- update of randomizer version to 6.1
- update of commons-codec version to 1.12
- change provider of code coverage to codecov.io

Version 5.8
-------------

CHANGED:

- update of parent version to 4.6
- update of file-worker version to 5.1
- update of jcommons-lang version to 5.1.1
- update of test-objects version to 5.0.1
- update of silly-collections version to 5.1

Version 5.7
-------------

CHANGED:

- update of parent version to 4.5
- update of file-worker version to 5.0.1
- update of jcommons-lang version to 5.1
- update of silly-collections version to 5
- update of randomizer version to 5.6
- update of guava version to 27.0.1-jre

Version 5.6
-------------

ADDED:

- new enum value NEGATECASE in Operation class that indicates to negate the case of the given character value
- new blockchain classes created for Block, Address and Transaction
- new extension created class for simple obfuscation
- new hash methods created for hash blocks in a blockchain and calculate the merkle root hash
- new obfuscation test data for unit test
- new lombok.config files added to projects

CHANGED:

- moved obfuscation classes to appropriate packages
- update of silly-collections version to 4.34.1
- unit tests extended for improve code coverage
- simple obfuscation implementation improved

Version 5.5
-------------

ADDED:

- new methods for encode and decode string objects in HexExtensions class created
- new enum created that holds union words for chaining algorithms

CHANGED:

- update of parent version to 4.1
- update of file-worker version to 4.23
- update of jcommons-lang version to 4.35
- update of resourcebundle-inspector version to 3
- update of guava version to 26.0-jre

Version 5.4
-------------

ADDED:

- new unit tests created

CHANGED:

- deleted deprecated class
- deleted unit test class deprecated class
- cleaned up of exclude classes in code coverage maven plugin

Version 5.3
-------------

CHANGED:

- javadoc improved and extended
- deleted deprecated methods and classes
- unit tests extended for improve code coverage

Version 5.2
-------------

CHANGED:

- moved auth relevant projects to own [project](https://github.com/astrapi69/auth)
- update of parent version to 4
- removed unneeded .0 at the end of version
- update of file-worker version to 4.22
- update of jcommons-lang version to 4.34
- update of test-objects version to 4.28
- update of silly-collections version to 4.33
- update of jobject-extensions version to 1.12
- update of resourcebundle-inspector version to 2.22
- update of randomizer version to 5.4
- update of bouncycastle version to 1.60
- update of guava version to 25.1-jre
- unit tests extended for improve code coverage

Version 5.1.0
-------------

ADDED:

- moved all left intefaces to the api projects
- moved all enums to the api projects
- provide new package.html for the javadoc of new packages

CHANGED:

- moved random relevant projects to own [project](https://github.com/astrapi69/randomizer)
- update of dependency version of silly-collections
- update of dependency version of jcommons-lang
- update of dependency version of file-worker
- update of dependency version of resourcebundle-inspector
- update of dependency version of jobject-extensions
- unit tests extended for improve code coverage


Version 5.0.0
-------------

ADDED:

- this changelog file
- protect and encrypt private key with password
- write protected private key with password to a file
- paypal button as markdown added
- new classes that declares simple and complex rules for obfuscation of characters
- moved intefaces to new api projects
- added new meanbean dependency for better unit testing of beans
- provide package.html for the javadoc of packages

CHANGED:

- interfaces moved to api projects
- moved several classes to appropriate named packages
- javadoc improved and extended
- deleted deprecated classes
- en- and decryption of file extended
- refactoring: moved classes to appropriate package
- Obfuscation classes uses now guava BiMap

Version 4.24.0
-------------

ADDED:

- new eclipse launch scripts created
- created PULL_REQUEST_TEMPLATE.md file
- created CODE_OF_CONDUCT.md file
- created CONTRIBUTING.md file
- created GoogleMapsUrlSigner class that is a possible solution to that [issue](https://github.com/astrapi69/mystic-crypt/issues/6)
- created new intefaces of blockchain domain
- added guava dependency

CHANGED:

- refactoring of several classes
- update of parent version
- update of dependency version of silly-collections
- update of dependency version of jcommons-lang
- update of dependency version of file-worker
- update of dependency version of test-objects
- sorted pom.xml's

Version 4.23.0
-------------

ADDED:

- new eclipse launch scripts created

CHANGED:

- update of dependency version of silly-collections
- update of dependency version of jcommons-lang
- update of parent version
- update of dependency version of file-worker

Version 4.22.0
-------------

ADDED:

- created new CertificateExtensions, HashExtensions class
- added new reader method for der files
- javadoc image in the READE.md added with a reference to the online javadoc site
- mvn depencencies diagramm image added in the READE.md

CHANGED:

- extended reader and writer methods
- unit tests improved and extended
- javadoc improved and extended
- update of parent version

Version 4.21.0
-------------

ADDED:

- added jsr305 dependency
- new method in CertFactory for create a x509 cert v1
- created new unit tests
- code coverage added
- created new SecureRandomBuilder, CertificateReader and CertificateWriter classes

CHANGED:

- unit tests improved
- javadoc improved and extended

Version 4.20.0
-------------

ADDED:

- created new model class SignInWithRedirectionModel with redirection

CHANGED:

- moved mystic-crypt-ui project to own repository

Version 4.19.0
-------------

ADDED:

- initial version of a obfuscate demo

Version 4.18.0
-------------

ADDED:

- created panels for the demo app
- new enum KeySize created that holds the bit size for private keys
- new class EnableButtonBehavior created for demo project
- create new CipherTypes.dat file that contain ciphers
- generate key pair keys with gui for demo project

CHANGED:

- gui examples extended in the demo project

Version 4.17.0
-------------

ADDED:

- new project mystic-crypt-ui for demos created
- created readers and writers for public and private keys
- new method for resolve the public key from a private key
- new abstract classes for encrypt and decrypt

CHANGED:

- update of license headers
- refactoring: moved several classes to appropriate packages
- optimized factory for cipher creation

Version 4.16.0
-------------

ADDED:

- chainable encryptor and decryptor created
- created new project crypt-data

CHANGED:

- moved all algorithms and enums to the new project crypt-data

Version 4.15.0
-------------

ADDED:

- new classes for encryption and decryption with public and private keys
  that take byte arrays as arguments in the encryption and decryption process
- new class for build a SecureRandom object
- new factory for Certificate object creation
- new inteface Cryptor created for define the operation mode
- new factory class for KeyStore object

CHANGED:

- javadoc extended and improved
- rename of interfaces from encryptor and decryptor
- extended crypt model and adapted related classes
- update of documentation in README.md file

Version 4.14.0
-------------

ADDED:

- new encryptor and decryptor classes for base64 pem files created
- new enum for modes, paddings created
- created new crypt model and extracted all relevant data to the crypt model

CHANGED:

- update of several dependencies versions
- renamed GenericCryptor to AbstractCryptor
- update the abstract cryptor to the new crypt model
- unit tests improved
- javadoc extended and improved

Version 4.13.0
-------------

CHANGED:

- update of several dependencies versions

Version 4.12.0
-------------

ADDED:

- new exception for security created

Version 4.11.0
-------------

ADDED:

- new method for create a random token

CHANGED:

- update of license header from all files

Version 4.10.0
-------------

ADDED:

- create new top25pw.txt for unit tests with WordlistProcessorTest
- create KeyPairAlgorithm class
- create new enum for mac algorithms
- create new interface generators for random data

CHANGED:

- update of Algorithm interface and RandomExtensions class


Version 4.9.0
-------------

ADDED:

- new class Credentials created

CHANGED:

- documentation of README.md file improved and extended
- update of several dependencies versions

Version 4.8.0
-------------

ADDED:

- using git-flow for new releases
- added license header to all files
- new AuthenticationResult class created for authentication

CHANGED:

- documentation of README.md file improved and extended
- javadoc improved and extended

Version 4.7.0
-------------

ADDED:

- New factory classes and new abstract classes for en and decrypting

CHANGED:

- resourcebundle-inspector version upgrade to 2.7.0


Version 4.6.0
-------------

ADDED:

- created new abstract cryptor class with callback methods

CHANGED:

- update of parent version

...

Version 4.2.0
-------------

CHANGED:

- rename of classes to a more appropriate name
- javadoc improved and extended

Version 4.1.0
-------------

CHANGED:

- javadoc improved and extended
- renamed util classes
- deleted depracated classes

Version 4.0.0
-------------

ADDED:

- moved project jaulp.security to mystic-crypt and rename it to auth-security
- created a simple wordlist processor that was requested from an issue

CHANGED:

- new major version 4.0.0 and using new jdk version 8
- altered .travis.yml email address
- update of lombok version to 1.16.6

Version 3.12.0
-------------

ADDED:

- created new maven profile for deploy on sonatype

CHANGED:

- maven-compiler-plugin.version updated to 3.3
- maven-javadoc-plugin.version updated to 2.10.3
- nexus-staging-maven-plugin version updated to version 1.6.5
- Refactoring from method parameters and made method parameters final

Version 3.11.0
-------------

ADDED:

- added flattr image for donations
- added .travis.yml file and build-status image
- moved jaulp.random project as new module project randomizer in parent project mystic-crypt

CHANGED:

- update of lombok version to 1.16.4
- javadoc extended and improved

Version 3.10.0
-------------

ADDED:

- initial version of mystic-crypt
- moved from project jaulp.core
- adoption of version from jaulp.core

CHANGED:

- javadoc extended and improved

-------------

Notable links:
[keep a changelog](http://keepachangelog.com/en/1.0.0/) Don’t let your friends dump git logs into changelogs
