# mystic-crypt

**A modern Java cryptography library: symmetric and public-key encryption, password hashing,
digital signatures, key agreement and post-quantum cryptography — with an API you can use
correctly without being a cryptographer.**

<div style="text-align: center">

[![Java CI with Gradle](https://github.com/astrapi69/mystic-crypt/actions/workflows/gradle.yml/badge.svg)](https://github.com/astrapi69/mystic-crypt/actions/workflows/gradle.yml)
[![Coverage Status](https://codecov.io/gh/astrapi69/mystic-crypt/branch/develop/graph/badge.svg)](https://codecov.io/gh/astrapi69/mystic-crypt)
[![Mutation Coverage](https://img.shields.io/badge/mutation%20coverage-96%25-brightgreen)](https://pitest.org/)
[![Open Issues](https://img.shields.io/github/issues/astrapi69/mystic-crypt.svg?style=flat)](https://github.com/astrapi69/mystic-crypt/issues)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.astrapi69/mystic-crypt.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.astrapi69/mystic-crypt)
[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](http://opensource.org/licenses/MIT)
[![Javadoc](http://www.javadoc.io/badge/io.github.astrapi69/mystic-crypt.svg)](http://www.javadoc.io/doc/io.github.astrapi69/mystic-crypt)
[![Java](https://img.shields.io/badge/Java-25-orange)](https://openjdk.org/projects/jdk/25/)

</div>

mystic-crypt wraps the JDK's and Bouncy Castle's cryptographic primitives in small, focused classes
with safe defaults: authenticated encryption (AES-GCM, ChaCha20-Poly1305) with a fresh nonce per
call, memory-hard password hashing (Argon2id), modern elliptic-curve signatures and key agreement
(Ed25519, X25519), and the NIST post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA). You pick the
operation; the library picks parameters that are not a footgun.

- 📖 [Capability matrix](docs/CRYPTO_CAPABILITIES.md) — every algorithm, where it lives, and what is deliberately out of scope
- 🧪 [Testing strategy](docs/TESTING.md) — how it is tested, the coverage and mutation numbers, and the bugs that process found
- 🎓 [Key agreement, explained](docs/KEY_AGREEMENT_EVOLUTION.md) — from book ciphers to the Double Ratchet
- 🖥️ [Desktop GUI](https://github.com/astrapi69/mystic-crypt-ui) — the same library behind a Swing front end

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Features](#features)
- [Command-line interface](#command-line-interface)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [Similar projects](#similar-projects)

## Requirements

**JDK 25 or newer**, at build and at runtime — the published jar targets JDK 25 bytecode and will
not load on an older JVM. That baseline lets the library use JDK-native cryptography (Ed25519 since
JDK 15, X25519 since JDK 11, the `javax.crypto.KEM` API behind the post-quantum classes since
JDK 21) instead of carrying Bouncy Castle fallbacks for what the JDK already provides.

## Installation

Replace `${latestVersion}` with the current release:
[![Maven Central](https://img.shields.io/maven-central/v/io.github.astrapi69/mystic-crypt.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.astrapi69/mystic-crypt)

**Gradle** (version catalog, `gradle/libs.versions.toml`):

```toml
[versions]
mystic-crypt-version = "${latestVersion}"

[libraries]
mystic-crypt = { module = "io.github.astrapi69:mystic-crypt", version.ref = "mystic-crypt-version" }
```

```groovy
dependencies {
    implementation libs.mystic.crypt
}
```

**Gradle** (plain):

```groovy
dependencies {
    implementation "io.github.astrapi69:mystic-crypt:${latestVersion}"
}
```

**Maven**:

```xml
<dependency>
    <groupId>io.github.astrapi69</groupId>
    <artifactId>mystic-crypt</artifactId>
    <version>${latestVersion}</version>
</dependency>
```

## Quick start

Every snippet below is compiled and executed by
[`ReadmeExamplesTest`](src/test/java/io/github/astrapi69/mystic/crypt/ReadmeExamplesTest.java) —
if it is in this README, it runs.

### Encrypt and decrypt data

AES-256-GCM with a fresh random nonce per call, prepended to the ciphertext:

```java
SecretKey key = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 256);

byte[] encrypted = new BaseByteArrayEncryptor(key)
    .encrypt("attack at dawn".getBytes(StandardCharsets.UTF_8));
byte[] decrypted = new BaseByteArrayDecryptor(key).decrypt(encrypted);
```

### Store a password

Argon2id with a random salt; the salt and all parameters travel inside the returned string, so
there is no second column to manage:

```java
PasswordEncryptor passwordEncryptor = PasswordEncryptor.getInstance();

String stored = passwordEncryptor.hashPasswordArgon2id("correct horse battery staple");

boolean ok = passwordEncryptor.matchArgon2id("correct horse battery staple", stored);
```

### Sign and verify

```java
KeyPair keyPair = Ed25519Signer.newKeyPair();
byte[] document = "release 11.0.0".getBytes(StandardCharsets.UTF_8);

byte[] signature = new Ed25519Signer(keyPair.getPrivate()).sign(document);

boolean valid = new Ed25519Verifier(keyPair.getPublic()).verify(document, signature);
```

### Agree on a shared key

X25519 Diffie-Hellman, with the raw shared secret run through HKDF rather than used directly:

```java
KeyPair alice = X25519KeyExchange.newKeyPair();
KeyPair bob = X25519KeyExchange.newKeyPair();

SecretKey aliceSecret = X25519KeyExchange.deriveSharedSecret(alice.getPrivate(), bob.getPublic(), 32);
SecretKey bobSecret = X25519KeyExchange.deriveSharedSecret(bob.getPrivate(), alice.getPublic(), 32);
// aliceSecret and bobSecret are equal
```

### Post-quantum key encapsulation

ML-KEM (FIPS 203). See also `HybridKemKeyExchange` for the X25519+ML-KEM combiner, which stays
secure as long as *either* half is unbroken:

```java
KeyPair recipient = MlKemKeyExchange.newKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);

MlKemKeyExchange.Encapsulation sent =
    MlKemKeyExchange.encapsulate(recipient.getPublic(), KeyPairGeneratorAlgorithm.ML_KEM_768);
SecretKey received = MlKemKeyExchange.decapsulate(recipient.getPrivate(),
    sent.getCiphertext(), KeyPairGeneratorAlgorithm.ML_KEM_768);
// sent.getSharedSecret() and received are equal
```

### Hash

```java
byte[] digest = Sha3Hasher.hashUtf8("hello", MessageDigestAlgorithm.SHA3_256);
```

## Features

**Symmetric encryption** — AES-GCM and ChaCha20-Poly1305 authenticated encryption with a fresh
nonce per call, for byte arrays, strings, files, streams and serializable objects; chainable
encryptors; hex-encoded variants; key-committing AEAD against the "invisible salamanders" attack.

**Password hashing** — Argon2id (recommended), PBKDF2-HMAC-SHA256, bcrypt and scrypt for interop.
Salt and parameters are encoded with the hash; comparisons are constant-time.

**Public-key cryptography** — RSA hybrid encryption (RSA wraps an AES key rather than the data),
Ed25519 signatures, X25519 key agreement with HKDF derivation, reading and writing PEM/DER/PKCS#8
keys generated by OpenSSL or Java, X.509 certificate generation, keystore handling.

**Post-quantum** — ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and a hybrid
X25519+ML-KEM combiner for the transition period.

**Hashing** — SHA-2, SHA-3, BLAKE2b/BLAKE2s including keyed (MAC) mode, file and object checksums.

**Secret sharing and PAKE** — Shamir's Secret Sharing, Feldman verifiable secret sharing, J-PAKE
and SRP-6a password-authenticated key exchange, AES key wrap, PKCS#11/HSM provider configuration.

**Utilities** — text obfuscation with rule maps, brute-force and wordlist processors for password
recovery, Google Maps URL signing.

The [capability matrix](docs/CRYPTO_CAPABILITIES.md) lists every one of these with the classes
involved — and, just as importantly, what is deliberately *not* implemented and why.

## Command-line interface

The published `-all` artifact is a runnable uber-jar:

```shell
java -jar mystic-crypt-${latestVersion}-all.jar --help
```

| Command | Description |
|---|---|
| `hash` | Hash a password with Argon2id or PBKDF2 and print the encoded hash |
| `verify` | Verify a password against an encoded hash (exit code 0 = match) |
| `keygen` | Generate a key pair and print or write it as PEM |
| `kem` | Run an ML-KEM or hybrid X25519+ML-KEM encapsulation between two parties |
| `checksum` | Compute the checksum of a file |
| `der2pem` | Convert a DER-encoded private key to PEM |
| `cert` | Create a self-signed X.509 certificate |
| `obfuscate` / `disentangle` | Obfuscate text with a substitution map, and recover it |

```shell
java -jar mystic-crypt-${latestVersion}-all.jar hash --password "correct horse battery staple"
java -jar mystic-crypt-${latestVersion}-all.jar checksum --file build.gradle --algorithm SHA-256
```

## Documentation

| Document | What it covers |
|---|---|
| [docs/CRYPTO_CAPABILITIES.md](docs/CRYPTO_CAPABILITIES.md) | Capability matrix: every algorithm, its class, and what is out of scope with reasons |
| [docs/TESTING.md](docs/TESTING.md) | Testing strategy, coverage and mutation numbers, and the defects the process caught |
| [docs/COVERAGE_EXCEPTIONS.md](docs/COVERAGE_EXCEPTIONS.md) | Every uncovered line and surviving mutant, with its reason |
| [docs/KEY_AGREEMENT_EVOLUTION.md](docs/KEY_AGREEMENT_EVOLUTION.md) | How key agreement got from book ciphers to the Double Ratchet |
| [Wiki](https://github.com/astrapi69/mystic-crypt/wiki) | Task-oriented guides |
| [Javadoc](http://www.javadoc.io/doc/io.github.astrapi69/mystic-crypt) | API reference |

This library is the top of a three-repository stack:
[crypt-api](https://github.com/astrapi69/crypt-api) (algorithm constants and interfaces) →
[crypt-data](https://github.com/astrapi69/crypt-data) (factories, readers/writers, models) →
**mystic-crypt** (the ready-to-use encryptors).

## Contributing

Pull requests are welcome — fork [astrapi69/mystic-crypt](https://github.com/astrapi69/mystic-crypt/fork)
and [open a PR](https://github.com/astrapi69/mystic-crypt/pull/new/develop) against `develop`.

Please add tests for your change. This library sits at 99% line and 98% branch coverage with a 96%
PIT mutation score; the [conventions for contributors](docs/TESTING.md#conventions-for-contributors)
describe what a good test looks like here — parameterized with records, a property assertion plus
the matching negative case, and never lowering those numbers.

```shell
./gradlew build            # tests + coverage + formatting check
./gradlew spotlessApply    # fix formatting
./gradlew pitest           # mutation testing (opt-in, minutes)
```

Versions follow [Semantic Versioning](https://semver.org): `<major>.<minor>.<patch>`.

Questions, bug reports and feature requests belong on the
[issues page](https://github.com/astrapi69/mystic-crypt/issues).

## Similar projects

- [Tink](https://github.com/tink-crypto/tink) — Google's misuse-resistant cryptography library
- [cryptacular](https://github.com/vt-middleware/cryptacular) — a friendly complement to the Bouncy Castle API
- [jasypt](http://www.jasypt.org/) — Java simplified encryption
- [Encryptor4j](https://github.com/martinwithaar/Encryptor4j) — strong encryption for Java, simplified
- [CogniCrypt](https://github.com/eclipse-cognicrypt/CogniCrypt) — Eclipse plugin that helps developers use Java crypto APIs correctly
- [curve25519](https://github.com/signalapp/curve25519-java) — Signal's Curve25519 implementation
- [Apache Shiro](https://github.com/apache/shiro) — security framework with authentication, authorization and cryptography
- [vault](https://github.com/hashicorp/vault) — secrets management and encryption as a service

## License

MIT — see [LICENSE](LICENSE).

## Support this project

If mystic-crypt is useful to you, a ⭐ on
[GitHub](https://github.com/astrapi69/mystic-crypt) helps others find it. Sharing it or reporting a
bug helps just as much.

If you would like to contribute financially:

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=GVBTWLRAZ7HB8" target="_blank">
<img src="https://www.paypalobjects.com/en_US/GB/i/btn/btn_donateCC_LG.gif" alt="Donate via PayPal" title="PayPal - The safer, easier way to pay online!" style="border: none" />
</a>

or Monero (XMR):

```
49bqeRQ7Bf49oJFVC72pqpe5hFbb62pfXDYPdLsadGGF81KZW2ZfrPZ8PbAVu5X2v1TYAspeczMya3cYQysNS4usRRPQHVw
```

<img src="https://raw.githubusercontent.com/astrapi69/jgeohash/master/src/main/resources/img/49bqeRQ7Bf49oJFVC72pqpe5hFbb62pfXDYPdLsadGGF81KZW2ZfrPZ8PbAVu5X2v1TYAspeczMya3cYQysNS4usRRPQHVw.png"
alt="Monero donation wallet QR code" width="250"/>

## Credits

| | |
|---|---|
| [Maven Central](https://central.sonatype.com/artifact/io.github.astrapi69/mystic-crypt) | for hosting the artifacts of this open source project |
| [codecov.io](https://codecov.io) | for free code coverage reporting |
| [javadoc.io](http://www.javadoc.io) | for free javadoc hosting |
| [PIT](https://pitest.org/) | for mutation testing |

No animals were harmed in the making of this library.
