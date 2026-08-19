# Cryptographic capabilities

A capability matrix mapping general cryptographic concepts to what is actually implemented
across the `mystic-crypt` / `crypt-data` / `crypt-api` library family, verified directly
against source (not inferred from naming). Intended as a reference for deciding "do we
already have this, and where" before adding something new.

Status key:

- ✅ **Implemented** — a real, wired implementation exists (class + call sites), not just a
  name.
- ⚠️ **Partial** — an algorithm name/constant exists (usually in `crypt-api`), but nothing in
  `mystic-crypt`/`crypt-data` actually calls it. Adding real support means wiring the
  constant into a factory/encryptor, not just defining it.
- ❌ **Not present** — no trace anywhere in the three repos.
- 🚫 **Out of scope** — deliberately not a fit for this library. These are protocol-level,
  infrastructure-level, or hardware-level concerns; a data/key-encryption utility library is
  the wrong layer to implement them in. Reasoning given per item.

Last verified: 2026-08-19, against `mystic-crypt` 10.1-SNAPSHOT, `crypt-data` 10.3-SNAPSHOT
(10.2 released), `crypt-api` 9.7-SNAPSHOT (9.6 released). The capability tables below are current
as of this date; the mutation-coverage numbers in the section further down predate this round's
PQC/J-PAKE/PKCS#11 additions and will read a little low until the next `./gradlew pitest` run
picks up their tests.

---

## Part 1: Fundamentals

### Symmetric encryption

| Topic | Status | Where |
|---|---|---|
| AES-GCM | ✅ | `MysticSymmetricAlgorithm.AES_GCM_NO_PADDING`; wired into `BaseByteArrayEncryptor`/`Decryptor`, `HexableEncryptor`/`Decryptor`, `PublicKeyEncryptor`/`PrivateKeyDecryptor` (all `mystic-crypt`). Random 12-byte IV per call, 128-bit tag, IV prepended to ciphertext. |
| AES-CBC | ⚠️ | Defined in `Mode`/algorithm enums (`crypt-api`); legacy PBE paths in `mystic-crypt` still support it for backward compatibility, but AES-GCM is the default everywhere. |
| AES-ECB | ⚠️ | Still definable via raw JCA transformation strings; no longer a default anywhere (removed in the 10.0.0 security hardening pass). Never use — no authentication, patterns leak. |
| ChaCha20-Poly1305 | ✅ | `MysticSymmetricAlgorithm.CHACHA20_POLY1305`; wired into the same six classes as AES-GCM above. JDK-native (SunJCE), no Bouncy Castle. Requires a 256-bit key (unlike AES's 128/192/256). |

### Asymmetric encryption

| Topic | Status | Where |
|---|---|---|
| RSA | ✅ | `PublicKeyEncryptor`/`PrivateKeyDecryptor` (`mystic-crypt`) — hybrid RSA+AES-GCM envelope, RSA wraps the AES key rather than encrypting data directly (correct usage; RSA is unsuited to bulk encryption). `KeyPairGeneratorAlgorithm.RSA`/`.RSASSA_PSS` (`crypt-api`). |
| ECC / named curves | ✅ (as constants) | `SECGCurveAlgorithm` (incl. P-256/`SECP256R1`), `BrainpoolCurveAlgorithm` (`crypt-api`). "Curve25519" has no dedicated enum constant — X25519/Ed25519 are the JDK-native algorithm names actually used. |
| X25519 (ECDH) | ✅ | `X25519KeyExchange` (`mystic-crypt`) — JDK-native since JDK 11, no Bouncy Castle. Derives the raw ECDH shared secret then runs it through HKDF (see below) rather than using it directly. |
| Ed25519 (signatures) | ✅ | `Ed25519Signer`/`Ed25519Verifier` (`mystic-crypt`) — JDK-native since JDK 15. `SignatureFactory` (`crypt-data`) is the generic sign/verify primitive underneath, algorithm-agnostic (also usable for RSA signature schemes). |
| DH / ECDH (generic) | ✅ | `KeyAgreementAlgorithm` (`DIFFIE_HELLMAN`, `ECDH`, `ECMQV`, `XDH`, `X25519`, `X448` — `crypt-api`); `KeyAgreementFactory` (`crypt-data`) executes it. Note: `KeyAgreementFactory.toSecretKey()` truncates the shared secret to 16 bytes regardless of algorithm — fine for classic (EC)DH's byte-agnostic usage, but callers deriving a full-strength key from a 32-byte X25519 secret should use the raw-bytes overload + HKDF instead (as `X25519KeyExchange` does), not `toSecretKey()`. |

### Hashing

| Topic | Status | Where |
|---|---|---|
| SHA-256 / SHA-512 | ✅ | `Hasher` (`mystic-crypt`), `HashExtensions` (`crypt-data`), `HashAlgorithm.SHA_256`/`.SHA_512` (`crypt-api`). |
| SHA-3 / Keccak | ⚠️ | `MessageDigestAlgorithm.SHA3_224/256/384/512` (`crypt-api`) defined; no call site outside that enum's own tests. |
| MD5 / SHA-1 | ✅ (present, legacy) | Still defined and reachable (e.g. for checksums, not security use) — not a gap, these are correctly *not* used for anything security-sensitive. |
| BLAKE2 / BLAKE3 | ❌ | Not present anywhere. |
| Constant-time comparison | ✅ | `MessageDigest.isEqual(...)` used in `PasswordEncryptor` and `Argon2Support` (`mystic-crypt`). Not used in `crypt-data`/`crypt-api` (no password/MAC comparison logic lives there). |

### Password hashing

| Topic | Status | Where |
|---|---|---|
| Argon2id | ✅ | `Argon2Support` (package-private) + `PasswordEncryptor.hashPasswordArgon2id()`/`.matchArgon2id()` (`mystic-crypt`). Bouncy Castle `Argon2BytesGenerator`, PHC string format (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) so parameters travel with the hash. |
| PBKDF2 | ✅ | `Pbkdf2Support` (package-private) + `PasswordEncryptor.hashPasswordPbkdf2()`/`.matchPbkdf2()` (`mystic-crypt`). Pure JDK (`SecretKeyFactory`), PBKDF2-HMAC-SHA256, 600k iterations by default (OWASP 2023 guidance). Argon2id remains the recommended default; this is for interop with systems that specifically require PBKDF2. |
| bcrypt / scrypt | ❌ | Not present anywhere. |

### Certificates / PKI

| Topic | Status | Where |
|---|---|---|
| X.509 generation (self-signed, CA-issued, intermediate) | ✅ | `CertFactory` (`newX509CertificateV1/V3`), `CertificateBuilderFactory`, `CertificateReader`/`Writer`, `PublicKeyReader`, `X509CertificateV1Info`/`V3Info` (`crypt-data`) — Bouncy Castle-backed. |
| TLS socket / handshake code | ✅ (main + test) | `KeyTrustExtensions` (main source, `mystic-crypt/.../ssl/`) resolves `KeyManager`/`TrustManager`s from a keystore. Actual `SSLSocket` handshake exercise (`SecureServer`/`SecureClient`) is test-only, not shipped in the published jar. |
| Certificate pinning / OCSP / CRL | 🚫 | Client-side trust-decision policy, not something a key/cert *utility* library should hardcode — belongs in the application's `TrustManager` configuration, which `KeyTrustExtensions` already exposes the building blocks for. |

### Post-Quantum

| Topic | Status | Where |
|---|---|---|
| ML-KEM / Kyber (FIPS 203) | ✅ | `MlKemKeyExchange` (`mystic-crypt`) wraps `KemFactory` (`crypt-data`, generic `javax.crypto.KEM` wrapper) — Bouncy Castle-backed (`ML-KEM-512/768/1024`), requires BC registered as a security provider. Verified end-to-end (encapsulate/decapsulate, shared secrets match) before wiring. |
| ML-DSA / Dilithium (FIPS 204) | ✅ | `MlDsaSigner`/`MlDsaVerifier` (`mystic-crypt`) — Bouncy Castle-backed (`ML-DSA-44/65/87`), same `SignatureFactory` primitive as Ed25519. |
| SLH-DSA / SPHINCS+ (FIPS 205) | ✅ | `SlhDsaSigner`/`SlhDsaVerifier` (`mystic-crypt`) — Bouncy Castle-backed, covers all 12 pure parameter sets (SHA2/SHAKE × 128/192/256 × S/F). Conservative hash-based signatures; large (tens of KB) and, for "S" sets, slow to sign — offered as a fallback if ML-DSA's lattice-based security assumption is ever broken. |

---

## Part 2: Key agreement

| Topic | Status | Where / Reasoning |
|---|---|---|
| Static vs. ephemeral DH | ✅ (ephemeral by default) | `X25519KeyExchange.newKeyPair()` generates a fresh keypair per call; nothing caches/reuses a long-term DH keypair for repeated exchanges. |
| Authenticated Key Exchange (STS, SIGMA, Noise) | 🚫 | These are session-establishment *protocols* (message flows, transcripts, replay handling) — a different problem from "derive a key from two public keys," which is what this library provides as a primitive. Building STS/Noise on top of `X25519KeyExchange` + `Ed25519Signer` is an application-level concern. |
| HKDF (RFC 5869) | ✅ | `HkdfExtensions` (`crypt-data`) — Bouncy Castle `HKDFBytesGenerator`/SHA-256. Used by `X25519KeyExchange` to derive the final AES key from the raw ECDH secret instead of truncating it. |
| KEM (Key Encapsulation) | ✅ | `KemFactory` (`crypt-data`) wraps the JDK-standard `javax.crypto.KEM` API (JDK 21+), algorithm-agnostic. Used by `MlKemKeyExchange` (`mystic-crypt`) for ML-KEM. |
| Signal Protocol (X3DH, Double Ratchet) | 🚫 | Full messaging protocol with session state, ratcheting, out-of-order message handling — an application/protocol layer built *on top of* primitives like X25519 + HKDF + AEAD, all of which this library already provides. Not a fit for a stateless utility library. |
| PAKE (J-PAKE, SRP, OPAQUE, SPAKE2/CPace) | ✅ (J-PAKE) | `JpakeKeyExchange` (`mystic-crypt`) wraps Bouncy Castle's `JPAKEParticipant` (Password-Authenticated Key Exchange by Juggling) - the only PAKE BC actually ships (no SPAKE2/CPace/SRP). A genuine 3-round interactive protocol, unlike this package's other key-exchange classes: the wrapper only adds sane-default participant creation and HKDF-based `SecretKey` derivation from the raw keying material; the round1/2/3 payload exchange is direct `JPAKEParticipant` API (documented with a full example in the class Javadoc). Verified end-to-end: matching passwords derive identical keys and pass round-3 confirmation, mismatched passwords derive different keys and round-3 confirmation throws. |
| Group key agreement / MLS / TreeKEM | 🚫 | Multi-party session/state-machine protocol (member add/remove, tree rebalancing) — same reasoning as Signal Protocol above. |
| AES Key Wrap (RFC 3394) | ✅ | `KeyWrapFactory` (`crypt-data`) — JDK-native `"AESWrap"` transformation (SunJCE), no Bouncy Castle needed. Implicit integrity check: tampered wrapped bytes throw `InvalidKeyException` on unwrap. |
| Key hierarchy (Master/KEK/DEK) | ⚠️ | The *primitive* (`KeyWrapFactory`) needed to build a KEK→DEK hierarchy exists; the hierarchy itself (master key never leaving an HSM, rotation policy, etc.) is an application/infrastructure design, not a library API. |
| Shamir's Secret Sharing | ✅ | `ShamirSecretSharingFactory` (`crypt-data`) — wraps Bouncy Castle's `org.bouncycastle.crypto.threshold.ShamirSecretSplitter` (GF(256) polynomial interpolation). `split()`/`combine()`, own `Share(index, value)` type since BC's own share type doesn't expose the share index. Two documented constraints inherited from BC's implementation: total share count must not exceed the secret length in bytes, and combining fewer than the original threshold silently yields a wrong secret (no built-in integrity check — Shamir's scheme has none). |
| Verifiable Secret Sharing (Feldman/Pedersen VSS) | ❌ | Not present. Would close the "wrong result on too few shares" gap above if ever needed. |
| Key transparency (append-only key-change log) | 🚫 | Requires a server/log infrastructure (Merkle tree, auditors, gossip) — infrastructure, not a library primitive. |
| Pre-Shared Keys (PSK) | ✅ (trivially) | Any `byte[]`/`SecretKey` works as a PSK with the existing `BaseByteArrayEncryptor`/`Decryptor` — no dedicated PSK class needed, since "PSK" just means "a symmetric key from an out-of-band channel" from the library's point of view. |

---

## Part 3: Practice, hardware, attacks

| Topic | Status | Where / Reasoning |
|---|---|---|
| Key generation (RNG) | ✅ | All key generation goes through `SecureRandom` (JDK) or Bouncy Castle equivalents — no use of non-cryptographic RNGs anywhere in the three repos. |
| Key storage (files, keystores) | ✅ | `CertFactory`/`KeyStoreFactory`/`KeyStoreInfo` etc. (`crypt-data`) read/write PKCS#8/PKCS#12/JKS keystores. No integration with OS keychains or Vault/SOPS — appropriately out of scope, those are deployment-environment concerns. |
| Key rotation / revocation policy | 🚫 | Operational/infrastructure concern (CRL/OCSP serving, rotation scheduling) — the library provides the primitives (cert generation, key wrap) that a rotation system would use, not the policy engine itself. |
| Key destruction (secure wipe) | ✅ (password paths + X25519) | `Argon2Support`/`Pbkdf2Support` zero their `char[] password` argument in a `finally` block after `hash()`/`verify()` (`mystic-crypt`); `X25519KeyExchange.deriveSharedSecret` zeroes the raw ECDH shared secret after HKDF derivation. Not applied everywhere key material exists (e.g. `SecretKeySpec`/`SecretKey` objects generally aren't zeroable via the JCA `Destroyable` interface in practice - a known JCA limitation, not something this library can work around). |
| HSM / PKCS#11 | ✅ | `Pkcs11Factory` (`crypt-data`) configures the JDK's built-in `SunPKCS11` provider from a config file and opens the token's keystore; the returned `Provider` then works with any standard JCA factory method (`KeyPairGenerator`, `Signature`, etc.), so key material generated/used through it never leaves the token. Verified end-to-end against a real (software) PKCS#11 module - SoftHSM2, installed specifically for this rather than touching the real desktop GNOME Keyring PKCS#11 module: token init, provider config, keystore open, on-token EC keypair generation, sign/verify all confirmed working. `Pkcs11FactoryTest` skips itself (doesn't fail) when no PKCS#11 test module is configured, since that's external test infrastructure. |
| TPM | 🚫 | Platform-specific hardware integration (`tpm2-pkcs11` et al.) — outside a portable Java library's remit; would layer on top of the PKCS#11 gap above if ever needed. |
| Secure Enclaves (SGX/TrustZone/Secure Enclave) | 🚫 | OS/platform-specific, no portable JCA path exists for these at all. |
| FIDO2/WebAuthn | 🚫 | Full authenticator protocol (attestation, challenge-response ceremonies) — a different problem domain from "encrypt this data with this key." |
| Quantum Key Distribution (QKD) | 🚫 | Requires dedicated physical hardware (fiber/satellite photon transmission) — not something a software library can provide regardless of scope. |
| Identity-Based Key Exchange (IBKE) | ❌ | Not present. Niche/academic; no current consumer need identified. |
| Deniability (deniable AKE, ring signatures) | 🚫 | Protocol-design property of a *session*, not a primitive — same layering argument as Signal Protocol/AKE above. |
| Key-committing AEAD | ❌ | Current AES-GCM usage does not add explicit key-commitment. Real, narrow gap *if* this library is ever used in a context vulnerable to the "invisible salamanders" class of attack (multi-recipient encryption, abuse-reporting systems) — not a concern for its current point-to-point encryption use cases. |
| Channel binding (`tls-exporter`/`tls-unique`) | 🚫 | Only meaningful bound to an active TLS session the library isn't managing (`KeyTrustExtensions` builds `TrustManager`s, doesn't own the socket lifecycle). |
| Threshold signatures / MPC (FROST etc.) | ❌ | Not present. Distinct from Shamir's Secret Sharing above (threshold signing never reconstructs the private key at all, even transiently) — a real gap only if a multi-party signing use case ever emerges. |
| Downgrade attacks (FREAK/Logjam/POODLE/ROBOT) | 🚫 | These are TLS *protocol negotiation* flaws, not something a data-at-rest encryption library can be vulnerable to or defend against — has no cipher-suite negotiation surface at all. |
| Formal verification (ProVerif/Tamarin/CryptoVerif) | 🚫 | Applies to protocol *designs* (message flows, state machines). This library ships primitives (AES-GCM, Ed25519, X25519+HKDF, Argon2id, Shamir SSS, AES-KW) each already backed by a formally-analyzed algorithm/JCA provider — there's no protocol-level design here to verify. |

---

## Summary: real gaps vs. correctly out of scope

**Every gap identified in the original pass through this document is now closed:** PBKDF2 wiring,
ChaCha20-Poly1305 wiring, the full NIST post-quantum suite (ML-KEM, ML-DSA, SLH-DSA), key zeroing
for password/shared-secret material, PAKE (J-PAKE), and PKCS#11/HSM provider configuration are all
✅ — see the tables above for the classes involved, and each item's commit message for how it was
verified before being wired in (this library's standing discipline: confirm an algorithm/API
actually behaves as expected via a throwaway empirical test *before* writing the real
implementation against it, not after).

**Residual, narrower items not pursued further** (each is a real but genuinely marginal
improvement, not a category-level gap):

- **Verifiable Secret Sharing (Feldman/Pedersen VSS)** — would close Shamir SSS's "too-few-shares
  silently gives a wrong result" limitation, at the cost of a second, more complex primitive.
- **Key-committing AEAD** — only matters for multi-recipient encryption / abuse-reporting use
  cases this library doesn't currently target.
- **SRP/OPAQUE specifically** (as opposed to J-PAKE, which is what's actually implemented) — would
  require either hand-rolling the protocol math (SRP) or a dependency neither the JDK nor Bouncy
  Castle currently ships (OPAQUE).

**Everything marked 🚫 is correctly out of scope**, not missing: session/messaging protocols (Signal, MLS, STS, Noise), hardware/platform integrations this library can't portably reach (TPM, secure enclaves, QKD, FIDO2), and infrastructure/policy concerns (key rotation scheduling, certificate pinning policy, key transparency logs). Adding any of those would mean turning a key/data-encryption utility library into a protocol or infrastructure framework — a different, much larger project.

---

## Test quality: mutation testing

All three repos now have [PIT](https://pitest.org/) mutation testing configured (`info.solidsoft.pitest` Gradle plugin), run via `./gradlew pitest` — deliberately **not** wired into `check`/`build`, since mutation testing is slow (minutes, not seconds) and belongs in an occasional, deliberately-triggered run rather than every CI build. Baseline scores (mutations killed / generated):

| Repo | Mutation coverage | Line coverage (mutated classes) |
|---|---|---|
| `crypt-api` | 96% (75/78) | 99% |
| `crypt-data` | 77% (610/793) | 91% |
| `mystic-crypt` | 69% (415/605) | 79% |

`mystic-crypt`'s lower score reflects its larger, more integration-heavy surface (file I/O, streaming, SSL/keystore glue) rather than the newer crypto primitives specifically — most of the newly-added classes this round (PQC, ChaCha20, PBKDF2, key wrap, secret sharing) have direct, focused unit tests. Known rough edge: running `./gradlew pitest` in `mystic-crypt` has been observed to leave `src/test/resources/crypt/test.txt` deleted afterwards (a file-based test's cleanup interacting badly with PIT's forked/parallel execution) — run `git checkout -- src/test/resources/crypt/test.txt` afterward if the next build fails with a `FileNotFoundException` there.
