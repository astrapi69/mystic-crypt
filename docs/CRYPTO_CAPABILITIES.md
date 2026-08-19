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
(10.2 released), `crypt-api` 9.7-SNAPSHOT (9.6 released).

---

## Part 1: Fundamentals

### Symmetric encryption

| Topic | Status | Where |
|---|---|---|
| AES-GCM | ✅ | `MysticSymmetricAlgorithm.AES_GCM_NO_PADDING`; wired into `BaseByteArrayEncryptor`/`Decryptor`, `HexableEncryptor`/`Decryptor`, `PublicKeyEncryptor`/`PrivateKeyDecryptor` (all `mystic-crypt`). Random 12-byte IV per call, 128-bit tag, IV prepended to ciphertext. |
| AES-CBC | ⚠️ | Defined in `Mode`/algorithm enums (`crypt-api`); legacy PBE paths in `mystic-crypt` still support it for backward compatibility, but AES-GCM is the default everywhere. |
| AES-ECB | ⚠️ | Still definable via raw JCA transformation strings; no longer a default anywhere (removed in the 10.0.0 security hardening pass). Never use — no authentication, patterns leak. |
| ChaCha20-Poly1305 | ⚠️ | `CipherAlgorithm.ChaCha20` / `.ChaCha20_Poly1305` constants exist (`crypt-api`). Zero call sites anywhere else — no cipher/encryptor path uses it. |

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
| PBKDF2 | ⚠️ | `PasswordHashType.PBKDF2`, `CompoundAlgorithm.PBKDF2_WITH_HMAC_SHA1` (`crypt-api`) defined; no call site actually invokes PBKDF2 key derivation in main source. |
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
| ML-KEM / Kyber, ML-DSA / Dilithium, SLH-DSA / SPHINCS+ | ❌ | Not present. Bouncy Castle (already a dependency) does provide these, so adding them is a real, scoped option if/when needed — nothing architectural blocks it. |

---

## Part 2: Key agreement

| Topic | Status | Where / Reasoning |
|---|---|---|
| Static vs. ephemeral DH | ✅ (ephemeral by default) | `X25519KeyExchange.newKeyPair()` generates a fresh keypair per call; nothing caches/reuses a long-term DH keypair for repeated exchanges. |
| Authenticated Key Exchange (STS, SIGMA, Noise) | 🚫 | These are session-establishment *protocols* (message flows, transcripts, replay handling) — a different problem from "derive a key from two public keys," which is what this library provides as a primitive. Building STS/Noise on top of `X25519KeyExchange` + `Ed25519Signer` is an application-level concern. |
| HKDF (RFC 5869) | ✅ | `HkdfExtensions` (`crypt-data`) — Bouncy Castle `HKDFBytesGenerator`/SHA-256. Used by `X25519KeyExchange` to derive the final AES key from the raw ECDH secret instead of truncating it. |
| KEM (Key Encapsulation) | ❌ | No KEM implementation (this is the interactive-DH-vs-encapsulation distinction; relevant mainly once PQC/ML-KEM is added, since PQC key exchange is KEM-shaped, not DH-shaped). |
| Signal Protocol (X3DH, Double Ratchet) | 🚫 | Full messaging protocol with session state, ratcheting, out-of-order message handling — an application/protocol layer built *on top of* primitives like X25519 + HKDF + AEAD, all of which this library already provides. Not a fit for a stateless utility library. |
| PAKE (SRP, OPAQUE, SPAKE2/CPace) | ❌ | Not present. Real gap if a password-authenticated channel is ever needed directly (today, Argon2id covers password *storage*, not password-authenticated *key exchange*). |
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
| Key destruction (secure wipe) | ❌ | No explicit zeroing of key material in memory (e.g. no `Arrays.fill(key, (byte) 0)` after use). A real, scoped hardening candidate if ever prioritized — low effort, meaningfully reduces memory-dump exposure window. |
| HSM / PKCS#11 | ⚠️ | `KeystoreType.PKCS11`, `SecureRandomAlgorithm.PKCS11`, `SecurityProvider.SunPKCS11` (`crypt-api`) are name-only constants. No `Security.getProvider("SunPKCS11")` config/slot wiring exists. This is architecturally reasonable to add later (JCA's standard extension point), but nothing calls it today. |
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

**Actual gaps worth considering, roughly in order of value:**

1. **PBKDF2 wiring** — constant exists, unused; cheapest possible addition if a PBKDF2-compatible path is ever needed (e.g. interop with a system that mandates it).
2. **ChaCha20-Poly1305 wiring** — same situation, useful on platforms without AES hardware acceleration.
3. **Key zeroing** — explicit wipe of `SecretKey`/byte-array key material after use; low effort, real memory-exposure reduction.
4. **PAKE (OPAQUE or SPAKE2/CPace)** — the one clear category-level gap if a password-authenticated key exchange (not just password storage) is ever required.
5. **Post-Quantum primitives (ML-KEM/ML-DSA)** — Bouncy Castle already provides them; no architectural blocker, just not yet prioritized.
6. **PKCS#11/HSM wiring** — constants exist as the correct JCA extension point; needs actual provider configuration code once a consumer needs hardware-backed keys.

**Everything marked 🚫 is correctly out of scope**, not missing: session/messaging protocols (Signal, MLS, STS, Noise), hardware/platform integrations this library can't portably reach (TPM, secure enclaves, QKD, FIDO2), and infrastructure/policy concerns (key rotation scheduling, certificate pinning policy, key transparency logs). Adding any of those would mean turning a key/data-encryption utility library into a protocol or infrastructure framework — a different, much larger project.
