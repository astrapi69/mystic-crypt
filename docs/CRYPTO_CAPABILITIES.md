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

Last full pass: 2026-08-22, against `mystic-crypt` 11.0.0, `crypt-data` 10.4-SNAPSHOT
and `crypt-api` 10.0.0.

Partially re-verified 2026-09-05 against `mystic-crypt` 12.2-SNAPSHOT, which resolves
`crypt-data` 12.2 and `crypt-api` 10.0.0 (`gradle/libs.versions.toml`; note that `crypt-api` 10.1
is released but not yet pinned here). That pass re-read source for the rows it changed only -
ECIES, ECC/named curves and the new HMAC row - and did not re-walk the rest, so every other row
still carries the 2026-08-22 verification date. Coverage and mutation-testing numbers live in
[TESTING.md](TESTING.md). All three libraries now require **JDK 25** (raised from 21, 21 and 17
respectively in the same release cycle - see [README.md](../README.md#requirements)).

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
| ECIES (EC hybrid encryption) | ✅ | `EcPublicKeyEncryptor`/`EcPrivateKeyDecryptor` on bytes, `EcPublicKeyHexEncryptor`/`EcPrivateKeyHexDecryptor` on hex strings (`mystic-crypt`), in the shape of the RSA pair above. Bouncy Castle `ECIESwithSHA256`, picked because it is self-contained: the block-cipher variants (`ECIESwithAES-CBC` and friends) need an `IESParameterSpec` carrying the same nonce on both sides, which would have to travel beside the ciphertext, and BC registers no AES-GCM variant at all. An ephemeral key pair is generated per message and ECDH'd against the recipient's public key, so two encryptions of the same plaintext never match. A key of another algorithm is refused by name (`EcCipherSupport.requireEcKey`), including X25519/X448, ML-KEM and the signature families, none of which have an encryption primitive. |
| ECC / named curves | ✅ | `SECGCurveAlgorithm` (incl. P-256/`SECP256R1`), `BrainpoolCurveAlgorithm` (`crypt-api`) supply the names; `keygen --curve` and the ECIES row above are the call sites that consume them, so these are no longer constants without a consumer. "Curve25519" has no dedicated enum constant — X25519/Ed25519 are the JDK-native algorithm names actually used. |
| X25519 (ECDH) | ✅ | `X25519KeyExchange` (`mystic-crypt`) — JDK-native since JDK 11, no Bouncy Castle. Derives the raw ECDH shared secret then runs it through HKDF (see below) rather than using it directly. |
| Ed25519 (signatures) | ✅ | `Ed25519Signer`/`Ed25519Verifier` (`mystic-crypt`) — JDK-native since JDK 15. `SignatureFactory` (`crypt-data`) is the generic sign/verify primitive underneath, algorithm-agnostic (also usable for RSA signature schemes). |
| DH / ECDH (generic) | ✅ | `KeyAgreementAlgorithm` (`DIFFIE_HELLMAN`, `ECDH`, `ECMQV`, `XDH`, `X25519`, `X448` — `crypt-api`); `KeyAgreementFactory` (`crypt-data`) executes it. Note: `KeyAgreementFactory.toSecretKey()` truncates the shared secret to 16 bytes regardless of algorithm — fine for classic (EC)DH's byte-agnostic usage, but callers deriving a full-strength key from a 32-byte X25519 secret should use the raw-bytes overload + HKDF instead (as `X25519KeyExchange` does), not `toSecretKey()`. |

### Hashing

| Topic | Status | Where |
|---|---|---|
| SHA-256 / SHA-512 | ✅ | `Hasher` (`mystic-crypt`), `HashExtensions` (`crypt-data`), `HashAlgorithm.SHA_256`/`.SHA_512` (`crypt-api`). |
| SHA-3 / Keccak | ✅ | `Sha3Hasher` (`mystic-crypt`) — all four fixed-length FIPS 202 variants (SHA3-224/256/384/512) via the JDK's built-in `MessageDigest`, no Bouncy Castle. Selected through the `MessageDigestAlgorithm.SHA3_*` constants (`crypt-api`), which finally have a call site; any non-SHA-3 constant is rejected so the class can never silently compute MD5/SHA-2 under a SHA-3 name. Verified against OpenSSL-generated known-answer vectors. SHAKE128/256 (the variable-length XOFs) are not wrapped — no consumer need, and `MessageDigest` can't express variable output length. |
| MD5 / SHA-1 | ✅ (present, legacy) | Still defined and reachable (e.g. for checksums, not security use) — not a gap, these are correctly *not* used for anything security-sensitive. |
| BLAKE2 / BLAKE3 | ✅ (BLAKE2 only) | `Blake2bHasher`/`Blake2sHasher` (`mystic-crypt`) — Bouncy Castle-backed, both BLAKE2b (64-bit optimized) and BLAKE2s (32-bit/embedded optimized) with configurable digest length. Also the commitment-tag primitive under `KeyCommittingAeadEncryptor` (see Key-committing AEAD, Part 2). BLAKE3 remains absent — no BLAKE3 implementation ships in Bouncy Castle or the JDK, only third-party libraries this project doesn't depend on. |
| HMAC / keyed MAC | ✅ (capability), ⚠️ (as a library API) | `ChecksumCommand --hmac` (`mystic-crypt`) computes a keyed MAC through the JDK's `Mac`/`SecretKeySpec`, default `HmacSHA256`, any JDK MAC name accepted (`HmacSHA512`, `HmacSHA3-256`, ...); a plain digest name is refused with a message that says to drop `--hmac` instead. The MAC key is the passphrase's UTF-8 bytes, not a KDF output — adequate for the "did this file change, and was the change made by someone holding the key" question the command answers, not a substitute for a derived key. `MacAlgorithm` (`crypt-api`) enumerates the names but has no caller anywhere in the three repos: the CLI passes strings straight to the JDK, so the enum is a constant set rather than a wired API. |
| Constant-time comparison | ✅ | `MessageDigest.isEqual(...)` used in `PasswordEncryptor` and `Argon2Support` (`mystic-crypt`). Not used in `crypt-data`/`crypt-api` (no password/MAC comparison logic lives there). |

### Password hashing

| Topic | Status | Where |
|---|---|---|
| Argon2id | ✅ | `Argon2Support` (package-private) + `PasswordEncryptor.hashPasswordArgon2id()`/`.matchArgon2id()` (`mystic-crypt`). Bouncy Castle `Argon2BytesGenerator`, PHC string format (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) so parameters travel with the hash. |
| PBKDF2 | ✅ | `Pbkdf2Support` (package-private) + `PasswordEncryptor.hashPasswordPbkdf2()`/`.matchPbkdf2()` (`mystic-crypt`). Pure JDK (`SecretKeyFactory`), PBKDF2-HMAC-SHA256, 600k iterations by default (OWASP 2023 guidance). Argon2id remains the recommended default; this is for interop with systems that specifically require PBKDF2. |
| bcrypt / scrypt | ✅ | `BcryptHasher` (Bouncy Castle `OpenBSDBCrypt`), `ScryptHasher` (Bouncy Castle `SCrypt.generate`). The initial implementation (authored by an automated `qwen.ai[bot]` commit, not this session) called BCrypt methods that don't exist on Bouncy Castle's API and could not compile; fixed to use the real `OpenBSDBCrypt.generate`/`.checkPassword` API, and `ScryptHasher`'s convenience `hash()` overloads (which silently discarded their randomly-generated salt, making the result unverifiable) now return `salt‖derivedKey`. Argon2id remains the recommended default for new code - these exist for interop with systems that specifically require bcrypt or scrypt. |

### Certificates / PKI

| Topic | Status | Where |
|---|---|---|
| X.509 generation (self-signed, CA-issued, intermediate) | ✅ | `CertFactory` (`newX509CertificateV1/V3`), `CertificateBuilderFactory`, `CertificateReader`/`Writer`, `PublicKeyReader`, `X509CertificateV1Info`/`V3Info` (`crypt-data`) — Bouncy Castle-backed. |
| TLS socket / handshake code | ✅ (main + test) | `KeyTrustExtensions` (main source, `mystic-crypt/.../ssl/`) resolves `KeyManager`/`TrustManager`s from a keystore. Actual `SSLSocket` handshake exercise (`SecureServer`/`SecureClient`) is test-only, not shipped in the published jar. |
| Certificate pinning / OCSP / CRL | 🚫 | Each is a *runtime trust decision*, not a key/data primitive: pinning means comparing a live peer certificate/public key against an app-embedded allowlist and rejecting the connection on mismatch; OCSP means making a live network call per handshake to a responder URL (with its own timeout/soft-fail/stapling policy tradeoffs); CRL means periodically fetching and diffing a revocation list. All three require the *application* to own connection lifecycle, network policy, and update cadence decisions this library has no visibility into. `KeyTrustExtensions` already exposes the correct extension point: it hands back a real `TrustManager`, and any of the three can be implemented by wrapping that `TrustManager` with `X509ExtendedTrustManager.checkServerTrusted` overrides — that's an application concern, not something this library should decide on the app's behalf. |

### Post-Quantum

| Topic | Status | Where |
|---|---|---|
| ML-KEM / Kyber (FIPS 203) | ✅ | `MlKemKeyExchange` (`mystic-crypt`) wraps `KemFactory` (`crypt-data`, generic `javax.crypto.KEM` wrapper) — Bouncy Castle-backed (`ML-KEM-512/768/1024`), requires BC registered as a security provider. Verified end-to-end (encapsulate/decapsulate, shared secrets match) before wiring. |
| Hybrid classical+PQC KEM (X25519 + ML-KEM) | ✅ | `HybridKemKeyExchange` (`mystic-crypt`) — the NIST-recommended transitional combiner: concatenates the classical X25519 ECDH shared secret (32 bytes) with the ML-KEM shared secret, then HKDF-derives the final key, so security holds as long as *either* component algorithm remains unbroken. Sender generates a fresh ephemeral X25519 keypair per encapsulation. `HybridKemKeyExchangeTest` covers round-trip encapsulate/decapsulate, non-determinism across calls, and rejection of non-ML-KEM algorithms. |
| ML-DSA / Dilithium (FIPS 204) | ✅ | `MlDsaSigner`/`MlDsaVerifier` (`mystic-crypt`) — Bouncy Castle-backed (`ML-DSA-44/65/87`), same `SignatureFactory` primitive as Ed25519. |
| SLH-DSA / SPHINCS+ (FIPS 205) | ✅ | `SlhDsaSigner`/`SlhDsaVerifier` (`mystic-crypt`) — Bouncy Castle-backed, covers all 12 pure parameter sets (SHA2/SHAKE × 128/192/256 × S/F). Conservative hash-based signatures; large (tens of KB) and, for "S" sets, slow to sign — offered as a fallback if ML-DSA's lattice-based security assumption is ever broken. |

---

## Part 2: Key agreement

| Topic | Status | Where / Reasoning |
|---|---|---|
| Static vs. ephemeral DH | ✅ (ephemeral by default) | `X25519KeyExchange.newKeyPair()` generates a fresh keypair per call; nothing caches/reuses a long-term DH keypair for repeated exchanges. |
| Authenticated Key Exchange (STS, SIGMA, Noise) | 🚫 | A real AKE isn't one function call, it's a *message-flow specification*: exact byte layout of each handshake message, the order signatures/MACs are computed in (and over which transcript prefix — get this wrong and you reintroduce the exact reflection/identity-misbinding attacks these protocols exist to prevent), explicit transcript hashing across every prior message, and replay/downgrade protection via nonces or handshake hashes bound into the final key. None of that is "crypto math" this library is missing — `X25519KeyExchange` (the DH) and `Ed25519Signer` (the signature) are exactly the primitives an STS or Noise `XX`/`IK` pattern is built from. Implementing one correctly means picking or defining a specific message schema and getting the transcript-binding order exactly right, which is a protocol-design task with its own attack surface, not a wrapper around existing calls. |
| HKDF (RFC 5869) | ✅ | `HkdfExtensions` (`crypt-data`) — Bouncy Castle `HKDFBytesGenerator`/SHA-256. Used by `X25519KeyExchange` to derive the final AES key from the raw ECDH secret instead of truncating it. |
| KEM (Key Encapsulation) | ✅ | `KemFactory` (`crypt-data`) wraps the JDK-standard `javax.crypto.KEM` API (JDK 21+), algorithm-agnostic. Used by `MlKemKeyExchange` (`mystic-crypt`) for ML-KEM. |
| Signal Protocol (X3DH, Double Ratchet) | 🚫 | This isn't one primitive, it's a persistent per-conversation *state machine*: X3DH alone needs four key types per user (identity, signed prekey, one-time prekeys, ephemeral) and a server to publish/consume prekey bundles; the Double Ratchet then advances a DH ratchet on every message direction change plus a symmetric KDF chain on every single message, and that ratchet state has to be durably persisted between app runs or messages become undecryptable. Every primitive it's built from already exists here (`X25519KeyExchange` for the DH steps, `HkdfExtensions` for each KDF step, `BaseByteArrayEncryptor` for the AEAD step) — what's genuinely missing is the *state machine and its storage contract*, which belongs to whatever application owns message persistence, not a stateless encrypt-this-blob library. |
| PAKE (J-PAKE, SRP, OPAQUE, SPAKE2/CPace) | ✅ (J-PAKE, SRP-6a) | `JpakeKeyExchange` (`mystic-crypt`) wraps Bouncy Castle's `JPAKEParticipant`. A genuine 3-round interactive protocol, unlike this package's other key-exchange classes: the wrapper only adds sane-default participant creation and HKDF-based `SecretKey` derivation from the raw keying material; the round1/2/3 payload exchange is direct `JPAKEParticipant` API (documented with a full example in the class Javadoc). Verified end-to-end: matching passwords derive identical keys and pass round-3 confirmation, mismatched passwords derive different keys and round-3 confirmation throws. `SRP6aClient`/`SRP6aServer`/`SRP6aVerifierGenerator` (`mystic-crypt`) wrap Bouncy Castle's real `org.bouncycastle.crypto.agreement.srp.*` classes - BC does ship an audited SRP-6a implementation, contrary to what this row previously said. The initial hand-rolled (non-BC) implementation had a critical vulnerability: neither side checked the peer's public value against zero mod N (the classic SRP zero-key attack, RFC 5054 section 2.5.4), letting a malicious client or compromised server force a session key with no dependence on the password, bypassing authentication entirely; every hash step also used signed, inconsistently-padded `BigInteger.toByteArray()` instead of RFC 5054's fixed-width unsigned encoding. Rewritten to delegate every computation to BC's `SRP6Util` (which includes the zero-check via `validatePublicValue`), keeping the original public API shape. SPAKE2/CPace/OPAQUE remain unimplemented - BC ships none of them. |
| Group key agreement / MLS / TreeKEM | 🚫 | TreeKEM's entire reason to exist is maintaining a balanced binary tree of node keys across a *dynamic membership set* — every add/remove/update triggers a specific tree-path re-key sequence, and correctness depends on every group member applying commits in the same order (a distributed-consensus-adjacent problem, not a crypto-math one). This needs its own persisted tree state per group and a defined transport for `Commit`/`Welcome`/`Proposal` messages (RFC 9420 specifies these precisely) — same category of "genuinely missing piece is the state machine and its storage/ordering contract" as Signal Protocol above, at even more implementation complexity since it's multi-party rather than pairwise. |
| AES Key Wrap (RFC 3394) | ✅ | `KeyWrapFactory` (`crypt-data`) — JDK-native `"AESWrap"` transformation (SunJCE), no Bouncy Castle needed. Implicit integrity check: tampered wrapped bytes throw `InvalidKeyException` on unwrap. |
| Key hierarchy (Master/KEK/DEK) | ⚠️ | The *primitive* (`KeyWrapFactory`) needed to build a KEK→DEK hierarchy exists; the hierarchy itself (master key never leaving an HSM, rotation policy, etc.) is an application/infrastructure design, not a library API. |
| Shamir's Secret Sharing | ✅ | `ShamirSecretSharingFactory` (`crypt-data`) — wraps Bouncy Castle's `org.bouncycastle.crypto.threshold.ShamirSecretSplitter` (GF(256) polynomial interpolation). `split()`/`combine()`, own `Share(index, value)` type since BC's own share type doesn't expose the share index. Two documented constraints inherited from BC's implementation: total share count must not exceed the secret length in bytes, and combining fewer than the original threshold silently yields a wrong secret (no built-in integrity check — Shamir's scheme has none). |
| Verifiable Secret Sharing (Feldman/Pedersen VSS) | ✅ (Feldman only) | `FeldmanVSS` (`mystic-crypt`) — extends Shamir SSS with public commitments (`g^{a_i} mod p`) so shares can be verified against the commitments before reconstruction, closing the "wrong result on too few/wrong shares" silent-failure gap above. Operates in a prime-order subgroup of `Z_p*`; the secret is reduced into `Z_q` (`secret.mod(q)`) since reconstruction can only ever recover a value mod q. Pedersen VSS (which additionally hides the secret from the dealer via a second generator) is not implemented — no current consumer need for dealer-blindness specifically. |
| Key transparency (append-only key-change log) | 🚫 | The mechanism (a Merkle tree of key-change entries with periodic signed tree-head checkpoints) is server-hosted, publicly-queryable infrastructure that has to run continuously and be independently monitored by third-party auditors for consistency and non-equivocation — it's not something a client library instantiates on demand. What this library *could* reasonably provide is a client-side inclusion-proof verifier (given a leaf, a Merkle path, and a signed tree head, confirm the leaf is really in the tree) — genuinely closer to a "primitive," but there's no concrete consumer need for it today, and building it speculatively without a real transparency-log server to verify against would violate this session's standing discipline of confirming an implementation against something real before shipping it. |
| Pre-Shared Keys (PSK) | ✅ (trivially) | Any `byte[]`/`SecretKey` works as a PSK with the existing `BaseByteArrayEncryptor`/`Decryptor` — no dedicated PSK class needed, since "PSK" just means "a symmetric key from an out-of-band channel" from the library's point of view. |

---

## Part 3: Practice, hardware, attacks

| Topic | Status | Where / Reasoning |
|---|---|---|
| Key generation (RNG) | ✅ | All key generation goes through `SecureRandom` (JDK) or Bouncy Castle equivalents — no use of non-cryptographic RNGs anywhere in the three repos. |
| Key storage (files, keystores) | ✅ | `CertFactory`/`KeyStoreFactory`/`KeyStoreInfo` etc. (`crypt-data`) read/write PKCS#8/PKCS#12/JKS keystores. No integration with OS keychains or Vault/SOPS — appropriately out of scope, those are deployment-environment concerns. |
| Key rotation / revocation policy | 🚫 | "Rotate this key" isn't a function, it's a *policy decision tree*: how often (calendar-based? usage-count-based?), how the old key stays available to decrypt already-encrypted data during a grace period, how consumers discover a new key is active (a key-ID/version scheme, which this library doesn't impose), and — for revocation specifically — how a compromise gets propagated to every relying party before they trust the compromised key again. All of that is business/deployment logic that varies per application; this library supplies the mechanical pieces a rotation system would call (`CertFactory` to mint a new cert, `KeyWrapFactory`/`Pkcs11Factory` to protect the new key) without presuming to own the schedule or trust-propagation policy around them. |
| Key destruction (secure wipe) | ✅ (password paths + X25519) | `Argon2Support`/`Pbkdf2Support` zero their `char[] password` argument in a `finally` block after `hash()`/`verify()` (`mystic-crypt`); `X25519KeyExchange.deriveSharedSecret` zeroes the raw ECDH shared secret after HKDF derivation. Not applied everywhere key material exists (e.g. `SecretKeySpec`/`SecretKey` objects generally aren't zeroable via the JCA `Destroyable` interface in practice - a known JCA limitation, not something this library can work around). |
| HSM / PKCS#11 | ✅ | `Pkcs11Factory` (`crypt-data`) configures the JDK's built-in `SunPKCS11` provider from a config file and opens the token's keystore; the returned `Provider` then works with any standard JCA factory method (`KeyPairGenerator`, `Signature`, etc.), so key material generated/used through it never leaves the token. Verified end-to-end against a real (software) PKCS#11 module - SoftHSM2, installed specifically for this rather than touching the real desktop GNOME Keyring PKCS#11 module: token init, provider config, keystore open, on-token EC keypair generation, sign/verify all confirmed working. `Pkcs11FactoryTest` skips itself (doesn't fail) when no PKCS#11 test module is configured, since that's external test infrastructure. |
| TPM | 🚫 | A real TPM binding needs the platform's TPM 2.0 stack reachable as a PKCS#11 module (e.g. `tpm2-pkcs11`, which itself needs the `tpm2-tools`/`tpm2-tss` userspace stack installed and a TPM device or firmware-TPM present) or a TPM-specific JCA provider — this library already has the correct, portable extension point for that (`Pkcs11Factory`, verified this round against SoftHSM2). What's out of scope is bundling/assuming a specific TPM stack, since that's inherently OS- and hardware-dependent in a way a portable Java library can't own; a consumer with a real TPM can point `Pkcs11Factory.newProvider(...)` at their platform's TPM PKCS#11 module directly, today. |
| Secure Enclaves (SGX/TrustZone/Secure Enclave) | 🚫 | Unlike TPM, there's no PKCS#11 (or any standard JCA) path into these at all — Intel SGX needs the enclave's own attested SDK and a signed enclave binary, ARM TrustZone requires a trusted-OS-side trustlet built against a vendor SDK (OP-TEE, Qualcomm QSEE, etc.), and Apple's Secure Enclave is reachable only via Apple's own `SecKey`/Keychain APIs from native (Objective-C/Swift) code — none expose a portable JVM entry point. Supporting any one of these means shipping a JNI bridge to a platform-specific, often vendor-gated SDK, which is a different (and per-platform) engineering effort from "add a class to this library." |
| FIDO2/WebAuthn | 🚫 | The authenticator ceremony (browser/platform-mediated `navigator.credentials.create()`/`.get()`, attestation object parsing, origin/RP-ID binding, challenge-response with a hardware authenticator like a YubiKey) happens in a context this library has no access to — a browser or a platform authenticator API, not a JVM process holding key bytes. This library's actual crypto (ECDSA/Ed25519 verify) is the *easy* 5% of a WebAuthn relying-party implementation; the hard 95% (CBOR attestation parsing, origin validation, credential storage/lookup, replay-counter tracking) is a specific, security-sensitive protocol implementation that would need its own dedicated, audited library rather than a corner of this one. |
| Quantum Key Distribution (QKD) | 🚫 | Not a software gap in any sense — BB84 and its variants work by transmitting individual polarized photons over dedicated fiber (or free-space/satellite links) and measuring quantum-mechanical disturbance from eavesdropping; there is no way to "implement" the physical transmission layer in code, only to consume key material a QKD hardware link has already produced (at which point it's just a `byte[]` PSK, already trivially supported — see the PSK row above). |
| Identity-Based Key Exchange (IBKE) | 🚫 | Deliberately not implemented. The one thing worth naming: IBKE architecturally requires a trusted Key Generation Center that computes every participant's private key from their identity string plus a master secret, meaning the KGC can derive (or has derived) every user's private key by construction — a form of mandatory key escrow that real deployments generally consider a feature only in specific closed/regulated contexts (e.g. enterprise email escrow), not a general-purpose property most users of a crypto library would want. Niche/academic beyond that; no current consumer need identified. |
| Deniability (deniable AKE, ring signatures) | 🚫 | Deniability is a *proof-theoretic property of a protocol run*, not something a single signature call can provide: "deniable" means a third party, given the full transcript, *cannot* mathematically prove which party said what (e.g. because a MAC key both parties know equally could have produced the authentication tag) — which is a property of how an AKE's transcript is constructed end-to-end, not a flag you set. Ring signatures are more primitive-shaped (sign such that a verifier learns "someone in this ring signed" but not who) and could plausibly live in `SignatureFactory`-adjacent code someday, but nothing in this library's current consumer base has asked for the anonymity-set bookkeeping that comes with them. |
| Key-committing AEAD | ✅ | `KeyCommittingAeadEncryptor` (`mystic-crypt`) — closes the "invisible salamanders" gap (a malicious sender crafting one ciphertext that decrypts to *different* valid plaintexts under different keys, relevant to multi-recipient encryption or abuse-reporting re-decryption flows). Adds a BLAKE2b(key‖iv‖associatedData) commitment tag folded into the AAD; wire format is `IV(12) ‖ Ciphertext ‖ CommitmentTag(32)`. Offered as an explicit opt-in class alongside the existing default AES-GCM path (`BaseByteArrayEncryptor`), not a replacement for it. |
| Channel binding (`tls-exporter`/`tls-unique`) | 🚫 | Channel binding only has meaning bound to a *specific, live* TLS connection: `tls-exporter` (RFC 9266) needs the negotiated master secret from an active `SSLSession` to derive its binding value, and `tls-unique` needs the handshake's Finished-message bytes — both require owning the socket that's mid-handshake. `KeyTrustExtensions` deliberately stops at building `KeyManager`/`TrustManager`s for the caller to hand to their own `SSLContext`; it never takes ownership of the resulting `SSLSocket`/`SSLEngine`, so there's no connection object here to extract a binding value from. A consumer doing channel binding would call `sslSession.exportKeyingMaterial(...)`/inspect the Finished message on their own live socket, not through this library. |
| Threshold signatures / MPC (FROST etc.) | 🚫 | Deliberately not implemented. Distinct from Shamir's Secret Sharing above in a way worth being precise about: Shamir SSS *reconstructs* the private key at combine-time (briefly, in memory) — exactly what `ShamirSecretSharingFactory.combine()` does — whereas threshold signing (FROST and friends) produces a valid signature via an interactive multi-round protocol among signers that never assembles the full private key anywhere, not even transiently. That's a strictly stronger security property, but it needs the same kind of multi-round message-exchange support this doc already flags as out of scope for AKE/PAKE above (nonce commitment round, signature-share round, aggregation round) — a real gap only if a multi-party signing use case (e.g. custody/co-signing) ever emerges here. |
| Downgrade attacks (FREAK/Logjam/POODLE/ROBOT) | 🚫 | Every one of these exploited a *cipher-suite negotiation* step: a TLS client and server agree on parameters from a list, and each attack found a way to force that negotiation toward a deliberately weak choice (export-grade RSA for FREAK, weak DH groups for Logjam, SSLv3 fallback for POODLE, PKCS#1 v1.5 padding oracles for ROBOT). This library never negotiates a transformation with a peer — the caller picks `MysticSymmetricAlgorithm.AES_GCM_NO_PADDING` (or any other transformation) directly in code, so there is no negotiation step for an attacker to downgrade. The entire attack class requires a negotiation surface this library structurally doesn't have. |
| Formal verification (ProVerif/Tamarin/CryptoVerif) | 🚫 | These tools symbolically or computationally model a *protocol's message flow* (a Dolev-Yao attacker interacting with a state machine across many messages) to prove properties like secrecy or authentication hold under all possible attacker interleavings — that only applies to something with multi-message protocol structure to model in the first place. This library ships single-call primitives (AES-GCM, Ed25519, X25519+HKDF, Argon2id, Shamir SSS, AES-KW, ML-KEM/ML-DSA/SLH-DSA, J-PAKE), each backed by an algorithm that's already been formally analyzed independently (TLS 1.3's use of X25519+HKDF is Tamarin-verified, for instance) or by a JCA/BC provider implementation with its own test suite — there's no additional protocol-level composition happening *inside this library* for a verifier to model, since composing these primitives into a protocol (with the resulting verification obligation) is exactly the application-level work the 🚫 rows above this one describe. |

---

## Summary: real gaps vs. correctly out of scope

**Every gap identified in the original pass through this document is now closed:** PBKDF2 wiring,
ChaCha20-Poly1305 wiring, the full NIST post-quantum suite (ML-KEM, ML-DSA, SLH-DSA) plus the
X25519+ML-KEM hybrid combiner, key zeroing for password/shared-secret material, PAKE (J-PAKE and
SRP-6a), PKCS#11/HSM provider configuration, BLAKE2, Feldman VSS, key-committing AEAD, and
bcrypt/scrypt are all ✅ — see the tables above for the classes involved, and each item's
commit message for how it was verified before being wired in (this library's standing discipline:
confirm an algorithm/API actually behaves as expected via a throwaway empirical test *before*
writing the real implementation against it, not after).

**Residual, narrower items not pursued further** (each is a real but genuinely marginal
improvement, not a category-level gap):

- **BLAKE3** — no BLAKE3 implementation ships in Bouncy Castle or the JDK; BLAKE2 already covers
  the "modern, fast, non-SHA hash" use case.
- **`MacAlgorithm` has no caller** — the HMAC capability is real (see the row in Part 1), but it is
  reached by passing JDK MAC name strings from `ChecksumCommand`, while the `crypt-api` enum that
  names those same algorithms is referenced from nowhere in the three repos. Wiring the CLI through
  the enum would make an unknown name fail at one documented place instead of at
  `Mac.getInstance`; it is a tidiness item, not a missing capability.
- **Pedersen VSS specifically** (as opposed to Feldman, which is what's actually implemented) —
  would additionally hide the secret from the dealer via a second generator; no current consumer
  need for dealer-blindness specifically.
- **SPAKE2/CPace/OPAQUE specifically** (as opposed to J-PAKE and SRP-6a, which are what's actually
  implemented) — Bouncy Castle ships none of the three, so closing this would mean hand-rolling
  the protocol math with no audited reference implementation to delegate to, a materially higher
  risk undertaking than wrapping an existing BC primitive (see the SRP-6a entry above for what can
  go wrong hand-rolling this class of protocol).

**Everything marked 🚫 is correctly out of scope**, not missing: session/messaging protocols (Signal, MLS, STS, Noise), hardware/platform integrations this library can't portably reach (TPM, secure enclaves, QKD, FIDO2), and infrastructure/policy concerns (key rotation scheduling, certificate pinning policy, key transparency logs). Adding any of those would mean turning a key/data-encryption utility library into a protocol or infrastructure framework — a different, much larger project.

---

## Test quality

How each capability above is verified - test layers, the coverage and mutation-testing numbers
per repo, the independent verification loop that produced them, the bugs that loop caught, and
the deliberate gaps - is documented in [TESTING.md](TESTING.md). The short version: every
primitive has round-trip *and* negative tests, coverage is treated as the floor and
[PIT](https://pitest.org/) mutation score as the bar, and no number in that document was produced
by the same pass that reports it.
