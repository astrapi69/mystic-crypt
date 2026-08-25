# Library first - the implementation hierarchy

Before writing any new utility, walk this hierarchy top-down and stop at the
first level that fits. The PR/commit documents WHY a lower level was chosen.

## 0. Never implement cryptographic primitives yourself

Ciphers, hashes, signatures, KDFs, random generation, padding, encodings of
key material: always the JDK or Bouncy Castle. Own code only orchestrates
proven primitives. This level has no exceptions.

## 1. JDK first

`java.security`, `javax.crypto`, `java.util.HexFormat`, `java.nio.file`,
`MessageDigest.isEqual` (constant-time comparison), records, switch
expressions. The JDK has grown: Ed25519 since 15, ML-KEM/ML-DSA since 24 -
check before assuming Bouncy Castle is needed.

## 2. Bouncy Castle

For what the JDK lacks (SLH-DSA, PEM/PKCS parsing via bcpkix, X.509
building). Registered once via `SecurityProviderSupport.ensureBouncyCastle()`.

## 3. The crypt family and existing io.github.astrapi69 libraries

crypt-api (interfaces/enums), crypt-data (factories, readers, writers,
extensions), then the wider silly-*/file-worker family. Check what exists
before duplicating it here - but verify the API is actually usable from a
JPMS module (exported package) and behaves correctly; a family API with a
defect (e.g. a helper hardcoding a store type) is fixed at its source or
consciously worked around with a comment saying why.

## 4. A new dependency

Only after asking, and only if 1-3 do not fit: maintained (recent releases),
no known CVEs, sane transitive footprint, JPMS-capable (module or at least
automatic module name).

## 5. Write it yourself

Smallest scope that works, library-grade (own tests, javadoc, no incidental
coupling), and the reason documented in the PR.
