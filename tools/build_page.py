import datetime, html, json, re, sys
from pathlib import Path

# The stylesheet lives next to this script; the page inlines it, so it loads nothing from another host.
CSS = (Path(__file__).resolve().parent / "page.css").read_text(encoding="utf-8")

SITE = "https://astrapi69.github.io/mystic-crypt/"
REPO = "https://github.com/astrapi69/mystic-crypt"
DESCRIPTION = ("Java cryptography library: AES-GCM, Ed25519, X25519, ML-KEM and ML-DSA, "
               "PEM/PKCS#8 and OpenPGP key reading, Argon2id. Requires JDK 25.")
TITLE = "mystic-crypt: Java encryption, signature and key library"
VERSION = "13.8"
RELEASE_CHECKED = "30 October 2026"

FAQ = [
 ("Which Java version does mystic-crypt need?",
  "JDK 25 or newer, both to build and to run. The published jar targets JDK 25 bytecode and will not load on an older JVM."),
 ("Which key and keystore formats does it read and write?",
  "PEM, DER and PKCS#8 private and public keys from OpenSSL or Java, X.509 certificates, and PKCS12, JKS and JCEKS key stores. "
  "A GnuPG key home is read-only: the OpenPGP key reader reads pubring.kbx and the secret-key files through Bouncy Castle, never through gpg."),
 ("Is mystic-crypt post-quantum?",
  "Yes. It includes ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), and a hybrid X25519 plus ML-KEM combiner. "
  "ML-KEM and ML-DSA are provided by the JDK since JDK 24; this library runs on JDK 25 at the earliest, "
  "and there they work without Bouncy Castle registered. SLH-DSA is not in the JDK and needs Bouncy Castle registered as a security provider. "
  "The project does not claim FIPS 140 validation for any module."),
 ("How safe is decrypting Java objects since 13.8?",
  "Objects decrypted by PrivateKeyDecryptor, PrivateKeyGenericDecryptor and GenericObjectDecryptor pass an ObjectInputFilter. "
  "It admits only the classes the caller names, String by default, and bounds depth, references, array length and size. "
  "Callers that decrypt other types name them in the constructors that take a class collection. Java serialization is still the format; replacing it is a later step."),
 ("Can I pass a password on the command line?",
  "The commands read secrets from standard input with their -stdin option, or ask for them in a terminal without echo. "
  "Passing a secret as an argument still works in 13.x, prints a warning, and is removed in 14.0."),
 ("How do I verify a release?",
  "Import the signing key, then run gpg --verify on the .asc file next to the jar. The fingerprints to compare are in the Security section of this page."),
 ("Does the library or this page send data anywhere?",
  "The library opens no network connections; it contains no socket or HTTP client code. This page loads no scripts, fonts, images or trackers from other hosts "
  "and sets no cookies. A link leaves the page only when you follow it."),
]

def faq_json():
    return {"@context": "https://schema.org", "@type": "FAQPage",
            "mainEntity": [{"@type": "Question", "name": q,
                            "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in FAQ]}

def software_json():
    return {"@context": "https://schema.org", "@type": "SoftwareSourceCode",
            "@id": SITE + "#software",
            "name": "mystic-crypt",
            "identifier": "io.github.astrapi69:mystic-crypt",
            "description": DESCRIPTION,
            "url": SITE,
            "codeRepository": REPO,
            "programmingLanguage": {"@type": "ComputerLanguage", "name": "Java"},
            "runtimePlatform": "JDK 25",
            "license": "https://opensource.org/licenses/MIT",
            "author": {"@type": "Person", "name": "Asterios Raptis", "url": "https://github.com/astrapi69"},
            "version": VERSION,
            "sameAs": "https://central.sonatype.com/artifact/io.github.astrapi69/mystic-crypt",
            "keywords": ["Java", "cryptography", "digital signatures", "key agreement", "post-quantum cryptography", "OpenPGP"]}

def ld(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)

def e(t):
    return html.escape(t, quote=False)

FAQ_HTML = "\n".join(
    f'        <h3>{e(q)}</h3>\n        <p>{e(a)}</p>' for q, a in FAQ)

HEAD = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{e(TITLE)}</title>
  <meta name="description" content="{html.escape(DESCRIPTION)}">
  <meta name="robots" content="index, follow">
  <link rel="canonical" href="{SITE}">
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' rx='3' fill='%235b3cc4'/%3E%3Ctext x='8' y='12' font-size='11' text-anchor='middle' fill='white' font-family='monospace'%3Em%3C/text%3E%3C/svg%3E">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="mystic-crypt">
  <meta property="og:title" content="{html.escape(TITLE)}">
  <meta property="og:description" content="{html.escape(DESCRIPTION)}">
  <meta property="og:url" content="{SITE}">
  <meta property="og:image" content="{SITE}og-image.png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="mystic-crypt: Java encryption, signature and key library">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="{html.escape(TITLE)}">
  <meta name="twitter:description" content="{html.escape(DESCRIPTION)}">
  <meta name="twitter:image" content="{SITE}og-image.png">
  <meta name="twitter:image:alt" content="mystic-crypt: Java encryption, signature and key library">
  <script type="application/ld+json">
{ld(software_json())}
  </script>
  <script type="application/ld+json">
{ld(faq_json())}
  </script>
  <style>{CSS}</style>
</head>
"""

HEADER = f"""<body>
  <header class="site">
    <div class="wrap">
      <a class="brand" href="#top">mystic-crypt</a>
      <nav aria-label="Sections">
        <a href="#getting-started">Getting started</a>
        <a href="#quick-start">Examples</a>
        <a href="#features">Features</a>
        <a href="#cli">Command line</a>
        <a href="#faq">FAQ</a>
        <a href="#security">Security</a>
        <a href="#docs">Documentation</a>
      </nav>
    </div>
  </header>

  <main id="top">
    <section class="hero">
      <div class="wrap">
        <h1>mystic-crypt: a Java cryptography library</h1>
        <p class="lead">Encryption, password hashing, digital signatures, key agreement and post-quantum
          algorithms for Java 25, built on the JDK and Bouncy Castle. It reads PEM and PKCS#8 keys and
          OpenPGP key homes, and it ships a command line tool.</p>
        <p class="meta-line">Current release {VERSION} on Maven Central, checked {RELEASE_CHECKED}. License: MIT.</p>
        <div class="badges">
          <a href="https://central.sonatype.com/artifact/io.github.astrapi69/mystic-crypt">Maven Central</a>
          <a href="{REPO}">Source on GitHub</a>
          <a href="https://www.javadoc.io/doc/io.github.astrapi69/mystic-crypt">Javadoc</a>
          <a href="{REPO}/blob/develop/CHANGELOG.md">Changelog</a>
          <a href="{REPO}/blob/develop/LICENSE">MIT license</a>
        </div>
        <div class="actions">
          <a class="btn primary" href="#getting-started">Get started</a>
          <a class="btn" href="{REPO}">View the source</a>
        </div>
      </div>
    </section>

    <section id="getting-started">
      <div class="wrap">
        <h2>Getting started</h2>
        <p>Requires JDK 25 or newer, at build and at runtime. Add the library with the current release
          {VERSION} from Maven Central. Version 13.9 is in development and is not published yet.</p>

        <h3>Gradle</h3>
        <pre><code>dependencies {{
    implementation "io.github.astrapi69:mystic-crypt:{VERSION}"
}}</code></pre>

        <h3>Maven</h3>
        <pre><code>&lt;dependency&gt;
    &lt;groupId&gt;io.github.astrapi69&lt;/groupId&gt;
    &lt;artifactId&gt;mystic-crypt&lt;/artifactId&gt;
    &lt;version&gt;{VERSION}&lt;/version&gt;
&lt;/dependency&gt;</code></pre>

        <h3>Command line</h3>
        <p>The published <code>-all</code> jar runs the command line tool. Pass secrets through standard input
          rather than as arguments, because an argument is visible to other processes and lands in the shell history:</p>
        <pre><code>java -jar mystic-crypt-{VERSION}-all.jar hash --password-stdin &lt; password.txt</code></pre>
      </div>
    </section>

    <section id="quick-start">
      <div class="wrap">
        <h2>Quick start</h2>
        <p>Every example below is compiled and run by
          <a href="{REPO}/blob/develop/src/test/java/io/github/astrapi69/mystic/crypt/ReadmeExamplesTest.java">ReadmeExamplesTest</a>.</p>

        <h3>Encrypt and decrypt data</h3>
        <p>AES-256-GCM with a fresh random nonce per call, prepended to the ciphertext:</p>
<pre><code>SecretKey key = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 256);

byte[] encrypted = new BaseByteArrayEncryptor(key)
    .encrypt("attack at dawn".getBytes(StandardCharsets.UTF_8));
byte[] decrypted = new BaseByteArrayDecryptor(key).decrypt(encrypted);</code></pre>

        <h3>Store a password</h3>
        <p>Argon2id with a random salt; the salt and all parameters travel inside the returned string:</p>
<pre><code>PasswordEncryptor passwordEncryptor = PasswordEncryptor.getInstance();

String stored = passwordEncryptor.hashPasswordArgon2id("correct horse battery staple");

boolean ok = passwordEncryptor.matchArgon2id("correct horse battery staple", stored);</code></pre>

        <h3>Sign and verify</h3>
        <p>Ed25519 signatures:</p>
<pre><code>KeyPair keyPair = Ed25519Signer.newKeyPair();
byte[] document = "release 11.0.0".getBytes(StandardCharsets.UTF_8);

byte[] signature = new Ed25519Signer(keyPair.getPrivate()).sign(document);

boolean valid = new Ed25519Verifier(keyPair.getPublic()).verify(document, signature);</code></pre>

        <h3>Agree on a shared key</h3>
        <p>X25519 Diffie-Hellman, with the raw shared secret run through HKDF rather than used directly:</p>
<pre><code>KeyPair alice = X25519KeyExchange.newKeyPair();
KeyPair bob = X25519KeyExchange.newKeyPair();

SecretKey aliceSecret = X25519KeyExchange.deriveSharedSecret(alice.getPrivate(), bob.getPublic(), 32);
SecretKey bobSecret = X25519KeyExchange.deriveSharedSecret(bob.getPrivate(), alice.getPublic(), 32);
// aliceSecret and bobSecret are equal</code></pre>

        <h3>Post-quantum key encapsulation</h3>
        <p>ML-KEM (FIPS 203). <code>HybridKemKeyExchange</code> combines X25519 and ML-KEM and stays
          secure as long as <em>either</em> half is unbroken:</p>
<pre><code>KeyPair recipient = MlKemKeyExchange.newKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);

MlKemKeyExchange.Encapsulation sent =
    MlKemKeyExchange.encapsulate(recipient.getPublic(), KeyPairGeneratorAlgorithm.ML_KEM_768);
SecretKey received = MlKemKeyExchange.decapsulate(recipient.getPrivate(),
    sent.getCiphertext(), KeyPairGeneratorAlgorithm.ML_KEM_768);
// sent.getSharedSecret() and received are equal</code></pre>

        <h3>Hash</h3>
<pre><code>byte[] digest = Sha3Hasher.hashUtf8("hello", MessageDigestAlgorithm.SHA3_256);</code></pre>
      </div>
    </section>

    <section id="features">
      <div class="wrap">
        <h2>Features</h2>
        <div class="grid">
          <div class="card">
            <h3>Symmetric encryption and files</h3>
            <p>AES-GCM and ChaCha20-Poly1305 with a fresh nonce per call, for byte arrays, strings, files,
              streams and serializable objects. Chainable encryptors, hex-encoded variants, key-committing
              AEAD against the "invisible salamanders" attack. Files and text can be encrypted with a
              passphrase (AES-GCM, PBKDF2-HMAC-SHA256) from the command line.</p>
          </div>
          <div class="card">
            <h3>Password hashing</h3>
            <p>Argon2id (recommended), PBKDF2-HMAC-SHA256, bcrypt and scrypt for interop. Salt and
              parameters are encoded with the hash; comparisons are constant-time.</p>
          </div>
          <div class="card">
            <h3>Keys, certificates and key stores</h3>
            <p>RSA hybrid encryption, Ed25519 and ML-DSA signatures, X25519 key agreement with HKDF, key pair
              generation, PEM, DER and PKCS#8 key files from OpenSSL or Java, X.509 certificates, and PKCS12,
              JKS and JCEKS key stores. Read-only reading of an OpenPGP key home, never through gpg. Ed25519 key
              blinding and SLIP-0010 seed derivation.</p>
          </div>
          <div class="card">
            <h3>Post-quantum</h3>
            <p>ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and a hybrid X25519 plus ML-KEM
              combiner for the transition period.</p>
          </div>
          <div class="card">
            <h3>Hashing</h3>
            <p>SHA-2, SHA-3, BLAKE2b and BLAKE2s including keyed (MAC) mode, HMAC as one call, file and
              object checksums.</p>
          </div>
          <div class="card">
            <h3>Secret sharing and PAKE</h3>
            <p>Shamir's Secret Sharing, Feldman verifiable secret sharing, J-PAKE and SRP-6a, AES key wrap,
              PKCS#11 and HSM provider configuration.</p>
          </div>
        </div>
        <p>The <a href="{REPO}/blob/develop/docs/CRYPTO_CAPABILITIES.md">capability matrix</a> lists every
          algorithm with the classes involved, and what is deliberately not implemented, and why.</p>
      </div>
    </section>

    <section id="cli">
      <div class="wrap">
        <h2>Command line</h2>
        <p>The published <code>-all</code> artifact is a runnable jar:</p>
        <pre><code>java -jar mystic-crypt-{VERSION}-all.jar --help
java -jar mystic-crypt-{VERSION}-all.jar hash --password-stdin &lt; password.txt
java -jar mystic-crypt-{VERSION}-all.jar checksum --file build.gradle --algorithm SHA-256</code></pre>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Command</th><th>Description</th></tr></thead>
            <tbody>
              <tr><td><code>hash</code></td><td>Hash a password with Argon2id or PBKDF2 and print the encoded hash</td></tr>
              <tr><td><code>verify</code></td><td>Verify a password against an encoded hash (exit code 0 = match)</td></tr>
              <tr><td><code>keygen</code></td><td>Generate a key pair and print or write it as PEM</td></tr>
              <tr><td><code>kem</code></td><td>Run an ML-KEM or hybrid X25519+ML-KEM encapsulation between two parties</td></tr>
              <tr><td><code>checksum</code></td><td>Compute the checksum of a file</td></tr>
              <tr><td><code>der2pem</code></td><td>Convert a DER-encoded private key to PEM</td></tr>
              <tr><td><code>cert</code></td><td>Create a self-signed X.509 certificate</td></tr>
              <tr><td><code>keystore</code></td><td>Manage a PKCS12, JKS or JCEKS key store: list, create, add-keypair, import-cert, export-cert, delete</td></tr>
              <tr><td><code>sign</code></td><td>Sign a file or stdin with an Ed25519, ML-DSA or SLH-DSA private key (PEM)</td></tr>
              <tr><td><code>verify-signature</code></td><td>Verify such a signature; exit code 0 = valid, 1 = invalid, 2 = error</td></tr>
              <tr><td><code>obfuscate</code> / <code>disentangle</code></td><td>Obfuscate text with a substitution map, and recover it</td></tr>
              <tr><td><code>encrypt</code> / <code>decrypt</code></td><td>Encrypt a file or a text with a passphrase (AES-GCM, PBKDF2-HMAC-SHA256), and decrypt it again</td></tr>
              <tr><td><code>share</code></td><td>Split a secret into shares and combine them back (Shamir secret sharing)</td></tr>
              <tr><td><code>keyx</code></td><td>Exchange a shared secret with another person: <code>new</code> on the recipient's side, <code>send</code> on the sender's, <code>receive</code> back on the recipient's</td></tr>
              <tr><td><code>convert</code></td><td>Say what a key or certificate file is, and convert it between PEM and DER or between PKCS#1 and PKCS#8</td></tr>
              <tr><td><code>release-key</code></td><td>Read the state of an OpenPGP release key in a GnuPG home: <code>status</code>, with <code>--home</code>, <code>--key</code> and <code>--json</code>. Only reads</td></tr>
            </tbody>
          </table>
        </div>
        <p>A desktop application that uses this library is <a href="https://github.com/astrapi69/mystic-crypt-ui">mystic-crypt-ui</a>, a separate project.</p>
      </div>
    </section>

    <section id="faq" class="faq">
      <div class="wrap">
        <h2>Frequently asked questions</h2>
{FAQ_HTML}
      </div>
    </section>

    <section id="security">
      <div class="wrap">
        <h2>Security</h2>
        <p>Report a vulnerability through GitHub's private vulnerability reporting, not as a public issue.
          <a href="{REPO}/blob/develop/SECURITY.md">SECURITY.md</a> names the supported lines (currently 13.x)
          and what happens after a report.</p>

        <h3>Known advisories and fixes</h3>
        <p>Up to 13.7, <code>PrivateKeyDecryptor</code>, <code>PrivateKeyGenericDecryptor</code> and
          <code>GenericObjectDecryptor</code> built whatever classes the ciphertext named, without a filter
          (GHSA-87j9-xjf5-f387). 13.8 fixes this. The <a href="{REPO}/blob/develop/CHANGELOG.md">changelog</a>
          describes the fix and what callers must change.</p>

        <h3>Verify a release signature</h3>
        <p>Since 13.6 the releases are signed by a signing subkey. Import the key once, then verify the signature
          next to the jar:</p>
        <pre><code>gpg --keyserver hkps://keys.openpgp.org --recv-keys 5B2FA6B11E298BC09287F423D8C403518C49CA75
gpg --verify mystic-crypt-{VERSION}.jar.asc mystic-crypt-{VERSION}.jar</code></pre>
        <p>The primary key fingerprint must be <code>5B2F A6B1 1E29 8BC0 9287 F423 D8C4 0351 8C49 CA75</code>,
          and for a release signed by the subkey its fingerprint must be
          <code>6D67 F844 2A6F CC96 BD7C 1B5E 9FCF 7C97 10E2 BD8D</code>.
          The <a href="{REPO}#verifying-the-release-signatures">README</a> explains the trust warning gpg prints.</p>
      </div>
    </section>

    <section id="docs">
      <div class="wrap">
        <h2>Documentation</h2>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Document</th><th>What it covers</th></tr></thead>
            <tbody>
              <tr><td><a href="{REPO}/blob/develop/docs/CRYPTO_CAPABILITIES.md">Capability matrix</a></td><td>Every algorithm, its class, and what is out of scope, with reasons</td></tr>
              <tr><td><a href="{REPO}/blob/develop/docs/TESTING.md">Testing strategy</a></td><td>How the library is tested, the coverage and mutation numbers, and the defects the process caught</td></tr>
              <tr><td><a href="{REPO}/blob/develop/docs/COVERAGE_EXCEPTIONS.md">Coverage exceptions</a></td><td>Every uncovered line and surviving mutant, with its reason</td></tr>
              <tr><td><a href="{REPO}/blob/develop/docs/KEY_AGREEMENT_EVOLUTION.md">Key agreement, explained</a></td><td>From book ciphers to the Double Ratchet</td></tr>
              <tr><td><a href="{REPO}/blob/develop/CHANGELOG.md">Changelog</a></td><td>What changed in each release</td></tr>
              <tr><td><a href="{REPO}/releases">GitHub releases</a></td><td>Release notes and the tags</td></tr>
              <tr><td><a href="https://www.javadoc.io/doc/io.github.astrapi69/mystic-crypt">Javadoc</a></td><td>API reference</td></tr>
              <tr><td><a href="{REPO}/wiki">Wiki</a></td><td>Task-oriented guides</td></tr>
            </tbody>
          </table>
        </div>

        <h3>The crypt family</h3>
        <p>mystic-crypt is the top of a three-repository stack: <a href="https://github.com/astrapi69/crypt-api">crypt-api</a>
          holds the algorithm constants and interfaces, <a href="https://github.com/astrapi69/crypt-data">crypt-data</a>
          the factories, readers, writers and models, and mystic-crypt the ready-to-use encryptors.</p>
      </div>
    </section>

    <section id="quality">
      <div class="wrap">
        <h2>Quality</h2>
        <p>The release gate is 100% branch coverage plus PIT mutation testing, and every uncovered line and
          surviving mutant has a stated reason. The measured numbers, with the commit they were measured on,
          are in <a href="{REPO}/blob/develop/docs/TESTING.md">docs/TESTING.md</a>.</p>
      </div>
    </section>

    <section id="contributing">
      <div class="wrap">
        <h2>Contributing</h2>
        <p>Pull requests are welcome: fork <a href="{REPO}/fork">astrapi69/mystic-crypt</a> and open a PR against
          <a href="{REPO}/pull/new/develop">develop</a>. Please add tests for your change; the
          <a href="{REPO}/blob/develop/docs/TESTING.md#conventions-for-contributors">conventions for contributors</a>
          describe what a good test looks like here.</p>
        <pre><code>./gradlew build            # tests + coverage + formatting check
./gradlew spotlessApply    # fix formatting
./gradlew pitest           # mutation testing (opt-in, minutes)</code></pre>
        <p>Questions, bug reports and feature requests belong on the <a href="{REPO}/issues">issues page</a>.</p>
      </div>
    </section>

    <section id="support">
      <div class="wrap">
        <h2>Support this project</h2>
        <p>If mystic-crypt is useful to you, a star on GitHub helps others find it. Sharing it or reporting a bug
          helps just as much. Financial support is possible through
          <a href="https://github.com/sponsors/astrapi69">GitHub Sponsors</a>,
          <a href="https://liberapay.com/astrapi69">Liberapay</a>,
          <a href="https://ko-fi.com/astrapi69">Ko-fi</a> and
          <a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=GVBTWLRAZ7HB8">PayPal</a>.</p>
      </div>
    </section>
  </main>

  <footer>
    <div class="wrap">
      <p>This page loads no scripts, fonts, images or trackers from other hosts, sets no cookies and runs no
        analytics. A link leaves the page only when you follow it.</p>
      <p class="foot-links">mystic-crypt is released under the <a href="{REPO}/blob/develop/LICENSE">MIT License</a>.
        <a href="{REPO}/tree/gh-pages">Source of this page</a></p>
      <p>No animals were harmed in the making of this library.</p>
    </div>
  </footer>
</body>
</html>
"""

# The page and its sitemap are written from this script only. lastmod in the sitemap moves to
# today's date when the page content changes, and stays when it does not.
ROOT = Path(__file__).resolve().parent.parent
SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>{loc}</loc>
    <lastmod>{lastmod}</lastmod>
  </url>
</urlset>
"""

def current_lastmod(sitemap_path):
    match = re.search(r"<lastmod>(\d{4}-\d{2}-\d{2})</lastmod>", sitemap_path.read_text(encoding="utf-8")) if sitemap_path.exists() else None
    return match.group(1) if match else None

out = HEAD + HEADER
index_path = ROOT / "index.html"
sitemap_path = ROOT / "sitemap.xml"
previous = index_path.read_text(encoding="utf-8") if index_path.exists() else None
lastmod = current_lastmod(sitemap_path) if previous == out else None
if lastmod is None:
    lastmod = datetime.date.today().isoformat()
index_path.write_text(out, encoding="utf-8")
sitemap_path.write_text(SITEMAP.format(loc=SITE, lastmod=lastmod), encoding="utf-8")
print("index.html", len(out.encode("utf-8")), "bytes; sitemap lastmod", lastmod)
