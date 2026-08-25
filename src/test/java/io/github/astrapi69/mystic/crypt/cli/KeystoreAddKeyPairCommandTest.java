/*
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.mystic.crypt.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@code keystore add-keypair} subcommand.
 */
class KeystoreAddKeyPairCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private File createStore(File tempDir, String type)
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret"));
		return storeFile;
	}

	private KeyStore load(File storeFile, String type) throws Exception
	{
		KeyStore keyStore = KeyStore.getInstance(type);
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
		return keyStore;
	}

	/**
	 * One add-keypair case: the key algorithm as the user would type it and the store type the
	 * entry goes into. The classical algorithms are exercised against every store type, the
	 * post-quantum ML-DSA parameter sets against PKCS12.
	 */
	record AddCase(String algorithm, String type) {
	}

	static Stream<AddCase> addCases()
	{
		return Stream.of(new AddCase("RSA", "PKCS12"), new AddCase("RSA", "JKS"),
			new AddCase("RSA", "JCEKS"), new AddCase("EC", "PKCS12"), new AddCase("DSA", "PKCS12"),
			new AddCase("ML-DSA-44", "PKCS12"), new AddCase("ML-DSA-65", "PKCS12"),
			new AddCase("ML-DSA-87", "PKCS12"),
			// dashes and underscores as well as lower case are accepted alike
			new AddCase("ml_dsa_65", "PKCS12"));
	}

	@ParameterizedTest
	@MethodSource("addCases")
	void addsAKeyPairWithASelfSignedCertificate(AddCase testCase, @TempDir File tempDir)
		throws Exception
	{
		File storeFile = createStore(tempDir, testCase.type());
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--type",
				testCase.type(), "--password", "secret", "--alias", "my-key", "--dname",
				"CN=add-keypair-test", "--algorithm", testCase.algorithm()));
		assertTrue(out.contains("added 'my-key'"),
			"stdout must confirm the new alias, but was: '" + out + "'");

		KeyStore keyStore = load(storeFile, testCase.type());
		assertTrue(keyStore.isKeyEntry("my-key"), "the alias must hold a private key entry");
		Key key = keyStore.getKey("my-key", "secret".toCharArray());
		assertNotNull(key, "the private key must be readable with the store password");
		X509Certificate certificate = (X509Certificate)keyStore.getCertificate("my-key");
		assertTrue(certificate.getSubjectX500Principal().getName().contains("add-keypair-test"),
			"the self-signed certificate must carry the requested subject");
		assertEquals(certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal(),
			"subject and issuer must be the same (self-signed)");
	}

	@Test
	void theKeySizeOptionIsApplied(@TempDir File tempDir) throws Exception
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "sized", "--dname", "CN=sized", "--algorithm", "RSA",
				"--key-size", "3072"));

		Key key = load(storeFile, "PKCS12").getKey("sized", "secret".toCharArray());
		assertEquals(3072, ((RSAKey)key).getModulus().bitLength(),
			"the generated RSA key must have the requested size");
	}

	@Test
	void theValidityPeriodOptionIsApplied(@TempDir File tempDir) throws Exception
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "short-lived", "--dname", "CN=short-lived", "--algorithm",
				"EC", "--days-valid", "10"));

		X509Certificate certificate = (X509Certificate)load(storeFile, "PKCS12")
			.getCertificate("short-lived");
		Instant notAfter = certificate.getNotAfter().toInstant();
		assertTrue(notAfter.isAfter(Instant.now().plus(9, ChronoUnit.DAYS)),
			"the certificate must be valid for about ten days");
		assertTrue(notAfter.isBefore(Instant.now().plus(11, ChronoUnit.DAYS)),
			"the certificate must not be valid for longer than the requested ten days");
	}

	@Test
	void thePasswordCanComeFromStandardInput(@TempDir File tempDir) throws Exception
	{
		File storeFile = createStore(tempDir, "PKCS12");
		// the password is used twice (opening and storing) but standard input yields it only
		// once - this breaks if the resolved password is not cached
		assertEquals(0,
			runWithStdin("secret\n", "keystore", "add-keypair", "--file",
				storeFile.getAbsolutePath(), "--password-stdin", "--alias", "stdin-key", "--dname",
				"CN=stdin", "--algorithm", "EC"));
		assertTrue(load(storeFile, "PKCS12").isKeyEntry("stdin-key"));
	}

	/**
	 * An RSASSA-PSS key is certified with a PSS signature: a certificate signed PKCS#1 v1.5 by a
	 * key whose SubjectPublicKeyInfo carries the id-RSASSA-PSS OID violates RFC 4055 and is
	 * rejected by strict verifiers such as OpenSSL.
	 */
	@Test
	void anRsassaPssKeyGetsAPssSignedCertificate(@TempDir File tempDir) throws Exception
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "pss", "--dname", "CN=pss", "--algorithm", "RSASSA-PSS"));

		X509Certificate certificate = (X509Certificate)load(storeFile, "PKCS12")
			.getCertificate("pss");
		assertEquals("1.2.840.113549.1.1.10", certificate.getSigAlgOID(),
			"the certificate must be signed with RSASSA-PSS, not PKCS#1 v1.5");
		// the self-signed certificate must verify against its own key
		certificate.verify(certificate.getPublicKey());
	}

	/** Mirrors the UI plugin's invocation without --dname and --algorithm. */
	@Test
	void dnameAndAlgorithmHaveDefaults(@TempDir File tempDir) throws Exception
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertEquals(0, run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(),
			"--password", "secret", "--alias", "defaults"));
		assertTrue(out.contains("added 'defaults' (RSA)"),
			"the default key algorithm must be RSA, but the output was: '" + out + "'");

		X509Certificate certificate = (X509Certificate)load(storeFile, "PKCS12")
			.getCertificate("defaults");
		assertTrue(certificate.getSubjectX500Principal().getName().contains("CN=mystic-crypt"),
			"the default subject must be CN=mystic-crypt");
	}

	/**
	 * Re-running add-keypair with an existing alias must fail instead of silently and irreversibly
	 * replacing the stored private key.
	 */
	@Test
	void anExistingAliasIsNotOverwritten(@TempDir File tempDir) throws Exception
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "precious", "--dname", "CN=precious", "--algorithm", "EC"));
		Key original = load(storeFile, "PKCS12").getKey("precious", "secret".toCharArray());

		assertNotEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "precious", "--dname", "CN=precious", "--algorithm", "EC"));
		assertTrue(err.contains("already exists"),
			"the error must say the alias already exists, but was: '" + err + "'");
		Key untouched = load(storeFile, "PKCS12").getKey("precious", "secret".toCharArray());
		assertEquals(original, untouched, "the stored private key must stay untouched");
	}

	/**
	 * {@code --key-size} must not be silently ignored for algorithms with a fixed parameter set.
	 */
	@Test
	void keySizeWithASizeFreeAlgorithmFails(@TempDir File tempDir)
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertNotEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "ec", "--dname", "CN=ec", "--algorithm", "EC", "--key-size",
				"256"));
		assertTrue(err.contains("--key-size only applies"),
			"the error must say --key-size does not apply, but was: '" + err + "'");
	}

	/**
	 * Key-exchange algorithms cannot sign the self-signed certificate and must be rejected with a
	 * clear message instead of being mapped silently to some signature algorithm.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "X25519", "X448", "ML-KEM-768" })
	void keyExchangeAlgorithmsAreRejected(String algorithm, @TempDir File tempDir)
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertNotEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "nope", "--dname", "CN=nope", "--algorithm", algorithm));
		assertTrue(err.contains("cannot sign a certificate"),
			"the error must say why '" + algorithm + "' is rejected, but was: '" + err + "'");
	}

	@Test
	void anUnknownAlgorithmFails(@TempDir File tempDir)
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertNotEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "nope", "--dname", "CN=nope", "--algorithm", "NOPE"));
		assertTrue(err.contains("unknown key algorithm"),
			"the error must name the unknown algorithm, but was: '" + err + "'");
	}

	@Test
	void aWrongStorePasswordFails(@TempDir File tempDir)
	{
		File storeFile = createStore(tempDir, "PKCS12");
		assertNotEquals(0, run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(),
			"--password", "wrong", "--alias", "my-key", "--dname", "CN=x", "--algorithm", "EC"));
	}

	@Test
	void aMissingRequiredOptionFails(@TempDir File tempDir)
	{
		File storeFile = createStore(tempDir, "PKCS12");
		// --alias is missing
		assertNotEquals(0, run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(),
			"--password", "secret", "--dname", "CN=x", "--algorithm", "EC"));
	}
}
