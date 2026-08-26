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
package io.github.astrapi69.mystic.crypt.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for {@link KeyFileReader}: the shapes a key file arrives in, and what it says about
 * the ones it cannot read.
 */
class KeyFileReaderTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static KeyPair rsaKeyPair() throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private static File armoured(File tempDir, String name, String label, byte[] encoded)
		throws Exception
	{
		File file = new File(tempDir, name);
		String base64 = Base64
			.getMimeEncoder(64, System.lineSeparator().getBytes(StandardCharsets.US_ASCII))
			.encodeToString(encoded);
		Files.writeString(file.toPath(),
			"-----BEGIN " + label + "-----" + System.lineSeparator() + base64
				+ System.lineSeparator() + "-----END " + label + "-----" + System.lineSeparator(),
			StandardCharsets.UTF_8);
		return file;
	}

	@Test
	void readsAPkcs8PrivateKeyPem(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = rsaKeyPair();
		File pem = armoured(tempDir, "pkcs8.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded());

		assertTrue(KeyFileReader.isPem(pem));
		assertArrayEquals(keyPair.getPrivate().getEncoded(),
			KeyFileReader.readPrivateKey(pem, "RSA").getEncoded());
	}

	@Test
	void readsAPublicKeyPem(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = rsaKeyPair();
		File pem = armoured(tempDir, "public.pem", "PUBLIC KEY", keyPair.getPublic().getEncoded());

		assertArrayEquals(keyPair.getPublic().getEncoded(),
			KeyFileReader.readPublicKey(pem, "RSA").getEncoded());
	}

	@Test
	void readsBothHalvesFromDer(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = rsaKeyPair();
		File privateDer = new File(tempDir, "private.der");
		File publicDer = new File(tempDir, "public.der");
		Files.write(privateDer.toPath(), keyPair.getPrivate().getEncoded());
		Files.write(publicDer.toPath(), keyPair.getPublic().getEncoded());

		assertFalse(KeyFileReader.isPem(privateDer), "a DER file carries no armour");
		assertArrayEquals(keyPair.getPrivate().getEncoded(),
			KeyFileReader.readPrivateKey(privateDer, "RSA").getEncoded());
		assertArrayEquals(keyPair.getPublic().getEncoded(),
			KeyFileReader.readPublicKey(publicDer, "RSA").getEncoded());
	}

	/**
	 * A traditional PKCS#1 PEM holds the whole key pair, so it answers both "what is the private
	 * key" and "what is the public half".
	 */
	@Test
	void aKeyPairPemAnswersForBothHalves(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = rsaKeyPair();
		byte[] pkcs1 = org.bouncycastle.asn1.pkcs.PrivateKeyInfo
			.getInstance(keyPair.getPrivate().getEncoded()).parsePrivateKey().toASN1Primitive()
			.getEncoded();
		File pem = armoured(tempDir, "pkcs1.pem", "RSA PRIVATE KEY", pkcs1);

		assertArrayEquals(keyPair.getPrivate().getEncoded(),
			KeyFileReader.readPrivateKey(pem, "RSA").getEncoded());
		assertArrayEquals(keyPair.getPublic().getEncoded(),
			KeyFileReader.readPublicKey(pem, "RSA").getEncoded());
	}

	@Test
	void aPublicKeyWhereAPrivateOneBelongsIsNamedByWhatItHolds(@TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = rsaKeyPair();
		File pem = armoured(tempDir, "public.pem", "PUBLIC KEY", keyPair.getPublic().getEncoded());

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPrivateKey(pem, "RSA"));

		assertTrue(rejected.getMessage().contains("not a private key"),
			"the message must say what the file holds instead, but was: '" + rejected.getMessage()
				+ "'");
	}

	@Test
	void aPrivateKeyWhereAPublicOneBelongsIsNamedByWhatItHolds(@TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = rsaKeyPair();
		File pem = armoured(tempDir, "pkcs8.pem", "PRIVATE KEY", keyPair.getPrivate().getEncoded());

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPublicKey(pem, "RSA"));

		assertTrue(rejected.getMessage().contains("not a public key"),
			"the message was: '" + rejected.getMessage() + "'");
	}

	@Test
	void aPemWithNoObjectInItIsNamedAsSuch(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "empty.pem");
		Files.writeString(pem.toPath(), "-----BEGIN NOTHING-----" + System.lineSeparator(),
			StandardCharsets.UTF_8);

		IllegalArgumentException asPrivate = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPrivateKey(pem, "RSA"));
		IllegalArgumentException asPublic = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPublicKey(pem, "RSA"));

		assertTrue(asPrivate.getMessage().contains("PEM object"),
			"the message was: '" + asPrivate.getMessage() + "'");
		assertTrue(asPublic.getMessage().contains("PEM object"),
			"the message was: '" + asPublic.getMessage() + "'");
	}

	@Test
	void aPemHoldingSomethingElseEntirelyIsNamedByItsType(@TempDir File tempDir) throws Exception
	{
		// a certificate signing request is a well formed PEM object that is not a key at all
		File pem = armoured(tempDir, "other.pem", "CERTIFICATE REQUEST",
			new byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 });

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPrivateKey(pem, "RSA"));

		assertTrue(rejected.getMessage().contains("PEM object"),
			"a body that does not match its armour is still 'this file is not that key', but the "
				+ "message was: '" + rejected.getMessage() + "'");
	}

	@Test
	void bytesThatAreNeitherPemNorDerAreNamedWithTheAlgorithmThatWasExpected(@TempDir File tempDir)
		throws Exception
	{
		File rubbish = new File(tempDir, "rubbish.bin");
		Files.write(rubbish.toPath(), new byte[] { 1, 2, 3, 4, 5 });

		IllegalArgumentException asPrivate = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPrivateKey(rubbish, "RSA"));
		IllegalArgumentException asPublic = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPublicKey(rubbish, "RSA"));

		assertTrue(asPrivate.getMessage().contains("RSA private key"),
			"the message was: '" + asPrivate.getMessage() + "'");
		assertTrue(asPublic.getMessage().contains("RSA public key"),
			"the message was: '" + asPublic.getMessage() + "'");
	}

	@Test
	void anEmptyFileIsNotMistakenForPem(@TempDir File tempDir) throws Exception
	{
		File empty = new File(tempDir, "empty.bin");
		Files.write(empty.toPath(), new byte[0]);

		assertFalse(KeyFileReader.isPem(empty));
		assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPrivateKey(empty, "RSA"));
	}

	/**
	 * A key of an algorithm no provider knows parses fine - the ASN.1 is well formed - and fails
	 * only when the converter tries to build a key out of it. Bouncy Castle answers "no such
	 * algorithm: 1.2.3.4.5.6.7", which has to reach the caller as a statement about this file.
	 */
	@Test
	void aKeyOfAnAlgorithmNoProviderKnowsIsReportedAgainstTheFile(@TempDir File tempDir)
		throws Exception
	{
		AlgorithmIdentifier unknown = new AlgorithmIdentifier(
			new ASN1ObjectIdentifier("1.2.3.4.5.6.7"));
		File privatePem = armoured(tempDir, "unknown-private.pem", "PRIVATE KEY",
			new PrivateKeyInfo(unknown, new DEROctetString(new byte[] { 1, 2, 3 })).getEncoded());
		File publicPem = armoured(tempDir, "unknown-public.pem", "PUBLIC KEY",
			new SubjectPublicKeyInfo(unknown, new byte[] { 1, 2, 3 }).getEncoded());

		IllegalArgumentException asPrivate = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPrivateKey(privatePem, "RSA"));
		IllegalArgumentException asPublic = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPublicKey(publicPem, "RSA"));

		assertTrue(asPrivate.getMessage().contains("unknown-private.pem"),
			"the message must name the file, but was: '" + asPrivate.getMessage() + "'");
		assertTrue(asPublic.getMessage().contains("unknown-public.pem"),
			"the message must name the file, but was: '" + asPublic.getMessage() + "'");
	}

	/**
	 * A stray BEGIN marker inside ordinary text is enough to look like PEM but parses to nothing,
	 * and that has to read as "no PEM object" rather than as a null slipping through.
	 */
	@Test
	void textThatOnlyLooksLikePemHoldsNoPemObject(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "looks-like.pem");
		Files.writeString(pem.toPath(), "text -----BEGIN something odd" + System.lineSeparator()
			+ "more text" + System.lineSeparator(), StandardCharsets.UTF_8);

		assertTrue(KeyFileReader.isPem(pem));
		IllegalArgumentException asPrivate = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPrivateKey(pem, "RSA"));
		IllegalArgumentException asPublic = assertThrows(IllegalArgumentException.class,
			() -> KeyFileReader.readPublicKey(pem, "RSA"));

		assertTrue(asPrivate.getMessage().contains("no PEM object"),
			"the message was: '" + asPrivate.getMessage() + "'");
		assertTrue(asPublic.getMessage().contains("no PEM object"),
			"the message was: '" + asPublic.getMessage() + "'");
	}
}
