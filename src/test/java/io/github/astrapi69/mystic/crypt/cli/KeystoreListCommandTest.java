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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.HexFormat;

import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@code keystore list} subcommand.
 */
class KeystoreListCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@ParameterizedTest
	@ValueSource(strings = { "PKCS12", "JKS", "JCEKS" })
	void anEmptyStoreListsZeroEntries(String type, @TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "empty.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret"));
		assertEquals(0, run("keystore", "list", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret"));
		assertTrue(out.contains("0 entries"), "an empty store must list '0 entries'");
	}

	@Test
	void aPrivateKeyEntryShowsItsCertificateDetails(@TempDir File tempDir) throws Exception
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "listed-key", "--dname", "CN=listed-subject", "--algorithm",
				"EC"));

		// the fingerprint the listing must show: SHA-256 over the stored certificate
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
		X509Certificate certificate = (X509Certificate)keyStore.getCertificate("listed-key");
		String expectedFingerprint = HexFormat.of()
			.formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));

		assertEquals(0,
			run("keystore", "list", "--file", storeFile.getAbsolutePath(), "--password", "secret"));
		assertTrue(out.contains("listed-key"), "the listing must show the alias");
		assertTrue(out.contains("private key"), "the entry kind must be 'private key'");
		assertTrue(out.contains("CN=listed-subject"), "the listing must show the subject");
		assertTrue(out.contains(expectedFingerprint),
			"the listing must show the SHA-256 fingerprint '" + expectedFingerprint
				+ "', but was: '" + out + "'");
		// an exact line match: 'out.contains("1 entries")' would also accept a broken count
		// like "-1 entries"
		assertTrue(out.lines().anyMatch("1 entries"::equals),
			"exactly one entry must be counted, but the output was: '" + out + "'");
	}

	@Test
	void aCertificateOnlyEntryIsShownAsCertificate(@TempDir File tempDir) throws Exception
	{
		File certificateFile = new File(tempDir, "imported.pem");
		assertEquals(0,
			run("cert", "--subject", "CN=imported-cert", "--algorithm", "EC",
				"--signature-algorithm", "SHA256withECDSA", "--out",
				certificateFile.getAbsolutePath()));

		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));
		assertEquals(0,
			run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "trusted", "--certificate",
				certificateFile.getAbsolutePath()));

		assertEquals(0,
			run("keystore", "list", "--file", storeFile.getAbsolutePath(), "--password", "secret"));
		assertTrue(out.contains("trusted\tcertificate"),
			"a certificate-only entry must be shown with the kind 'certificate', but was: '" + out
				+ "'");
		assertTrue(out.contains("CN=imported-cert"), "the listing must show the subject");
	}

	/**
	 * A key entry without any certificate - a JCEKS secret key - must still be listed, with empty
	 * certificate columns instead of an error.
	 */
	@Test
	void aKeyEntryWithoutACertificateListsEmptyCertificateColumns(@TempDir File tempDir)
		throws Exception
	{
		File storeFile = new File(tempDir, "secret-key.jceks");
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(null, "secret".toCharArray());
		keyStore.setKeyEntry("aes-key", KeyGenerator.getInstance("AES").generateKey(),
			"secret".toCharArray(), null);
		try (OutputStream outputStream = Files.newOutputStream(storeFile.toPath()))
		{
			keyStore.store(outputStream, "secret".toCharArray());
		}

		assertEquals(0, run("keystore", "list", "--file", storeFile.getAbsolutePath(), "--type",
			"JCEKS", "--password", "secret"));
		assertTrue(out.contains("aes-key\tsecret key\t\t\t\t"),
			"a symmetric key must be listed as 'secret key' with empty certificate columns, "
				+ "but was: '" + out + "'");
		assertTrue(out.lines().anyMatch("1 entries"::equals),
			"exactly one entry must be counted, but the output was: '" + out + "'");
	}

	@Test
	void aWrongPasswordFails(@TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));
		assertNotEquals(0,
			run("keystore", "list", "--file", storeFile.getAbsolutePath(), "--password", "wrong"));
	}

	@Test
	void aMissingStoreFileFails(@TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "no-such.ks");
		assertNotEquals(0,
			run("keystore", "list", "--file", storeFile.getAbsolutePath(), "--password", "secret"));
	}
}
