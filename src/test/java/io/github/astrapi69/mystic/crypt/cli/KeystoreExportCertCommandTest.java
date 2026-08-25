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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@code keystore export-cert} subcommand.
 */
class KeystoreExportCertCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@ParameterizedTest
	@ValueSource(strings = { "PKCS12", "JKS", "JCEKS" })
	void exportsTheCertificateOfAnAliasAsPem(String type, @TempDir File tempDir) throws Exception
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret"));
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--type", type,
				"--password", "secret", "--alias", "export-me", "--dname", "CN=export-test",
				"--algorithm", "EC"));

		File exported = new File(tempDir, "exported.pem");
		assertEquals(0,
			run("keystore", "export-cert", "--file", storeFile.getAbsolutePath(), "--type", type,
				"--password", "secret", "--alias", "export-me", "--out",
				exported.getAbsolutePath()));
		assertTrue(out.contains("exported 'export-me' to " + exported.getAbsolutePath()),
			"stdout must confirm alias and target file, but was: '" + out + "'");

		String pem = Files.readString(exported.toPath());
		assertTrue(pem.contains("BEGIN CERTIFICATE"), "the exported file must be PEM");
		// the written PEM must parse back into the certificate of the alias
		X509Certificate certificate;
		try (InputStream inputStream = Files.newInputStream(exported.toPath()))
		{
			certificate = (X509Certificate)CertificateFactory.getInstance("X.509")
				.generateCertificate(inputStream);
		}
		assertTrue(certificate.getSubjectX500Principal().getName().contains("export-test"));
	}

	/** A certificate-only entry (an imported one) must export unchanged, byte for byte. */
	@Test
	void exportsAnImportedCertificateEntryUnchanged(@TempDir File tempDir) throws Exception
	{
		File certificateFile = new File(tempDir, "original.pem");
		assertEquals(0,
			run("cert", "--subject", "CN=round-trip", "--algorithm", "EC", "--signature-algorithm",
				"SHA256withECDSA", "--out", certificateFile.getAbsolutePath()));
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));
		assertEquals(0,
			run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "round-trip", "--certificate",
				certificateFile.getAbsolutePath()));

		File exported = new File(tempDir, "exported.pem");
		assertEquals(0, run("keystore", "export-cert", "--file", storeFile.getAbsolutePath(),
			"--password", "secret", "--alias", "round-trip", "--out", exported.getAbsolutePath()));

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		X509Certificate original;
		X509Certificate roundTripped;
		try (InputStream inputStream = Files.newInputStream(certificateFile.toPath()))
		{
			original = (X509Certificate)certificateFactory.generateCertificate(inputStream);
		}
		try (InputStream inputStream = Files.newInputStream(exported.toPath()))
		{
			roundTripped = (X509Certificate)certificateFactory.generateCertificate(inputStream);
		}
		assertEquals(original, roundTripped,
			"import followed by export must yield the identical certificate");
	}

	@Test
	void anUnknownAliasFails(@TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));
		File exported = new File(tempDir, "exported.pem");
		assertNotEquals(0, run("keystore", "export-cert", "--file", storeFile.getAbsolutePath(),
			"--password", "secret", "--alias", "no-such", "--out", exported.getAbsolutePath()));
		assertTrue(err.contains("holds no X.509 certificate"),
			"the error must say the alias has no certificate, but was: '" + err + "'");
	}

	@Test
	void anEntryWithoutACertificateFails(@TempDir File tempDir) throws Exception
	{
		// a JCEKS store with a secret-key entry: a key entry that carries no certificate at all
		File storeFile = new File(tempDir, "secret-key.jceks");
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		keyStore.load(null, "secret".toCharArray());
		keyStore.setKeyEntry("aes-key", KeyGenerator.getInstance("AES").generateKey(),
			"secret".toCharArray(), null);
		try (OutputStream outputStream = Files.newOutputStream(storeFile.toPath()))
		{
			keyStore.store(outputStream, "secret".toCharArray());
		}

		File exported = new File(tempDir, "exported.pem");
		assertNotEquals(0,
			run("keystore", "export-cert", "--file", storeFile.getAbsolutePath(), "--type", "JCEKS",
				"--password", "secret", "--alias", "aes-key", "--out", exported.getAbsolutePath()));
		assertTrue(err.contains("holds no X.509 certificate"),
			"the error must say the alias has no certificate, but was: '" + err + "'");
	}
}
