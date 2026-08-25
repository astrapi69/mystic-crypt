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
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@code keystore import-cert} subcommand.
 */
class KeystoreImportCertCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private File newCertificatePem(File tempDir)
	{
		File certificateFile = new File(tempDir, "import-me.pem");
		assertEquals(0,
			run("cert", "--subject", "CN=import-test", "--algorithm", "EC", "--signature-algorithm",
				"SHA256withECDSA", "--out", certificateFile.getAbsolutePath()));
		return certificateFile;
	}

	private File newStore(File tempDir, String type)
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret"));
		return storeFile;
	}

	@ParameterizedTest
	@ValueSource(strings = { "PKCS12", "JKS", "JCEKS" })
	void importsAPemCertificateIntoEveryStoreType(String type, @TempDir File tempDir)
		throws Exception
	{
		File certificateFile = newCertificatePem(tempDir);
		File storeFile = newStore(tempDir, type);
		assertEquals(0,
			run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(), "--type", type,
				"--password", "secret", "--alias", "trusted", "--certificate",
				certificateFile.getAbsolutePath()));
		assertTrue(out.contains("imported the certificate as 'trusted'"),
			"stdout must confirm the import, but was: '" + out + "'");

		KeyStore keyStore = KeyStore.getInstance(type);
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
		assertTrue(keyStore.isCertificateEntry("trusted"),
			"the alias must hold a certificate entry");
		X509Certificate imported = (X509Certificate)keyStore.getCertificate("trusted");
		assertTrue(imported.getSubjectX500Principal().getName().contains("import-test"),
			"the imported certificate must keep its subject");
	}

	@Test
	void importsADerCertificate(@TempDir File tempDir) throws Exception
	{
		File certificatePem = newCertificatePem(tempDir);
		// the same certificate, DER-encoded
		X509Certificate certificate;
		try (InputStream inputStream = Files.newInputStream(certificatePem.toPath()))
		{
			certificate = (X509Certificate)CertificateFactory.getInstance("X.509")
				.generateCertificate(inputStream);
		}
		File certificateDer = new File(tempDir, "import-me.der");
		Files.write(certificateDer.toPath(), certificate.getEncoded());

		File storeFile = newStore(tempDir, "PKCS12");
		assertEquals(0,
			run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "trusted-der", "--certificate",
				certificateDer.getAbsolutePath()));

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
		assertTrue(keyStore.isCertificateEntry("trusted-der"));
	}

	/**
	 * Importing under an existing alias must fail instead of silently swapping a trust anchor.
	 */
	@Test
	void anExistingAliasIsNotOverwritten(@TempDir File tempDir) throws Exception
	{
		File certificateFile = newCertificatePem(tempDir);
		File storeFile = newStore(tempDir, "PKCS12");
		assertEquals(0,
			run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "trusted", "--certificate",
				certificateFile.getAbsolutePath()));

		assertNotEquals(0,
			run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(), "--password",
				"secret", "--alias", "trusted", "--certificate",
				certificateFile.getAbsolutePath()));
		assertTrue(err.contains("already exists"),
			"the error must say the alias already exists, but was: '" + err + "'");
	}

	@Test
	void aFileThatIsNoCertificateFails(@TempDir File tempDir) throws Exception
	{
		File garbage = new File(tempDir, "garbage.pem");
		Files.writeString(garbage.toPath(), "this is not a certificate");
		File storeFile = newStore(tempDir, "PKCS12");
		assertNotEquals(0, run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(),
			"--password", "secret", "--alias", "nope", "--certificate", garbage.getAbsolutePath()));
	}

	@Test
	void aMissingCertificateFileFails(@TempDir File tempDir)
	{
		File storeFile = newStore(tempDir, "PKCS12");
		File missing = new File(tempDir, "no-such.pem");
		assertNotEquals(0, run("keystore", "import-cert", "--file", storeFile.getAbsolutePath(),
			"--password", "secret", "--alias", "nope", "--certificate", missing.getAbsolutePath()));
	}
}
