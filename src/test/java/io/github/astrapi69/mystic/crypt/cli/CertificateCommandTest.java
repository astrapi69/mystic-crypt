/**
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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for the {@code cert} subcommand.
 */
class CertificateCommandTest extends AbstractCliTest
{

	@Test
	void writesASelfSignedCertificateForTheSubject(@TempDir File tempDir) throws Exception
	{
		File certFile = new File(tempDir, "cert.pem");
		assertEquals(0, run("cert", "--subject", "CN=unit-test", "--days", "30", "--out",
			certFile.getAbsolutePath()));
		assertTrue(certFile.exists() && certFile.length() > 0);

		String pem = Files.readString(certFile.toPath());
		assertTrue(pem.contains("BEGIN CERTIFICATE"));

		// the written PEM must parse as a real X.509 certificate whose subject is what we asked for
		X509Certificate certificate;
		try (var inputStream = Files.newInputStream(certFile.toPath()))
		{
			certificate = (X509Certificate)CertificateFactory.getInstance("X.509")
				.generateCertificate(inputStream);
		}
		assertTrue(certificate.getSubjectX500Principal().getName().contains("unit-test"));
	}

	@Test
	void writesACertificateForASizeFreeKeyAlgorithm(@TempDir File tempDir) throws Exception
	{
		// EC is not size-based, so this exercises the size-free key-generation branch
		File certFile = new File(tempDir, "ec-cert.pem");
		assertEquals(0, run("cert", "--subject", "CN=ec-test", "--algorithm", "EC",
			"--signature-algorithm", "SHA256withECDSA", "--out", certFile.getAbsolutePath()));
		assertTrue(Files.readString(certFile.toPath()).contains("BEGIN CERTIFICATE"));
	}
}
