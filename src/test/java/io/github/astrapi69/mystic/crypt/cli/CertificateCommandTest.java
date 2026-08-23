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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Unit tests for the {@code cert} subcommand.
 */
class CertificateCommandTest extends AbstractCliTest
{

	/** the temporary directory the confirmation-line cases write their certificates into */
	@TempDir
	File confirmationTempDir;

	/**
	 * One confirmation-line case: which subject and key algorithm the command is asked for, plus a
	 * different subject that must never show up in the output of this run.
	 */
	record ConfirmationCase(String fileName, String subject, String algorithm,
		String signatureAlgorithm, String otherSubject) {
	}

	static Stream<ConfirmationCase> confirmationCases()
	{
		return Stream.of(
			new ConfirmationCase("rsa-confirmation.pem", "CN=rsa-confirmation", "RSA",
				"SHA256withRSA", "CN=ec-confirmation"),
			new ConfirmationCase("ec-confirmation.pem", "CN=ec-confirmation", "EC",
				"SHA256withECDSA", "CN=rsa-confirmation"));
	}

	/**
	 * Guards the success message of the {@code cert} command. Writing the PEM is only half of the
	 * contract: the command must also tell the user on stdout for which subject it signed and where
	 * the file went, otherwise a successful run is silent and indistinguishable from a no-op. This
	 * test fails if that {@code System.out.println} is dropped or stops naming the subject or the
	 * output file.
	 */
	@ParameterizedTest
	@MethodSource("confirmationCases")
	void printsAConfirmationLineNamingTheSubjectAndTheOutputFile(ConfirmationCase testCase)
	{
		File certFile = new File(confirmationTempDir, testCase.fileName());
		assertEquals(0,
			run("cert", "--subject", testCase.subject(), "--algorithm", testCase.algorithm(),
				"--signature-algorithm", testCase.signatureAlgorithm(), "--out",
				certFile.getAbsolutePath()));

		assertTrue(
			out.contains("wrote self-signed certificate for '" + testCase.subject() + "' to "
				+ certFile.getAbsolutePath()),
			"stdout must confirm subject and target file, but was: '" + out + "'");
		// the matching negative: the confirmation names this run's subject, never another one
		assertFalse(out.contains(testCase.otherSubject()),
			"the confirmation must not name a subject that was not requested");
	}

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
