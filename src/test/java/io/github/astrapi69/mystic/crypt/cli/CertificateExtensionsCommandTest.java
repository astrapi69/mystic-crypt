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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the extensions {@code cert} gained: basic constraints, key usage and subject
 * alternative names, read back out of the written certificate rather than out of the run's own
 * output.
 */
class CertificateExtensionsCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static X509Certificate read(File pem) throws Exception
	{
		try (FileInputStream stream = new FileInputStream(pem))
		{
			return (X509Certificate)CertificateFactory.getInstance("X.509")
				.generateCertificate(stream);
		}
	}

	@Test
	void writesBasicConstraintsForACaWithAPathLength(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "ca.pem");

		assertEquals(0, run("cert", "--subject", "CN=a-ca", "--days", "1", "--basic-constraints",
			"ca,pathlen=1", "--out", pem.getPath()), "stderr was: '" + err + "'");

		assertEquals(1, read(pem).getBasicConstraints(),
			"getBasicConstraints returns the path length for a CA");
		assertTrue(out.contains("basic constraints"), "stdout was: '" + out + "'");
	}

	@Test
	void writesBasicConstraintsForAnEndEntity(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "leaf.pem");

		assertEquals(0, run("cert", "--subject", "CN=a-leaf", "--days", "1", "--basic-constraints",
			"end-entity", "--out", pem.getPath()), "stderr was: '" + err + "'");

		assertEquals(-1, read(pem).getBasicConstraints(),
			"getBasicConstraints returns -1 when the certificate is not a CA");
	}

	@Test
	void aCaWithoutAPathLengthHasNoLimit(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "ca.pem");

		assertEquals(0, run("cert", "--subject", "CN=a-ca", "--days", "1", "--basic-constraints",
			"ca", "--out", pem.getPath()), "stderr was: '" + err + "'");

		assertEquals(Integer.MAX_VALUE, read(pem).getBasicConstraints(),
			"an unlimited path length is reported as Integer.MAX_VALUE");
	}

	/** The nine key usages, each in the bit position the extension gives it. */
	@ParameterizedTest
	@CsvSource({ "digitalSignature, 0", "nonRepudiation, 1", "keyEncipherment, 2",
			"dataEncipherment, 3", "keyAgreement, 4", "keyCertSign, 5", "cRLSign, 6",
			"encipherOnly, 7", "decipherOnly, 8" })
	void writesEachKeyUsageInItsOwnBit(String usage, int bit, @TempDir File tempDir)
		throws Exception
	{
		File pem = new File(tempDir, "usage.pem");

		assertEquals(0, run("cert", "--subject", "CN=usage", "--days", "1", "--key-usage", usage,
			"--out", pem.getPath()), "stderr was: '" + err + "'");

		boolean[] keyUsage = read(pem).getKeyUsage();
		assertNotNull(keyUsage, "the key usage extension must be present");
		assertTrue(keyUsage[bit], usage + " must set bit " + bit);
	}

	@Test
	void writesSeveralKeyUsagesAtOnce(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "usage.pem");

		assertEquals(0,
			run("cert", "--subject", "CN=usage", "--days", "1", "--key-usage",
				"digitalSignature,keyCertSign", "--out", pem.getPath()),
			"stderr was: '" + err + "'");

		boolean[] keyUsage = read(pem).getKeyUsage();
		assertTrue(keyUsage[0] && keyUsage[5], "both usages must be set");
		assertFalse(keyUsage[2], "an unnamed usage must not be set");
	}

	@Test
	void writesEveryKindOfSubjectAlternativeName(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "san.pem");

		assertEquals(0,
			run("cert", "--subject", "CN=san", "--days", "1", "--san", "dns:example.org", "--san",
				"ip:10.0.0.1", "--san", "email:someone@example.org", "--san",
				"uri:https://example.org", "--out", pem.getPath()),
			"stderr was: '" + err + "'");

		List<String> names = read(pem).getSubjectAlternativeNames().stream()
			.map(entry -> String.valueOf(entry.get(1))).toList();
		assertTrue(names.contains("example.org"), "names were: " + names);
		assertTrue(names.contains("10.0.0.1"), "names were: " + names);
		assertTrue(names.contains("someone@example.org"), "names were: " + names);
		assertTrue(names.contains("https://example.org"), "names were: " + names);
	}

	@Test
	void marksTheNamedExtensionsCritical(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "critical.pem");

		assertEquals(0,
			run("cert", "--subject", "CN=critical", "--days", "1", "--basic-constraints", "ca",
				"--key-usage", "keyCertSign", "--san", "dns:example.org", "--critical",
				"basic-constraints,key-usage", "--out", pem.getPath()),
			"stderr was: '" + err + "'");

		X509Certificate certificate = read(pem);
		assertTrue(certificate.getCriticalExtensionOIDs().contains("2.5.29.19"),
			"basic constraints must be critical");
		assertTrue(certificate.getCriticalExtensionOIDs().contains("2.5.29.15"),
			"key usage must be critical");
		assertTrue(certificate.getNonCriticalExtensionOIDs().contains("2.5.29.17"),
			"the subject alternative names were not named, so they must not be critical");
	}

	@Test
	void withoutTheOptionsNoExtensionsAreWritten(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "plain.pem");

		assertEquals(0,
			run("cert", "--subject", "CN=plain", "--days", "1", "--out", pem.getPath()));

		X509Certificate certificate = read(pem);
		assertEquals(-1, certificate.getBasicConstraints());
		assertNull(certificate.getKeyUsage());
		assertNull(certificate.getSubjectAlternativeNames());
	}

	/**
	 * The mistake this refuses: RFC 4055 requires an RSASSA-PSS key to be used with a PSS
	 * signature. Signing with SHA256withRSA instead yields a certificate some verifiers reject, and
	 * it does so quietly, so the library refuses rather than producing it.
	 */
	@Test
	void anRsassaPssKeySignedWithPlainRsaIsRefusedWithTheRfcReason(@TempDir File tempDir)
	{
		int exitCode = run("cert", "--subject", "CN=pss", "--days", "1", "-a", "RSASSA-PSS",
			"--signature-algorithm", "SHA256withRSA", "--out",
			new File(tempDir, "x.pem").getPath());

		assertEquals(2, exitCode);
		assertTrue(err.contains("RFC 4055") && err.contains("MGF1"),
			"the message must say what to use instead, but was: '" + err + "'");
	}

	@Test
	void anRsassaPssKeySignedWithMgf1IsAccepted(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "pss.pem");

		assertEquals(0,
			run("cert", "--subject", "CN=pss", "--days", "1", "-a", "RSASSA-PSS",
				"--signature-algorithm", "SHA256withRSAandMGF1", "--out", pem.getPath()),
			"stderr was: '" + err + "'");

		assertNotNull(read(pem), "the certificate must be readable");
	}

	@ParameterizedTest
	@ValueSource(strings = { "neither", "ca,pathlen=notanumber", "ca,pathlen=-1", "ca,nonsense",
			"end-entity,pathlen=1" })
	void basicConstraintsThatDoNotMakeSenseAreRefusedWithTheReason(String value,
		@TempDir File tempDir)
	{
		assertEquals(2, run("cert", "--subject", "CN=x", "--days", "1", "--basic-constraints",
			value, "--out", new File(tempDir, "x.pem").getPath()));
		assertFalse(err.isBlank(), "the failure must be explained for '" + value + "'");
	}

	@Test
	void anUnknownKeyUsageListsTheOnesThatExist(@TempDir File tempDir)
	{
		assertEquals(2, run("cert", "--subject", "CN=x", "--days", "1", "--key-usage",
			"signAllTheThings", "--out", new File(tempDir, "x.pem").getPath()));

		assertTrue(err.contains("is not a key usage") && err.contains("digitalSignature"),
			"the message must list the usages, but was: '" + err + "'");
	}

	@ParameterizedTest
	@ValueSource(strings = { "example.org", "dns:", ":example.org", "ftp:example.org" })
	void aSubjectAlternativeNameWithoutAKnownTypeIsRefused(String value, @TempDir File tempDir)
	{
		assertEquals(2, run("cert", "--subject", "CN=x", "--days", "1", "--san", value, "--out",
			new File(tempDir, "x.pem").getPath()));
		assertFalse(err.isBlank(), "the failure must be explained for '" + value + "'");
	}

	/** Zero is a path length, not a missing one: it says no CA may appear below this one. */
	@Test
	void aPathLengthOfZeroIsAcceptedAndNegativeIsNot(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "ca0.pem");

		assertEquals(0, run("cert", "--subject", "CN=ca0", "--days", "1", "--basic-constraints",
			"ca,pathlen=0", "--out", pem.getPath()), "stderr was: '" + err + "'");
		assertEquals(0, read(pem).getBasicConstraints(), "pathlen=0 must reach the certificate");

		assertEquals(2, run("cert", "--subject", "CN=x", "--days", "1", "--basic-constraints",
			"ca,pathlen=-1", "--out", new File(tempDir, "x.pem").getPath()));
		assertTrue(err.contains("cannot be negative"), "stderr was: '" + err + "'");
	}

	/**
	 * An algorithm with a fixed parameter set takes no key size, and cert has to handle both. The
	 * post-quantum case also pins that the certificate can be signed at all: an ML-DSA key comes
	 * from the JDK's own provider, and a factory that insists on Bouncy Castle refuses it with
	 * "unknown private key passed to ML-DSA".
	 */
	@ParameterizedTest
	@CsvSource({ "ML_DSA_65, ML-DSA-65", "EC, SHA256withECDSA", "DSA, SHA256withDSA" })
	void anAlgorithmWithAFixedParameterSetNeedsNoKeySize(String algorithm,
		String signatureAlgorithm, @TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "fixed.pem");

		assertEquals(0,
			run("cert", "--subject", "CN=pq", "--days", "1", "-a", algorithm,
				"--signature-algorithm", signatureAlgorithm, "--out", pem.getPath()),
			"stderr was: '" + err + "'");

		assertNotNull(read(pem), algorithm + " must produce a readable certificate");
	}

	/**
	 * The confirmation names only the extensions that were actually written, so a run with one of
	 * them must not claim the others.
	 */
	@Test
	void theConfirmationNamesOnlyWhatWasWritten(@TempDir File tempDir)
	{
		assertEquals(0, run("cert", "--subject", "CN=only-bc", "--days", "1", "--basic-constraints",
			"ca", "--out", new File(tempDir, "a.pem").getPath()));
		assertTrue(out.contains("basic constraints"), "stdout was: '" + out + "'");
		assertFalse(out.contains("key usage"), "no key usage was asked for: '" + out + "'");
		assertFalse(out.contains("subject alternative"), "none was asked for: '" + out + "'");

		assertEquals(0, run("cert", "--subject", "CN=only-ku", "--days", "1", "--key-usage",
			"keyCertSign", "--out", new File(tempDir, "b.pem").getPath()));
		assertTrue(out.contains("key usage (keyCertSign)"), "stdout was: '" + out + "'");
		assertFalse(out.contains("basic constraints"), "stdout was: '" + out + "'");

		assertEquals(0, run("cert", "--subject", "CN=only-san", "--days", "1", "--san",
			"dns:example.org", "--out", new File(tempDir, "c.pem").getPath()));
		assertTrue(out.contains("subject alternative names (dns:example.org)"),
			"stdout was: '" + out + "'");
		assertFalse(out.contains("key usage"), "stdout was: '" + out + "'");
	}

	@Test
	void theCommandAnswersItsOwnHelp()
	{
		assertEquals(0, run("cert", "--help"));
		assertTrue(
			out.contains("--basic-constraints") && out.contains("--key-usage")
				&& out.contains("--san") && out.contains("--critical"),
			"stdout was: '" + out + "'");
	}
}
