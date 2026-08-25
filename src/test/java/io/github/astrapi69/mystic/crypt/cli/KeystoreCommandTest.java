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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Tests for the {@code keystore} command wiring and its shared helpers; the individual subcommands
 * are covered by their own test classes.
 */
class KeystoreCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@Test
	void withoutASubcommandPrintsTheUsage()
	{
		assertEquals(0, run("keystore"));
		for (String subcommand : new String[] { "list", "create", "add-keypair", "import-cert",
				"export-cert", "delete" })
		{
			assertTrue(out.contains(subcommand),
				"the keystore usage must mention the '" + subcommand + "' subcommand");
		}
	}

	/**
	 * Guards the mapping from key algorithm to certificate signature algorithm: a certificate can
	 * only be signed with a signature algorithm the key itself supports, so every mapped pair here
	 * is a contract of the {@code add-keypair} subcommand.
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, SHA256withRSA", "RSASSA_PSS, SHA256withRSAandMGF1", "EC, SHA256withECDSA",
			"DSA, SHA256withDSA", "ML_DSA_44, ML-DSA-44", "ML_DSA_65, ML-DSA-65",
			"ML_DSA_87, ML-DSA-87" })
	void signatureAlgorithmMatchesTheKeyAlgorithm(KeyPairGeneratorAlgorithm keyAlgorithm,
		String expectedSignatureAlgorithm)
	{
		assertEquals(expectedSignatureAlgorithm,
			KeystoreCommand.signatureAlgorithmFor(keyAlgorithm));
	}

	/**
	 * Key-exchange algorithms cannot sign a certificate and must be rejected with a clear message
	 * instead of being mapped silently to some signature algorithm.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "X25519", "X448", "XDH", "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
			"DIFFIE_HELLMAN", "DH", "Ed25519" })
	void algorithmsThatCannotSignACertificateAreRejected(String name)
	{
		KeyPairGeneratorAlgorithm keyAlgorithm = KeyPairGeneratorAlgorithm.valueOf(name);
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			() -> KeystoreCommand.signatureAlgorithmFor(keyAlgorithm));
		assertTrue(exception.getMessage().contains("cannot sign a certificate"),
			"the message must say why '" + name + "' is rejected, but was: '"
				+ exception.getMessage() + "'");
	}
}
