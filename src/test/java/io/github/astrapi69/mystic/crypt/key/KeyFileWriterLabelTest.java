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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Tests that {@link KeyFileWriter} labels what it writes.
 * <p>
 * The class was written as a workaround while crypt-data wrote PKCS#1 under a PKCS#8 header, and it
 * carried a smaller version of the same fault: the traditional form of anything that is not rsa was
 * labelled PRIVATE KEY, which means PKCS#8, over content that had the wrapper stripped. A file like
 * that is readable as neither format.
 */
class KeyFileWriterLabelTest
{

	@BeforeAll
	static void setUp()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static PrivateKey newPrivateKey(final String algorithm, final int size) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, "BC");
		if (size > 0)
		{
			generator.initialize(size);
		}
		return generator.generateKeyPair().getPrivate();
	}

	private static byte[] bodyOf(final String pem)
	{
		return Base64.getDecoder()
			.decode(pem.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s", ""));
	}

	/**
	 * The header has to name the encoding underneath it, for every algorithm.
	 *
	 * @param algorithm
	 *            the key algorithm
	 * @param size
	 *            the key size, 0 for the default
	 * @param expectedLabel
	 *            the pem label the traditional form must carry
	 * @throws Exception
	 *             if key generation or writing fails
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048, RSA PRIVATE KEY", "DSA, 2048, DSA PRIVATE KEY",
			"EC, 0, EC PRIVATE KEY" })
	void theTraditionalFormCarriesTheLabelOfItsOwnAlgorithm(final String algorithm, final int size,
		final String expectedLabel) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, size);

		String pem = KeyFileWriter.toPem(privateKey, true);

		assertTrue(pem.startsWith("-----BEGIN " + expectedLabel + "-----"),
			algorithm + " must be labelled '" + expectedLabel + "', but the file began '"
				+ pem.lines().findFirst().orElse("") + "'");
	}

	/**
	 * A key with no traditional form of its own keeps its pkcs#8 encoding, and the header says so -
	 * rather than the pkcs#8 header over stripped content, which names a format the bytes are not
	 * in.
	 *
	 * @param algorithm
	 *            the key algorithm
	 * @throws Exception
	 *             if key generation or writing fails
	 */
	@ParameterizedTest
	@CsvSource({ "Ed25519", "Ed448", "X25519" })
	void aKeyWithNoTraditionalFormKeepsItsPkcs8Encoding(final String algorithm) throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, 0);

		String pem = KeyFileWriter.toPem(privateKey, true);

		assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----"),
			algorithm + " keeps the pkcs#8 header, but the file began '"
				+ pem.lines().findFirst().orElse("") + "'");
		assertArrayEquals(privateKey.getEncoded(), bodyOf(pem),
			algorithm + " under the PRIVATE KEY header must hold the pkcs#8 encoding, not the "
				+ "stripped wrapper");
	}

	/**
	 * The der pair. {@code toPkcs1} lost its last caller when the pem conversions moved to
	 * crypt-data, but it is the counterpart of {@code toPkcs8}, which the convert command uses, and
	 * it is public since 12.0.0 - so it stays and is asserted rather than quietly kept alive.
	 *
	 * @param algorithm
	 *            the key algorithm
	 * @param size
	 *            the key size, 0 for the default
	 * @throws Exception
	 *             if key generation or conversion fails
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048", "DSA, 2048", "EC, 0" })
	void theDerFormsAreTheTwoEncodingsWithoutTheArmour(final String algorithm, final int size)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, size);

		assertArrayEquals(privateKey.getEncoded(), KeyFileWriter.toPkcs8(privateKey),
			algorithm + " as pkcs#8 der is the encoding the key hands out");
		assertArrayEquals(bodyOf(KeyFileWriter.toPem(privateKey, true)),
			KeyFileWriter.toPkcs1(privateKey),
			algorithm + " as traditional der is what its pem carries, without the armour");
	}

	/**
	 * The pkcs#8 side was never in question and stays as it was.
	 *
	 * @param algorithm
	 *            the key algorithm
	 * @param size
	 *            the key size, 0 for the default
	 * @throws Exception
	 *             if key generation or writing fails
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, 2048", "DSA, 2048", "EC, 0", "Ed25519, 0" })
	void thePkcs8FormIsTheEncodingUnderItsOwnHeader(final String algorithm, final int size)
		throws Exception
	{
		PrivateKey privateKey = newPrivateKey(algorithm, size);

		String pem = KeyFileWriter.toPem(privateKey, false);

		assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----"),
			pem.lines().findFirst().orElse(""));
		assertArrayEquals(privateKey.getEncoded(), bodyOf(pem));
	}
}
