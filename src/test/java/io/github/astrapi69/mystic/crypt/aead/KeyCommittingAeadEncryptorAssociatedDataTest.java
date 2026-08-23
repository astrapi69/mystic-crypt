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
package io.github.astrapi69.mystic.crypt.aead;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The unit test class for the "absent associated data" contract of
 * {@link KeyCommittingAeadEncryptor}.
 * <p>
 * {@code encrypt(byte[], byte[])} and {@code decrypt(byte[], byte[])} both guard the associated
 * data with {@code associatedData != null && associatedData.length > 0}, and
 * {@code computeCommitmentTag(byte[], byte[])} does the same. That makes {@code null} and a
 * zero-length array two spellings of "no associated data": both have to produce exactly the same
 * commitment tag and exactly the same GCM associated data, so a ciphertext written with one
 * spelling must be readable with the other. Nothing pinned that contract before this test - the
 * existing tests only ever used the same spelling on both sides of a round trip.
 * </p>
 *
 * @author Asterios Raptis
 */
class KeyCommittingAeadEncryptorAssociatedDataTest
{

	private static final byte[] PLAIN_TEXT = "the quick brown fox jumps over the lazy dog"
		.getBytes(StandardCharsets.UTF_8);

	private KeyCommittingAeadEncryptor encryptor;

	/**
	 * A scenario that pairs the spelling of "no associated data" used while encrypting with the
	 * spelling used while decrypting
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param encryptAssociatedData
	 *            the associated data handed to {@code encrypt}
	 * @param decryptAssociatedData
	 *            the associated data handed to {@code decrypt}
	 */
	record AbsentAssociatedDataCase(String description, byte[] encryptAssociatedData,
		byte[] decryptAssociatedData) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<AbsentAssociatedDataCase> absentAssociatedDataCases()
	{
		return Stream.of(
			new AbsentAssociatedDataCase("null on encrypt, null on decrypt", null, null),
			new AbsentAssociatedDataCase("empty on encrypt, empty on decrypt", new byte[0],
				new byte[0]),
			new AbsentAssociatedDataCase("empty on encrypt, null on decrypt", new byte[0], null),
			new AbsentAssociatedDataCase("null on encrypt, empty on decrypt", null, new byte[0]));
	}

	@BeforeEach
	void setUp() throws Exception
	{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey testKey = keyGen.generateKey();
		encryptor = new KeyCommittingAeadEncryptor(testKey);
	}

	/**
	 * Test method that guards the contract that {@code null} and a zero-length array mean the same
	 * "no associated data" on both legs of a round trip.
	 * <p>
	 * The positive half round-trips the plaintext through every combination of the two spellings;
	 * the matching negative half shows that this is not simply "the associated data is ignored" -
	 * as soon as a genuinely non-empty associated data is used on only one leg, the commitment
	 * check rejects the ciphertext with a {@link SecurityException}.
	 * </p>
	 *
	 * @param testCase
	 *            the scenario
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@ParameterizedTest
	@MethodSource("absentAssociatedDataCases")
	void encryptAndDecrypt_treatsNullAndEmptyAssociatedDataAsTheSame(
		final AbsentAssociatedDataCase testCase) throws Exception
	{
		byte[] encrypted = encryptor.encrypt(PLAIN_TEXT, testCase.encryptAssociatedData());

		assertArrayEquals(PLAIN_TEXT,
			encryptor.decrypt(encrypted, testCase.decryptAssociatedData()),
			"null and a zero-length array both mean 'no associated data', so the round trip must succeed");

		// the matching negative: a genuinely non-empty associated data is not interchangeable with
		// "absent", so the commitment verification has to reject it
		byte[] presentAssociatedData = "some associated data".getBytes(StandardCharsets.UTF_8);
		assertThrows(SecurityException.class,
			() -> encryptor.decrypt(encrypted, presentAssociatedData),
			"non-empty associated data must not decrypt a ciphertext written without associated data");
	}
}
