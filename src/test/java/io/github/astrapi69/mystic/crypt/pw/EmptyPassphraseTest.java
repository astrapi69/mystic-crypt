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
package io.github.astrapi69.mystic.crypt.pw;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/**
 * Encrypting refuses a passphrase that protects nothing: the empty one, and null, which the key
 * derivation would take as the empty one. Opening with the empty passphrase stays possible, so that
 * what an earlier release sealed under it still opens (#314)
 */
class EmptyPassphraseTest
{

	private static final byte[] MAGIC = "MCFILE".getBytes(StandardCharsets.US_ASCII);

	private static final byte[] PLAINTEXT = "sealed under nothing".getBytes(StandardCharsets.UTF_8);

	/** {@code PassphraseCryptor.encrypt(new char[0], PLAINTEXT)} of the released 13.10 */
	private static final String MCRYPT_OF_13_10 = "TUNSWVBUAQAJJ8DELEMWDf2oGJN9VDWFMYESmA3pz8d11nBJWF"
		+ "gO3H0Sbs/TSt/6qnwDeFr8y2ywZtgTvbJ7RtboTpfvywfE97qQVz+fc1SMs51sRxed1NGAVE0Fm4tpx5yVHNilu2w"
		+ "bwn0=";

	/** {@code PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, new char[0])} of the released 13.10 */
	private static final String MCFILE_OF_13_10 = "TUNGSUxFO1SLUQJWc9Cd4IG5GmPUjQAJJ8AKSJX3p5H/QOmY+Ai"
		+ "n5Jt19sObUSu2ALEyJ5FQ2a2gBpVlHXqBTOEdl/VHouahfrFtGcXuzufR06/iB653AEWCCFVM5OiyFEAlbubBqWxSwQ"
		+ "==";

	@Test
	@DisplayName("the envelope refuses to seal under an empty passphrase, and says why")
	void envelope_refusesAnEmptyPassphrase()
	{
		assertRefusedAsEmpty(() -> PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, new char[0]));
	}

	@Test
	@DisplayName("the envelope refuses to seal under a null passphrase")
	void envelope_refusesANullPassphrase()
	{
		assertRefusedAsNull(() -> PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, (char[])null));
	}

	@Test
	@DisplayName("the envelope refuses to seal under an empty string, and says why")
	void envelope_refusesAnEmptyString()
	{
		assertRefusedAsEmpty(() -> PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, ""));
	}

	@Test
	@DisplayName("the envelope refuses to seal under a null string, with a message")
	void envelope_refusesANullString()
	{
		assertRefusedAsNull(() -> PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, (String)null));
	}

	@Test
	@DisplayName("the released layout refuses to encrypt under an empty passphrase, and says why")
	void cryptor_refusesAnEmptyPassphrase()
	{
		assertRefusedAsEmpty(() -> PassphraseCryptor.encrypt(new char[0], PLAINTEXT));
	}

	@Test
	@DisplayName("the released layout refuses a null passphrase before it encrypts, with a message")
	void cryptor_refusesANullPassphrase()
	{
		assertRefusedAsNull(() -> PassphraseCryptor.encrypt(null, PLAINTEXT));
	}

	@Test
	@DisplayName("what 13.10 sealed in the envelope under the empty passphrase still opens with it")
	void envelope_stillOpensWhatWasSealedUnderTheEmptyPassphrase() throws Exception
	{
		byte[] sealed = Base64.getDecoder().decode(MCFILE_OF_13_10);

		assertArrayEquals(PLAINTEXT, PassphraseEnvelope.decrypt(MAGIC, sealed, new char[0]));
		assertArrayEquals(PLAINTEXT, PassphraseEnvelope.decrypt(MAGIC, sealed, ""));
		assertArrayEquals(PLAINTEXT, PassphraseFileFormat.open(sealed, new char[0]));
	}

	@Test
	@DisplayName("what 13.10 encrypted in the released layout under the empty passphrase still opens")
	void cryptor_stillOpensWhatWasEncryptedUnderTheEmptyPassphrase() throws Exception
	{
		byte[] sealed = Base64.getDecoder().decode(MCRYPT_OF_13_10);

		assertArrayEquals(PLAINTEXT, PassphraseCryptor.decrypt(new char[0], sealed));
		assertArrayEquals(PLAINTEXT, PassphraseFileFormat.open(sealed, new char[0]));
	}

	@Test
	@DisplayName("opening refuses a null passphrase, which used to open as the empty one")
	void opening_refusesANullPassphrase()
	{
		byte[] envelope = Base64.getDecoder().decode(MCFILE_OF_13_10);
		byte[] released = Base64.getDecoder().decode(MCRYPT_OF_13_10);

		assertRefusedAsNull(() -> PassphraseEnvelope.decrypt(MAGIC, envelope, (char[])null));
		assertRefusedAsNull(() -> PassphraseEnvelope.decrypt(MAGIC, envelope, (String)null));
		assertRefusedAsNull(() -> PassphraseCryptor.decrypt(null, released));
		assertRefusedAsNull(() -> PassphraseFileFormat.open(envelope, null));
	}

	private static void assertRefusedAsEmpty(final Executable sealing)
	{
		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class, sealing);
		assertTrue(refused.getMessage().contains("the passphrase is empty"), refused.getMessage());
		assertTrue(refused.getMessage().contains("opens for anybody"), refused.getMessage());
	}

	private static void assertRefusedAsNull(final Executable call)
	{
		NullPointerException refused = assertThrows(NullPointerException.class, call);
		assertEquals("the passphrase is null; the empty passphrase is an empty array or string",
			refused.getMessage());
	}
}
