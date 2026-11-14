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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What sealing does with a passphrase that protects nothing: the empty one, and null, which the key
 * derivation takes as the empty one (#314)
 */
class EmptyPassphraseTest
{

	private static final byte[] MAGIC = "MCFILE".getBytes(StandardCharsets.US_ASCII);

	private static final byte[] PLAINTEXT = "sealed under nothing".getBytes(StandardCharsets.UTF_8);

	@Test
	@DisplayName("the envelope seals under an empty passphrase, and the empty one opens it")
	void envelope_sealsUnderAnEmptyPassphrase() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, new char[0]);

		assertArrayEquals(PLAINTEXT, PassphraseEnvelope.decrypt(MAGIC, sealed, new char[0]));
	}

	@Test
	@DisplayName("the envelope seals under a null passphrase as under the empty one")
	void envelope_sealsUnderANullPassphrase() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, (char[])null);

		assertArrayEquals(PLAINTEXT, PassphraseEnvelope.decrypt(MAGIC, sealed, new char[0]));
	}

	@Test
	@DisplayName("the envelope seals under an empty string")
	void envelope_sealsUnderAnEmptyString() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(MAGIC, PLAINTEXT, "");

		assertArrayEquals(PLAINTEXT, PassphraseEnvelope.decrypt(MAGIC, sealed, ""));
	}

	@Test
	@DisplayName("the released layout seals under an empty passphrase, and the empty one opens it")
	void cryptor_sealsUnderAnEmptyPassphrase()
	{
		byte[] sealed = PassphraseCryptor.encrypt(new char[0], PLAINTEXT);

		assertArrayEquals(PLAINTEXT, PassphraseCryptor.decrypt(new char[0], sealed));
	}

	@Test
	@DisplayName("the released layout fails on a null passphrase only after it has sealed")
	void cryptor_failsOnANullPassphraseWithoutAMessage()
	{
		assertThrows(NullPointerException.class, () -> PassphraseCryptor.encrypt(null, PLAINTEXT));
	}
}
