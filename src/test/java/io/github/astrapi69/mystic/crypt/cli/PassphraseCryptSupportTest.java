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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.mystic.crypt.pw.PassphraseCryptor;

/**
 * The command line takes the passphrase as a character array so that it can be overwritten.
 * PassphraseCryptor overwrites what it is given; PassphraseEnvelope reads and leaves it alone, so
 * since the switch to the envelope the overwriting is this class's job. The assertion is on the
 * array's content after the call, not on a reference being dropped (#160)
 */
class PassphraseCryptSupportTest
{

	private static final char[] ZEROED = new char[8];

	@Test
	void sealing_overwritesThePassphrase() throws Exception
	{
		char[] passphrase = "pass1234".toCharArray();

		PassphraseCryptSupport.seal(passphrase, "x".getBytes(StandardCharsets.UTF_8));

		assertArrayEquals(ZEROED, passphrase, "the passphrase must be zero-filled after sealing");
	}

	@Test
	void openingTheGeneralEnvelope_overwritesThePassphrase() throws Exception
	{
		byte[] sealed = PassphraseCryptSupport.seal("pass1234".toCharArray(),
			"x".getBytes(StandardCharsets.UTF_8));
		char[] passphrase = "pass1234".toCharArray();

		PassphraseCryptSupport.open(passphrase, sealed);

		assertArrayEquals(ZEROED, passphrase, "the passphrase must be zero-filled after opening");
	}

	@Test
	void openingTheReleasedLayout_overwritesThePassphrase() throws Exception
	{
		byte[] old = PassphraseCryptor.encrypt("pass1234".toCharArray(),
			"x".getBytes(StandardCharsets.UTF_8));
		char[] passphrase = "pass1234".toCharArray();

		PassphraseCryptSupport.open(passphrase, old);

		assertArrayEquals(ZEROED, passphrase,
			"the passphrase must be zero-filled after opening an MCRYPT file too");
	}

	@Test
	void aFailedOpening_overwritesThePassphraseAsWell() throws Exception
	{
		byte[] sealed = PassphraseCryptSupport.seal("pass1234".toCharArray(),
			"x".getBytes(StandardCharsets.UTF_8));
		char[] wrong = "wrong123".toCharArray();

		try
		{
			PassphraseCryptSupport.open(wrong, sealed);
		}
		catch (SecurityException expected)
		{
			// the negative answer; what matters here is the state of the array afterwards
		}

		assertArrayEquals(ZEROED, wrong, "a wrong passphrase is still a passphrase to overwrite");
	}
}
