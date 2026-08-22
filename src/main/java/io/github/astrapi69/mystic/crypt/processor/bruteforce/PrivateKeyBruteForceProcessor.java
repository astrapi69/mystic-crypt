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
package io.github.astrapi69.mystic.crypt.processor.bruteforce;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Objects;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCSException;

import io.github.astrapi69.crypt.data.key.reader.EncryptedPrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;

/**
 * The class {@link PrivateKeyBruteForceProcessor}
 */
public final class PrivateKeyBruteForceProcessor
{

	private PrivateKeyBruteForceProcessor()
	{
	}

	/**
	 * Resolve the password from the given private key file. If no password is set an empty Optional
	 * will be returned.
	 *
	 * @param privateKeyFile
	 *            the private key file
	 * @param processor
	 *            the processor
	 * @return the optional
	 */
	public static Optional<String> resolvePassword(File privateKeyFile,
		BruteForceProcessor processor)
	{
		Objects.requireNonNull(processor);
		try
		{
			boolean isPasswordProtected = PrivateKeyReader
				.isPrivateKeyPasswordProtected(privateKeyFile);

			if (isPasswordProtected)
			{
				// A password protected key is not resolved by this processor: there is nothing
				// to try against the readers used here, so answer an empty optional
				return Optional.empty();
			}

			// The key is not password protected, so a single read decides the outcome. Retrying
			// with further passwords can never change the result for an unprotected key (the
			// password is ignored while parsing it), therefore there is deliberately no brute
			// force loop here. An unparseable or unsupported key (for example an unencrypted
			// PKCS#8 key, which the reader rejects with a PEMException on every attempt) is a
			// terminal error and answers an empty optional, rather than looping forever over an
			// ever growing attempt space, which was the previous behaviour and hung the caller.
			String attempt = processor.getCurrentAttempt();
			Security.addProvider(new BouncyCastleProvider());
			EncryptedPrivateKeyReader.getKeyPair(privateKeyFile, attempt);
			return Optional.of(attempt);
		}
		catch (IOException | PKCSException e)
		{
			return Optional.empty();
		}
	}

}
