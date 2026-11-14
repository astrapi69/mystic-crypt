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
package io.github.astrapi69.mystic.crypt.gnupg;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What a failed gpg call in the GnuPG tests leaves to read (#309, as
 * astrapi69/mystic-crypt-ui#940).
 * <p>
 * The message of a failed call points to the file that holds gpg's standard error. That file lies
 * next to the home in the test's {@code @TempDir}, which JUnit deletes when the test ends, so a run
 * that failed says nothing about why. The failure used here exits with code 2: a subkey for a key
 * the home does not have.
 * <p>
 * Now the message carries what gpg wrote to standard error for that one call.
 */
class ThrowawayGnuPgHomeTest
{

	/** A fingerprint no key in a fresh home has */
	private static final String NO_SUCH_KEY = "0000000000000000000000000000000000000000";

	@Test
	@DisplayName("a failed gpg call carries what gpg answered into its message")
	void aFailedCallCarriesTheAnswer(@TempDir final Path directory) throws IOException
	{
		try (ThrowawayGnuPgHome home = ThrowawayGnuPgHome.create(directory.resolve("home")))
		{
			IOException failure = assertThrows(IOException.class,
				() -> home.addSubkey(NO_SUCH_KEY, "ed25519", "sign", "1y"));

			assertTrue(failure.getMessage().startsWith("exit code 2 from "), failure.getMessage());
			assertTrue(failure.getMessage().contains(NO_SUCH_KEY + "\" not found"),
				"gpg's own answer is in the message, so the report holds it after the temporary "
					+ "directory is gone: " + failure.getMessage());
		}
	}

	@Test
	@DisplayName("the answer is the failed call's own, not what earlier calls wrote to the same log")
	void theAnswerIsTheFailedCallsOwn(@TempDir final Path directory) throws IOException
	{
		try (ThrowawayGnuPgHome home = ThrowawayGnuPgHome.create(directory.resolve("home")))
		{
			assertThrows(IOException.class,
				() -> home.addSubkey(NO_SUCH_KEY, "ed25519", "sign", "1y"));
			String other = NO_SUCH_KEY.replace('0', '1');

			IOException second = assertThrows(IOException.class,
				() -> home.addSubkey(other, "ed25519", "sign", "1y"));

			assertTrue(second.getMessage().contains(other + "\" not found"), second.getMessage());
			assertFalse(second.getMessage().contains(NO_SUCH_KEY),
				"the first call's answer belongs to the first failure only: "
					+ second.getMessage());
		}
	}
}
