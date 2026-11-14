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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Logger;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the diagnosis of a read keeps for the report of a failed GnuPG test (#309): the key files
 * the home held, and what the reader said about them while it read
 */
class ReadingDiagnosisTest
{

	@Test
	@DisplayName("a key file the reader cannot read is named, with the reader's own words")
	void record_namesTheKeyFileTheReaderCouldNotRead(@TempDir final Path home) throws IOException
	{
		Path keys = Files.createDirectories(home.resolve(GnuPgHome.PRIVATE_KEYS));
		Files.writeString(keys.resolve("ABCDEF.key"), "not a key file", StandardCharsets.US_ASCII);

		ReadingDiagnosis.Recorded<SecretKeyFiles> recorded = ReadingDiagnosis.record(home,
			() -> SecretKeyFiles.in(keys));

		assertTrue(recorded.diagnosis().contains("ABCDEF.key, 14 bytes"), recorded.diagnosis());
		assertTrue(recorded.diagnosis().contains("could not read the key file"),
			recorded.diagnosis());
	}

	@Test
	@DisplayName("a home without key files says so, and that the reader said nothing")
	void record_saysWhenThereIsNothingToReport(@TempDir final Path home) throws IOException
	{
		ReadingDiagnosis.Recorded<SecretKeyFiles> recorded = ReadingDiagnosis.record(home,
			() -> SecretKeyFiles.in(home.resolve(GnuPgHome.PRIVATE_KEYS)));

		assertTrue(recorded.diagnosis().contains("no " + GnuPgHome.PRIVATE_KEYS),
			recorded.diagnosis());
		assertTrue(recorded.diagnosis().contains("the reader logged nothing"),
			recorded.diagnosis());
	}

	@Test
	@DisplayName("the result of the read is handed through, and the listener leaves with the read")
	void record_handsTheResultThroughAndRemovesItsListener(@TempDir final Path home)
		throws IOException
	{
		Logger logger = Logger.getLogger(SecretKeyFiles.class.getName());
		List<Handler> before = List.of(logger.getHandlers());

		ReadingDiagnosis.Recorded<String> recorded = ReadingDiagnosis.record(home, () -> "read");

		assertEquals("read", recorded.result());
		assertEquals(before, List.of(logger.getHandlers()));
		assertFalse(recorded.diagnosis().isBlank());
	}
}
