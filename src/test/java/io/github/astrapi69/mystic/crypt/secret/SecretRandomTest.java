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
package io.github.astrapi69.mystic.crypt.secret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Salts, nonces, IVs and generated passwords come from {@link java.security.SecureRandom} directly,
 * never through randomizer, which generates test data (#241, GHSA-rmpr-hqmh-r8gp)
 */
class SecretRandomTest
{

	private static final String ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyz"
		+ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	@Test
	@DisplayName("no class of the library refers to randomizer")
	void noMainClass_refersToRandomizer() throws IOException, URISyntaxException
	{
		Path classes = Path
			.of(SecretRandom.class.getProtectionDomain().getCodeSource().getLocation().toURI());
		List<Path> refersToIt;
		try (Stream<Path> files = Files.walk(classes))
		{
			refersToIt = files.filter(file -> file.toString().endsWith(".class"))
				.filter(SecretRandomTest::refersToRandomizer).toList();
		}

		assertTrue(refersToIt.isEmpty(),
			"randomizer is for test data; these classes still use it: " + refersToIt);
	}

	@Test
	@DisplayName("bytes come in the asked length, and two draws differ")
	void bytes_haveTheLength_andDiffer()
	{
		byte[] first = SecretRandom.bytes(32);
		byte[] second = SecretRandom.bytes(32);

		assertEquals(32, first.length);
		assertFalse(Arrays.equals(first, second));
		assertEquals(0, SecretRandom.bytes(0).length);
	}

	@Test
	@DisplayName("an alphanumeric string has the length and draws every one of the 62 characters")
	void alphanumeric_hasTheLength_andDrawsEveryCharacter()
	{
		String drawn = SecretRandom.alphanumeric(62 * 200);

		assertEquals(62 * 200, drawn.length());
		assertTrue(drawn.chars().allMatch(c -> ALPHANUMERIC.indexOf(c) >= 0),
			"only letters and digits");
		assertTrue(ALPHANUMERIC.chars().allMatch(c -> drawn.indexOf(c) >= 0),
			"12400 draws reach every one of the 62 characters");
	}

	private static boolean refersToRandomizer(final Path classFile)
	{
		try
		{
			return new String(Files.readAllBytes(classFile), StandardCharsets.ISO_8859_1)
				.contains("io/github/astrapi69/random/");
		}
		catch (IOException unreadable)
		{
			throw new IllegalStateException("cannot read " + classFile, unreadable);
		}
	}
}
