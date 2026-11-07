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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Salts, nonces, IVs and generated passwords come from {@link java.security.SecureRandom} directly,
 * never through randomizer, which generates test data (#241, GHSA-rmpr-hqmh-r8gp)
 */
class SecretRandomTest
{

	private static final String ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyz"
		+ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	/** the 94 printable ASCII characters without the space, the alphabet of a password generator */
	private static final String PRINTABLE = IntStream.rangeClosed('!', '~')
		.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
		.toString();

	/** how often each character of {@link #PRINTABLE} is expected in the distribution test */
	private static final int EXPECTED_PER_CHARACTER = 1000;

	/**
	 * How far the count of a character may stray from {@link #EXPECTED_PER_CHARACTER}: 20 percent,
	 * 200 draws. With 94000 draws over 94 characters the standard deviation of a count is about
	 * 31.5, so 200 is more than 6 standard deviations, and a uniform draw leaves the tolerance with
	 * a probability below 1 in 10 million over all 94 characters.
	 */
	private static final int TOLERANCE = EXPECTED_PER_CHARACTER / 5;

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

	@Test
	@DisplayName("characters come in the asked length, only from the alphabet, and two draws differ")
	void characters_haveTheLength_comeFromTheAlphabet_andDiffer()
	{
		char[] drawn = SecretRandom.characters(1000, PRINTABLE);

		assertEquals(1000, drawn.length);
		for (char character : drawn)
		{
			assertTrue(PRINTABLE.indexOf(character) >= 0, "not in the alphabet: " + character);
		}
		assertFalse(
			Arrays.equals(SecretRandom.characters(32, PRINTABLE),
				SecretRandom.characters(32, PRINTABLE)),
			"two draws of 32 characters from 94 are equal with a probability of 94^-32");
	}

	@Test
	@DisplayName("every character of the alphabet is drawn equally often, where bytes modulo 94 are not")
	void characters_drawEveryCharacterEquallyOften_whereAModuloDoesNot()
	{
		int draws = PRINTABLE.length() * EXPECTED_PER_CHARACTER;

		int[] counts = countsOf(SecretRandom.characters(draws, PRINTABLE));
		int[] moduloCounts = new int[PRINTABLE.length()];
		for (byte drawnByte : SecretRandom.bytes(draws))
		{
			moduloCounts[Byte.toUnsignedInt(drawnByte) % PRINTABLE.length()]++;
		}

		assertTrue(allWithinTolerance(counts), "counts per character: " + Arrays.toString(counts));
		// 256 = 2 * 94 + 68: a byte modulo 94 hits the characters 68 to 93 two times in 256
		// instead of 256 / 94, about 734 times in 94000 draws instead of 1000. That is more than
		// 2 standard deviations below the tolerance for each of the 26, so all 26 stay inside it
		// with a probability far below 1 in 10^40: the test can tell a biased draw.
		assertFalse(allWithinTolerance(moduloCounts),
			"the modulo draw stays inside the tolerance: " + Arrays.toString(moduloCounts));
	}

	@Test
	@DisplayName("a character that appears more than once in the alphabet counts once")
	void characters_countARepeatedCharacterOnce()
	{
		char[] drawn = SecretRandom.characters(10_000, "aaaaaaaaab");

		long drawnB = new String(drawn).chars().filter(character -> character == 'b').count();
		// counted once, b is half of the 10000 draws (standard deviation 50); weighted by the
		// nine a it would be a tenth
		assertTrue(4000 < drawnB && drawnB < 6000, "b drawn " + drawnB + " times in 10000");
	}

	/**
	 * A boundary of the draw
	 *
	 * @param description
	 *            the case
	 * @param length
	 *            how many characters
	 * @param alphabet
	 *            the alphabet
	 */
	record Boundary(String description, int length, String alphabet) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<Boundary> boundaries()
	{
		return Stream.of(new Boundary("no character", 0, "abc"),
			new Boundary("one character", 1, "abc"),
			new Boundary("an alphabet of one character", 50, "x"));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("boundaries")
	@DisplayName("characters at the boundaries have the length and come from the alphabet")
	void characters_atTheBoundaries(final Boundary boundary)
	{
		char[] drawn = SecretRandom.characters(boundary.length(), boundary.alphabet());

		assertEquals(boundary.length(), drawn.length);
		for (char character : drawn)
		{
			assertTrue(boundary.alphabet().indexOf(character) >= 0,
				"not in the alphabet: " + character);
		}
	}

	/**
	 * An argument that characters refuses
	 *
	 * @param description
	 *            the case
	 * @param length
	 *            how many characters
	 * @param alphabet
	 *            the alphabet
	 * @param refusedWith
	 *            the exception expected
	 * @param named
	 *            what the message names
	 */
	record Refusal(String description, int length, CharSequence alphabet,
		Class<? extends RuntimeException> refusedWith, String named) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<Refusal> refusals()
	{
		return Stream.of(
			new Refusal("a null alphabet", 1, null, NullPointerException.class, "alphabet"),
			new Refusal("an empty alphabet", 1, "", IllegalArgumentException.class, "alphabet"),
			new Refusal("a length below 0", -1, "abc", IllegalArgumentException.class, "length"),
			new Refusal("an alphabet with a surrogate pair", 1, "ab😀",
				IllegalArgumentException.class, "surrogate"));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("refusals")
	@DisplayName("characters refuses an argument it cannot draw with, and names the argument")
	void characters_refuse(final Refusal refusal)
	{
		RuntimeException refused = assertThrows(refusal.refusedWith(),
			() -> SecretRandom.characters(refusal.length(), refusal.alphabet()));

		assertTrue(refused.getMessage().contains(refusal.named()), refused.getMessage());
	}

	private static int[] countsOf(final char[] drawn)
	{
		int[] counts = new int[PRINTABLE.length()];
		for (char character : drawn)
		{
			counts[PRINTABLE.indexOf(character)]++;
		}
		return counts;
	}

	private static boolean allWithinTolerance(final int[] counts)
	{
		return Arrays.stream(counts)
			.allMatch(count -> Math.abs(count - EXPECTED_PER_CHARACTER) <= TOLERANCE);
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
