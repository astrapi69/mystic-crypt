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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the operated obfuscation rules {@code obfuscate} and {@code disentangle} gained: a
 * rule that carries an operation and the positions it applies at, next to the plain substitution.
 */
class OperatedObfuscationCommandTest extends AbstractCliTest
{

	private String obfuscate(String text, String... rules)
	{
		String[] args = new String[3 + 2 * rules.length];
		args[0] = "obfuscate";
		args[1] = "--text";
		args[2] = text;
		for (int i = 0; i < rules.length; i++)
		{
			args[3 + 2 * i] = "--rule";
			args[4 + 2 * i] = rules[i];
		}
		assertEquals(0, run(args), "obfuscating failed, stderr was: '" + err + "'");
		return out.strip();
	}

	private String disentangle(String text, String... rules)
	{
		String[] args = new String[3 + 2 * rules.length];
		args[0] = "disentangle";
		args[1] = "--text";
		args[2] = text;
		for (int i = 0; i < rules.length; i++)
		{
			args[3 + 2 * i] = "--rule";
			args[4 + 2 * i] = rules[i];
		}
		assertEquals(0, run(args), "disentangling failed, stderr was: '" + err + "'");
		return out.strip();
	}

	/**
	 * At a named position the operated character is written, everywhere else the plain replacement.
	 * The round trip has to give back exactly what went in.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "aba", "banana", "aaa", "abcabc", "nothing to replace", "" })
	void anOperatedRuleSurvivesTheRoundTrip(String text)
	{
		String[] rules = { "a=x:UPPERCASE@0,3", "b=y:LOWERCASE@1", "c=z" };

		String obfuscated = obfuscate(text, rules);

		assertEquals(text, disentangle(obfuscated, rules),
			"'" + text + "' became '" + obfuscated + "' and must come back unchanged");
	}

	@Test
	void theOperatedCharacterStandsAtTheNamedPositionAndTheReplacementElsewhere()
	{
		assertEquals("Ayx", obfuscate("aba", "a=x:UPPERCASE@0", "b=y"),
			"position 0 carries the uppercase A, position 2 the plain replacement x");
	}

	/**
	 * NONE is not "no rule": at a named position it writes the character unchanged, which is what
	 * operating with NONE produces, while everywhere else the plain replacement still applies.
	 */
	@ParameterizedTest
	@CsvSource({ "UPPERCASE, aa, Ax", "LOWERCASE, AA, aX", "NONE, aa, ax" })
	void eachOperationWritesItsOwnCharacterAtThePosition(String operation, String input,
		String expected)
	{
		assertEquals(expected,
			obfuscate(input, "a=x:" + operation + "@0", "A=X:" + operation + "@0"),
			operation + " on '" + input + "'");
	}

	@Test
	void aPlainRuleStandingNextToAnOperatedOneStillSubstitutesEverywhere()
	{
		assertEquals("Ayz", obfuscate("abc", "a=x:UPPERCASE@0", "b=y", "c=z"));
		assertEquals("abc", disentangle("Ayz", "a=x:UPPERCASE@0", "b=y", "c=z"));
	}

	@Test
	void theplainFormIsUnchangedByTheOperatedOneExisting()
	{
		assertEquals("xyc", obfuscate("abc", "a=x", "b=y"));
		assertEquals("abc", disentangle("xyc", "a=x", "b=y"));
	}

	@Test
	void anOperatedRuleDiffersFromThePlainOneItWouldOtherwiseBe()
	{
		assertNotEquals(obfuscate("aba", "a=x", "b=y"), obfuscate("aba", "a=x:UPPERCASE@0", "b=y"),
			"the operation must make a difference at the named position");
	}

	@ParameterizedTest
	@ValueSource(strings = { "a=x:NOPE", "a=x:UPPERCASE@notanumber", "a=x:UPPERCASE@-1",
			"a=xy:UPPERCASE@0", "a=xy" })
	void aMalformedRuleIsRefusedWithTheReason(String rule)
	{
		int exitCode = run("obfuscate", "--text", "abc", "--rule", rule);

		assertEquals(2, exitCode, "'" + rule + "' must be refused, stderr was: '" + err + "'");
		assertTrue(err.contains("error"), "the failure must be explained for '" + rule + "'");
	}

	@Test
	void anUnknownOperationListsTheOnesThatExist()
	{
		assertEquals(2, run("obfuscate", "--text", "abc", "--rule", "a=x:ROT13"));

		assertTrue(err.contains("UPPERCASE") && err.contains("NEGATE"),
			"the message must list the operations, but was: '" + err + "'");
	}

	@Test
	void bothCommandsExplainTheOperatedShapeInTheirHelp()
	{
		assertEquals(0, run("obfuscate", "--help"));
		assertTrue(out.contains("UPPERCASE"),
			"the help must show the operated shape, but was: '" + out + "'");
	}
}
