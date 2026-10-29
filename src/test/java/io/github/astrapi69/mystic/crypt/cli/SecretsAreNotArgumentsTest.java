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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Every command that takes a secret reads it from standard input or asks for it in a terminal; the
 * argument that held it still works through 13.x, with a warning, and goes away in 14.0 (#214). The
 * test JVM has no terminal, so a command given neither refuses and names the way that works.
 */
class SecretsAreNotArgumentsTest extends AbstractCliTest
{

	private static final String SECRET = "the secret";

	private static final AtomicInteger FRESH = new AtomicInteger();

	@TempDir
	static Path directory;

	private static String pbkdf2Hash;

	private static Path plain;

	private static Path encrypted;

	@BeforeAll
	static void writeWhatTheCommandsReadBack() throws IOException
	{
		plain = Files.writeString(directory.resolve("plain.txt"), "the text");
		encrypted = directory.resolve("plain.txt.mcrypt");
		AbstractCliTest setup = new AbstractCliTest()
		{
		};
		assertEquals(0, setup.runWithStdin(SECRET + "\n", "encrypt", "-i", plain.toString(), "-o",
			encrypted.toString(), "--passphrase-stdin"), setup.err);
		assertEquals(0,
			setup.runWithStdin(SECRET + "\n", "hash", "--algorithm", "pbkdf2", "--password-stdin"),
			setup.err);
		pbkdf2Hash = setup.out.strip();
	}

	/**
	 * One command that takes a secret: how it is called apart from the secret, the argument that is
	 * going away, and its standard input flag
	 */
	record SecretCommand(String name, Supplier<List<String>> call, String argument,
		String stdinFlag) {

		String[] with(final String... more)
		{
			List<String> arguments = new ArrayList<>(call.get());
			arguments.addAll(List.of(more));
			return arguments.toArray(String[]::new);
		}

		@Override
		public String toString()
		{
			return name + " " + argument;
		}
	}

	static Stream<Arguments> commandsThatTakeASecret()
	{
		return Stream.of(
			new SecretCommand("hash", () -> List.of("hash", "--algorithm", "pbkdf2"), "--password",
				"--password-stdin"),
			new SecretCommand("verify", () -> List.of("verify", "--hash", pbkdf2Hash), "--password",
				"--password-stdin"),
			new SecretCommand("checksum", () -> List.of("checksum", "--hmac", plain.toString()),
				"--key", "--key-stdin"),
			new SecretCommand("encrypt",
				() -> List.of("encrypt", "-i", plain.toString(), "-o", fresh("encrypted")),
				"--passphrase", "--passphrase-stdin"),
			new SecretCommand("decrypt",
				() -> List.of("decrypt", "-i", encrypted.toString(), "-o", fresh("decrypted")),
				"--passphrase", "--passphrase-stdin"),
			new SecretCommand("keystore",
				() -> List.of("keystore", "create", "--file", fresh("store") + ".p12"),
				"--password", "--password-stdin"),
			new SecretCommand("share", () -> List.of("share", "split", "-t", "2", "-n", "3"),
				"--secret", "--secret-stdin"))
			.map(Arguments::of);
	}

	private static String fresh(final String name)
	{
		return directory.resolve(name + "-" + FRESH.incrementAndGet()).toString();
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("commandsThatTakeASecret")
	@DisplayName("the secret as an argument still works, and warns that it goes away in 14.0")
	void theArgument_works_andWarns(final SecretCommand command)
	{
		assertEquals(0, run(command.with(command.argument(), SECRET)), err);

		assertTrue(err.contains(command.argument()) && err.contains("14.0")
			&& err.contains(command.stdinFlag()), err);
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("commandsThatTakeASecret")
	@DisplayName("the secret on standard input works without a warning")
	void standardInput_works_withoutAWarning(final SecretCommand command)
	{
		assertEquals(0, runWithStdin(SECRET + "\n", command.with(command.stdinFlag())), err);

		assertFalse(err.contains("warning"), err);
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("commandsThatTakeASecret")
	@DisplayName("without a terminal and without standard input the command refuses and names the way that works")
	void neither_withoutATerminal_refuses(final SecretCommand command)
	{
		assertNotEquals(0, run(command.with()));

		assertTrue(err.contains(command.stdinFlag()) && err.contains("terminal"), err);
		assertFalse(err.contains("pass " + command.argument() + " "), err);
	}

	@Test
	@DisplayName("keystore -p without a value asks, as it did; without a terminal it refuses")
	void keystoreDashP_withoutAValue_asks()
	{
		assertNotEquals(0, run("keystore", "create", "--file", fresh("store") + ".p12", "-p"));

		assertTrue(err.contains("--password-stdin") && err.contains("terminal"), err);
		assertFalse(err.contains("14.0"), "asking is not the deprecated way: " + err);
	}

	@Test
	@DisplayName("an empty standard input is refused, it is not an empty secret")
	void emptyStandardInput_isRefused()
	{
		assertNotEquals(0, runWithStdin("", "hash", "--password-stdin"));

		assertTrue(err.contains("standard input"), err);
	}

	@Test
	@DisplayName("the warning goes to standard error, so a script that reads the output gets only the result")
	void theWarning_staysOutOfStandardOutput()
	{
		assertEquals(0, run("hash", "--algorithm", "pbkdf2", "--password", SECRET));

		assertFalse(out.contains("warning"), out);
		assertEquals(1, out.strip().lines().count(), out);
	}
}
