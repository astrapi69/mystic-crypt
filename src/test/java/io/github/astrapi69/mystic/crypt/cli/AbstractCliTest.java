/**
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * Base for the CLI tests: runs the root command with a subcommand's arguments via
 * {@link MysticCryptCli#execute} while capturing stdout and stderr, so tests can assert on the
 * printed output and the returned exit code exactly like a shell invocation would.
 */
abstract class AbstractCliTest
{

	/** captured standard output of the most recent {@link #run} call */
	protected String out;

	/** captured standard error of the most recent {@link #run} call */
	protected String err;

	protected int run(String... args)
	{
		PrintStream originalOut = System.out;
		PrintStream originalErr = System.err;
		ByteArrayOutputStream outBuffer = new ByteArrayOutputStream();
		ByteArrayOutputStream errBuffer = new ByteArrayOutputStream();
		System.setOut(new PrintStream(outBuffer, true, StandardCharsets.UTF_8));
		System.setErr(new PrintStream(errBuffer, true, StandardCharsets.UTF_8));
		try
		{
			return MysticCryptCli.execute(args);
		}
		finally
		{
			out = outBuffer.toString(StandardCharsets.UTF_8);
			err = errBuffer.toString(StandardCharsets.UTF_8);
			System.setOut(originalOut);
			System.setErr(originalErr);
		}
	}

	protected int runWithStdin(String stdin, String... args)
	{
		InputStream originalIn = System.in;
		System.setIn(new ByteArrayInputStream(stdin.getBytes(StandardCharsets.UTF_8)));
		try
		{
			return run(args);
		}
		finally
		{
			System.setIn(originalIn);
		}
	}
}
