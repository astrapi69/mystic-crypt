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

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * The {@code release-key} command group: the state of an OpenPGP release key, read with Bouncy
 * Castle, never through gpg. Stage 1 has one subcommand, {@code status}, which only reads.
 */
@Command(name = "release-key", mixinStandardHelpOptions = true, //
	description = "The state of an OpenPGP release key in a GnuPG home, read with Bouncy Castle: "
		+ "nothing is written to the home and gpg is never run.", //
	subcommands = { ReleaseKeyStatusCommand.class })
public class ReleaseKeyCommand implements Runnable
{

	/**
	 * Instantiates a new {@link ReleaseKeyCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public ReleaseKeyCommand()
	{
	}

	@Override
	public void run()
	{
		CommandLine.usage(this, System.out);
	}
}
