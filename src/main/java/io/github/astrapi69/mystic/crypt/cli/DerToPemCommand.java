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

import java.io.File;
import java.security.PrivateKey;
import java.util.concurrent.Callable;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Converts a DER-encoded private key to PEM, printing it or writing it to a file.
 */
@Command(name = "der2pem", mixinStandardHelpOptions = true, //
	description = "Deprecated: use 'convert' instead, which detects what the file is and "
		+ "converts in both directions. Convert a DER-encoded private key to PEM.")
public class DerToPemCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link DerToPemCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public DerToPemCommand()
	{
	}

	@Option(names = "--in", required = true, description = "The DER-encoded private key file to read.")
	File in;

	@Option(names = "--out", description = "Write the PEM to this file instead of stdout.")
	File out;

	@Override
	public Integer call() throws Exception
	{
		PrivateKey privateKey = PrivateKeyReader.readPrivateKey(in);
		if (privateKey == null)
		{
			throw new IllegalArgumentException("could not read a private key from '" + in
				+ "' (is it a DER-encoded private key?)");
		}
		CliSupport.writePrivateKeyPem(privateKey, out);
		return 0;
	}
}
