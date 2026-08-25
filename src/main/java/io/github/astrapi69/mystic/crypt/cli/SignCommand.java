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
import java.nio.file.Files;
import java.security.PrivateKey;
import java.util.concurrent.Callable;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Signs a file (or standard input) with an Ed25519, ML-DSA or SLH-DSA private key read from a PEM
 * file and writes the raw signature bytes to a file. The matching {@code verify-signature}
 * subcommand checks such a signature.
 */
@Command(name = "sign", mixinStandardHelpOptions = true, //
	description = "Sign a file (or standard input) with an Ed25519, ML-DSA or SLH-DSA private key.")
public class SignCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link SignCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public SignCommand()
	{
	}

	@Option(names = { "-a", "--algorithm" }, required = true, //
		description = "Signature algorithm: Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87 or an "
			+ "SLH-DSA parameter set such as SLH-DSA-SHA2-128S (dashes or underscores accepted).")
	String algorithm;

	@Option(names = "--key", required = true, //
		description = "The PEM file with the private key.")
	File key;

	@Option(names = "--in", required = true, //
		description = "The file to sign, or '-' to read the data from standard input.")
	File in;

	@Option(names = "--signature", required = true, //
		description = "Write the raw signature bytes to this file.")
	File signature;

	@Override
	public Integer call() throws Exception
	{
		if ("-".equals(signature.getPath()))
		{
			// without this guard a file literally named '-' would silently appear in the working
			// directory - surprising for users who learned the '-' convention from --in
			throw new IllegalArgumentException(
				"writing the signature to standard output is not supported; pass a file path "
					+ "for --signature");
		}
		String keyFactoryAlgorithm = SignatureSupport.keyFactoryAlgorithm(algorithm);
		byte[] data = CliSupport.readData(in);
		PrivateKey privateKey;
		try
		{
			privateKey = PrivateKeyReader.readPemPrivateKey(key, keyFactoryAlgorithm);
		}
		catch (Exception exception)
		{
			throw new IllegalArgumentException("could not read a " + keyFactoryAlgorithm
				+ " private key from '" + key + "': " + exception, exception);
		}
		byte[] signatureBytes = SignatureSupport.sign(algorithm, privateKey, data);
		Files.write(signature.toPath(), signatureBytes);
		System.out.println("wrote signature to " + signature);
		return 0;
	}
}
