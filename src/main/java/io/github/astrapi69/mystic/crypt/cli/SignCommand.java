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
import io.github.astrapi69.mystic.crypt.key.KeyFileReader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Signs a file (or standard input) with a private key read from a PEM or DER file and writes the
 * raw signature bytes to a file. RSA, ECDSA and DSA are signed through Bouncy Castle, as are their
 * keys decoded; Ed25519, ML-DSA and SLH-DSA go through their own signer classes. The matching
 * {@code verify-signature} subcommand checks such a signature.
 */
@Command(name = "sign", mixinStandardHelpOptions = true, //
	description = "Sign a file (or standard input) with an RSA, ECDSA, DSA, Ed25519, ML-DSA or "
		+ "SLH-DSA private key, from a PEM or DER file.")
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
		description = "Signature algorithm: RSA, EC (or ECDSA), DSA, Ed25519, ML-DSA-44, ML-DSA-65, "
			+ "ML-DSA-87, an SLH-DSA parameter set such as SLH-DSA-SHA2-128S, or a JCA name such "
			+ "as SHA512withRSA (dashes or underscores accepted).")
	String algorithm;

	@Option(names = "--key", required = true, //
		description = "The file with the private key, PEM or DER.")
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
		// this command guarded its output path from the start; the guard lives in CliSupport now,
		// because every other command needed the same one (issue #101)
		CliSupport.refuseDashAsPath(signature, "--signature", CliSupport.PASS_A_PATH);
		String keyFactoryAlgorithm = SignatureSupport.keyFactoryAlgorithm(algorithm);
		byte[] data = CliSupport.readData(in);
		PrivateKey privateKey = readPrivateKey(keyFactoryAlgorithm);
		byte[] signatureBytes = SignatureSupport.sign(algorithm, privateKey, data);
		Files.write(signature.toPath(), signatureBytes);
		System.out.println("wrote signature to " + signature);
		return 0;
	}

	/**
	 * Reads the signing key, accepting PEM and DER alike.
	 * <p>
	 * The classical families go through {@link KeyFileReader}, which decodes with the same Bouncy
	 * Castle provider that signs; the post-quantum and Ed25519 families keep the crypt-data reader
	 * they already used, whose provider lookup is not in question for them.
	 *
	 * @param keyFactoryAlgorithm
	 *            the key algorithm the signature algorithm implies
	 * @return the private key
	 */
	private PrivateKey readPrivateKey(String keyFactoryAlgorithm)
	{
		try
		{
			if (SignatureSupport.isClassical(algorithm))
			{
				return KeyFileReader.readPrivateKey(key, keyFactoryAlgorithm);
			}
			return PrivateKeyReader.readPemPrivateKey(key, keyFactoryAlgorithm);
		}
		catch (Exception exception)
		{
			throw new IllegalArgumentException("could not read a " + keyFactoryAlgorithm
				+ " private key from '" + key + "': " + exception, exception);
		}
	}
}
