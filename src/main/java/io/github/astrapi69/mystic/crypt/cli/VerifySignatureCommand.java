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
import java.security.PublicKey;
import java.util.concurrent.Callable;

import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.mystic.crypt.key.KeyFileReader;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Verifies a signature written by the {@code sign} subcommand against a file (or standard input)
 * with an Ed25519, ML-DSA or SLH-DSA public key read from a PEM file. The exit code carries the
 * result: 0 when the signature is valid, 1 when it is not, so shells and scripts can branch on it.
 * An error that prevents the verification altogether - unreadable key, missing file, unknown
 * algorithm - exits with 2, so it can never be mistaken for an invalid signature.
 */
@Command(name = "verify-signature", mixinStandardHelpOptions = true, //
	description = "Verify an Ed25519, ML-DSA or SLH-DSA signature; exit code 0 means valid, "
		+ "1 invalid, 2 an error before verification.")
public class VerifySignatureCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link VerifySignatureCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public VerifySignatureCommand()
	{
	}

	@Option(names = { "-a", "--algorithm" }, required = true, //
		description = "Signature algorithm: RSA, EC (or ECDSA), DSA, Ed25519, ML-DSA-44, ML-DSA-65, "
			+ "ML-DSA-87, an SLH-DSA parameter set such as SLH-DSA-SHA2-128S, or a JCA name such "
			+ "as SHA512withRSA (dashes or underscores accepted).")
	String algorithm;

	@Option(names = "--key", required = true, //
		description = "The file with the public key, PEM or DER.")
	File key;

	@Option(names = "--in", required = true, //
		description = "The signed file, or '-' to read the data from standard input.")
	File in;

	@Option(names = "--signature", required = true, //
		description = "The file with the raw signature bytes to check.")
	File signature;

	@Override
	public Integer call()
	{
		boolean valid;
		try
		{
			String keyFactoryAlgorithm = SignatureSupport.keyFactoryAlgorithm(algorithm);
			byte[] data = CliSupport.readData(in);
			byte[] signatureBytes = Files.readAllBytes(signature.toPath());
			PublicKey publicKey = readPublicKey(keyFactoryAlgorithm);
			valid = SignatureSupport.verify(algorithm, publicKey, data, signatureBytes);
		}
		catch (Exception exception)
		{
			// exit code 2, not 1: a failed verification attempt must never look like an invalid
			// signature to a script that branches on the exit code
			System.err.println(CliSupport.error(String.valueOf(exception)));
			return 2;
		}
		System.out.println(valid ? "signature is valid" : "signature is invalid");
		return valid ? 0 : 1;
	}

	/**
	 * Reads the verification key, accepting PEM and DER alike, through the same provider that will
	 * verify with it for the classical families.
	 *
	 * @param keyFactoryAlgorithm
	 *            the key algorithm the signature algorithm implies
	 * @return the public key
	 */
	private PublicKey readPublicKey(String keyFactoryAlgorithm)
	{
		try
		{
			if (SignatureSupport.isClassical(algorithm))
			{
				return KeyFileReader.readPublicKey(key, keyFactoryAlgorithm);
			}
			return PublicKeyReader.readPemPublicKey(key, keyFactoryAlgorithm);
		}
		catch (Exception exception)
		{
			throw new IllegalArgumentException("could not read a " + keyFactoryAlgorithm
				+ " public key from '" + key + "': " + exception, exception);
		}
	}
}
