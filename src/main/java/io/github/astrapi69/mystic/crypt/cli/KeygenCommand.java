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

import java.io.File;
import java.security.KeyPair;
import java.util.concurrent.Callable;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Generates a key pair for a chosen algorithm and prints, or writes to files, its private and
 * public key in PEM format. Classical size-based algorithms (RSA, DSA) use {@code --size}; the
 * modern fixed-parameter algorithms (X25519/X448, ML-KEM, ML-DSA, ...) ignore it.
 */
@Command(name = "keygen", mixinStandardHelpOptions = true, //
	description = "Generate a key pair and print (or write) its keys as PEM.")
public class KeygenCommand implements Callable<Integer>
{

	@Option(names = { "-a", "--algorithm" }, defaultValue = "RSA", //
		description = "Key algorithm, e.g. RSA, X25519, X448, ML-KEM-768, ML-DSA-65 "
			+ "(dashes or underscores accepted; default: RSA).")
	String algorithm;

	@Option(names = { "-s", "--size" }, defaultValue = "2048", //
		description = "Key size in bits for size-based algorithms like RSA (default: 2048).")
	int size;

	@Option(names = "--out-private", description = "Write the private key PEM to this file instead of stdout.")
	File outPrivate;

	@Option(names = "--out-public", description = "Write the public key PEM to this file instead of stdout.")
	File outPublic;

	@Override
	public Integer call() throws Exception
	{
		KeyPairGeneratorAlgorithm keyPairAlgorithm = CliSupport.parseKeyPairAlgorithm(algorithm);
		KeyPair keyPair = CliSupport.isSizeBased(keyPairAlgorithm)
			? KeyPairFactory.newKeyPair(keyPairAlgorithm, size)
			: KeyPairFactory.newKeyPair(keyPairAlgorithm);

		CliSupport.writePrivateKeyPem(keyPair.getPrivate(), outPrivate);
		CliSupport.writePublicKeyPem(keyPair.getPublic(), outPublic);
		return 0;
	}
}
