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
package io.github.astrapi69.mystic.crypt.key;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 *
 * The unit test class for the encryption and decryption with the class
 * {@link PublicKeyHexEncryptor} and {@link PrivateKeyHexDecryptor}
 */
public class KeyHexEncryptDecryptorTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * One key-source case: the same round trip runs once over DER files and once over PEM files -
	 * only how the key pair is read differs.
	 */
	record KeySourceCase(String description, ThrowingSupplier<PrivateKey> privateKey,
		ThrowingSupplier<PublicKey> publicKey) {
	}

	static Stream<KeySourceCase> keySourceCases()
	{
		File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		return Stream.of(
			new KeySourceCase("keys read from DER files",
				() -> PrivateKeyReader.readPrivateKey(new File(derDir, "private.der")),
				() -> PublicKeyReader.readPublicKey(new File(derDir, "public.der"))),
			new KeySourceCase("keys read from PEM files",
				() -> PrivateKeyReader.readPemPrivateKey(new File(pemDir, "private.pem")),
				() -> PublicKeyReader.readPemPublicKey(new File(pemDir, "public.pem"))));
	}

	/**
	 * Test encrypt and decrypt with {@link PublicKeyHexEncryptor#encrypt(String)} and
	 * {@link PrivateKeyHexDecryptor#decrypt(String)} over every key source
	 *
	 * @param testCase
	 *            the key-source case
	 * @throws Exception
	 *             is thrown if the encryption or the decryption fails
	 */
	@ParameterizedTest
	@MethodSource("keySourceCases")
	public void testEncryptDecrypt(KeySourceCase testCase) throws Exception
	{
		String expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		PublicKeyHexEncryptor encryptor = new PublicKeyHexEncryptor(testCase.publicKey().get());
		String encrypted = encryptor.encrypt(expected);

		PrivateKeyHexDecryptor decryptor = new PrivateKeyHexDecryptor(testCase.privateKey().get());

		assertEquals(expected, decryptor.decrypt(encrypted), testCase.description());
	}

	/** A supplier whose read may throw - key readers declare checked exceptions. */
	@FunctionalInterface
	interface ThrowingSupplier<T>
	{
		T get() throws Exception;
	}

}
