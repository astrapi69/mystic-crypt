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
package io.github.astrapi69.mystic.crypt.file;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;

/**
 * Regression tests proving that {@link PBEFileEncryptor} actually applies the
 * {@link CryptObjectDecorator}s of its {@link CryptModel} and that {@link PBEFileDecryptor} strips
 * all of them again.
 * <p>
 * Both halves used to be broken in a way that cancelled out: the encryptor discarded the decorated
 * string returned by {@code decorateFile} and encrypted the raw file, and the decryptor re-read the
 * file on every loop iteration so only the innermost decorator was ever removed. A plain
 * encrypt-then-decrypt round trip passed regardless - "never added" and "never removed" agree -
 * which is why these tests also decrypt <em>without</em> the decorators to look at what was really
 * encrypted.
 */
class PBEFileDecoratorRoundTripTest
{

	private static final String PLAINTEXT = "Hello decorators - ü ö ä €";
	private static final String PASSWORD = "foo";
	/**
	 * The PBE file format does not carry the salt, so encryptor and decryptor must agree on it via
	 * the model; a fixed salt lets the tests build separate models (with and without decorators)
	 * that still decrypt each other's output.
	 */
	private static final byte[] SALT = { 1, 2, 3, 4, 5, 6, 7, 8 };

	@TempDir
	Path tempDir;

	File toEncrypt;

	@BeforeEach
	void setUp() throws Exception
	{
		toEncrypt = tempDir.resolve("plain.txt").toFile();
		Files.writeString(toEncrypt.toPath(), PLAINTEXT, StandardCharsets.UTF_8);
	}

	/**
	 * A decorator set and the content that must come out of the decryptor when the decorators are
	 * <em>not</em> applied on the way back - i.e. exactly what the encryptor put into the
	 * ciphertext.
	 */
	record DecoratorCase(String name, List<CryptObjectDecorator<String>> decorators,
		String expectedDecorated) {
		@Override
		public String toString()
		{
			return name;
		}
	}

	static Stream<DecoratorCase> decoratorCases()
	{
		CryptObjectDecorator<String> dollar = CryptObjectDecorator.<String> builder().prefix("$")
			.suffix("?").build();
		CryptObjectDecorator<String> angle = CryptObjectDecorator.<String> builder().prefix("<<")
			.suffix(">>").build();
		CryptObjectDecorator<String> prefixOnly = CryptObjectDecorator.<String> builder()
			.prefix("BEGIN:").suffix("").build();
		return Stream.of(new DecoratorCase("single", List.of(dollar), "$" + PLAINTEXT + "?"),
			// applied in list order: the last decorator ends up outermost
			new DecoratorCase("two, nested", List.of(dollar, angle), "<<$" + PLAINTEXT + "?>>"),
			new DecoratorCase("three, nested", List.of(angle, dollar, prefixOnly),
				"BEGIN:$<<" + PLAINTEXT + ">>?"));
	}

	private CryptModel<Cipher, String, String> model(List<CryptObjectDecorator<String>> decorators)
	{
		var builder = CryptModel.<Cipher, String, String> builder().key(PASSWORD)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(SALT);
		for (CryptObjectDecorator<String> decorator : decorators)
		{
			builder.decorator(decorator);
		}
		return builder.build();
	}

	private String encryptThenDecrypt(List<CryptObjectDecorator<String>> encryptWith,
		List<CryptObjectDecorator<String>> decryptWith, String tag) throws Exception
	{
		File encrypted = tempDir.resolve(tag + ".enc").toFile();
		File decrypted = tempDir.resolve(tag + ".decrypted").toFile();
		new PBEFileEncryptor(model(encryptWith), encrypted).encrypt(toEncrypt);
		new PBEFileDecryptor(model(decryptWith), decrypted).decrypt(encrypted);
		return Files.readString(decrypted.toPath(), StandardCharsets.UTF_8);
	}

	/**
	 * Decrypting without the decorators exposes what was really encrypted: it must be the decorated
	 * content, not the raw file. This is the assertion the original bug failed.
	 */
	@ParameterizedTest
	@MethodSource("decoratorCases")
	void encryptAppliesDecoratorsInOrder(DecoratorCase testCase) throws Exception
	{
		String whatWasEncrypted = encryptThenDecrypt(testCase.decorators(), List.of(), "raw");

		assertEquals(testCase.expectedDecorated(), whatWasEncrypted);
		assertNotEquals(PLAINTEXT, whatWasEncrypted);
	}

	/**
	 * Decrypting with the same decorators must strip every one of them, outermost first, and
	 * recover the original - including for more than one decorator, which the old decryptor loop
	 * got wrong.
	 */
	@ParameterizedTest
	@MethodSource("decoratorCases")
	void decryptStripsAllDecorators(DecoratorCase testCase) throws Exception
	{
		assertEquals(PLAINTEXT,
			encryptThenDecrypt(testCase.decorators(), testCase.decorators(), "roundtrip"));
	}

	/**
	 * Decoration must happen in memory: the caller's source file is not rewritten.
	 */
	@Test
	void encryptDoesNotModifyTheSourceFile() throws Exception
	{
		List<CryptObjectDecorator<String>> decorators = decoratorCases().toList().get(1)
			.decorators();
		File encrypted = tempDir.resolve("untouched.enc").toFile();

		new PBEFileEncryptor(model(decorators), encrypted).encrypt(toEncrypt);

		assertEquals(PLAINTEXT, Files.readString(toEncrypt.toPath(), StandardCharsets.UTF_8));
	}

	/**
	 * Without decorators the raw file content is encrypted, as before.
	 */
	@Test
	void encryptWithoutDecoratorsEncryptsRawContent() throws Exception
	{
		assertEquals(PLAINTEXT, encryptThenDecrypt(List.of(), List.of(), "plain"));
	}

}
