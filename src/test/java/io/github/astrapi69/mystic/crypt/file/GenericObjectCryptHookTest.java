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
package io.github.astrapi69.mystic.crypt.file;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.NotSerializableException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.test.object.Person;
import io.github.astrapi69.test.object.enumeration.Gender;

/**
 * The unit test class for the extension hooks of the class {@link GenericObjectEncryptor} and the
 * class {@link GenericObjectDecryptor}
 * <p>
 * {@code onBeforeEncrypt}, {@code onAfterEncrypt}, {@code onBeforeDecrypt} and
 * {@code onAfterDecrypt} are the documented extension points of these two classes: a subclass
 * overrides them to run its own pre- and post-processing. Without a test that observes them, the
 * calls could be dropped from {@link GenericObjectEncryptor#encrypt(Object)} and
 * {@link GenericObjectDecryptor#decrypt(File)} without a single test turning red, and every
 * subclass hook would silently stop running. These tests pin that both hooks are invoked, with the
 * object respectively the file that is being processed, and that they bracket the actual crypt
 * step.
 */
public class GenericObjectCryptHookTest
{

	private static final String KEY = "D1D15ED36B887AF1";

	/** a fixed salt so that separately built encryptor and decryptor models derive the same key */
	private static final byte[] SALT = { 1, 2, 3, 4, 5, 6, 7, 8 };

	/** the temporary directory of the current test */
	@TempDir
	File temporaryDirectory;

	private static CryptModel<Cipher, String, String> newCryptModel()
	{
		return CryptModel.<Cipher, String, String> builder().key(KEY)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(SALT).build();
	}

	/**
	 * A scenario with a serializable payload that is sent through the generic object cryptors
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param payload
	 *            the object to encrypt and decrypt again
	 */
	record ObjectCryptCase(String description, Serializable payload) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<ObjectCryptCase> objectCryptCases()
	{
		return Stream.of(new ObjectCryptCase("a string payload", "Foo bar i will be encrypted"),
			new ObjectCryptCase("a person payload",
				Person.builder().about("about").name("Foo").gender(Gender.MALE).build()),
			new ObjectCryptCase("a number payload", Integer.valueOf(42)));
	}

	/**
	 * A {@link GenericObjectEncryptor} that records every invocation of its extension hooks, the
	 * argument the hook received and the number of bytes the target file holds at that moment
	 *
	 * @param <T>
	 *            the generic type of the object to encrypt
	 */
	static class RecordingObjectEncryptor<T> extends GenericObjectEncryptor<T, String>
	{
		/** The Constant serialVersionUID. */
		private static final long serialVersionUID = 1L;

		/** the recorded hook invocations in the order they happened */
		final transient List<String> events = new ArrayList<>();

		/** the arguments the recorded hooks received in the order they happened */
		final transient List<T> arguments = new ArrayList<>();

		private final transient File target;

		RecordingObjectEncryptor(final CryptModel<Cipher, String, String> model,
			final File encryptedFile) throws Exception
		{
			super(model, encryptedFile);
			this.target = encryptedFile;
		}

		@Override
		protected void onBeforeEncrypt(final T toEncrypt)
		{
			super.onBeforeEncrypt(toEncrypt);
			this.arguments.add(toEncrypt);
			this.events.add("onBeforeEncrypt(" + toEncrypt + ") targetBytes=" + target.length());
		}

		@Override
		protected void onAfterEncrypt(final T toEncrypt)
		{
			super.onAfterEncrypt(toEncrypt);
			this.arguments.add(toEncrypt);
			this.events.add("onAfterEncrypt(" + toEncrypt + ") targetBytes=" + target.length());
		}
	}

	/**
	 * A {@link GenericObjectDecryptor} that records every invocation of its extension hooks and the
	 * argument the hook received
	 *
	 * @param <R>
	 *            the generic type of the object that the decryption returns
	 */
	static class RecordingObjectDecryptor<R> extends GenericObjectDecryptor<R, String>
	{
		/** The Constant serialVersionUID. */
		private static final long serialVersionUID = 1L;

		/** the recorded hook invocations in the order they happened */
		final transient List<String> events = new ArrayList<>();

		/** the arguments the recorded hooks received in the order they happened */
		final transient List<File> arguments = new ArrayList<>();

		RecordingObjectDecryptor(final CryptModel<Cipher, String, String> model) throws Exception
		{
			super(model);
		}

		@Override
		protected void onBeforeDecrypt(final File encrypted)
		{
			super.onBeforeDecrypt(encrypted);
			this.arguments.add(encrypted);
			this.events.add("onBeforeDecrypt(" + encrypted.getName() + ")");
		}

		@Override
		protected void onAfterDecrypt(final File encrypted)
		{
			super.onAfterDecrypt(encrypted);
			this.arguments.add(encrypted);
			this.events.add("onAfterDecrypt(" + encrypted.getName() + ")");
		}
	}

	/**
	 * Test method for {@link GenericObjectEncryptor#encrypt(Object)}: both extension hooks must be
	 * invoked, in this order, with the object that is being encrypted, and they must bracket the
	 * write of the encrypted file - {@code onBeforeEncrypt} while the target is still empty and
	 * {@code onAfterEncrypt} once the ciphertext is on disk. Guards against a silent removal of
	 * either hook call.
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@ParameterizedTest
	@MethodSource("objectCryptCases")
	void encrypt_invokesBothHooksAroundTheWriteOfTheEncryptedFile(final ObjectCryptCase testCase)
		throws Exception
	{
		File encryptedFile = new File(temporaryDirectory, "hooks.enc");
		RecordingObjectEncryptor<Serializable> encryptor = new RecordingObjectEncryptor<>(
			newCryptModel(), encryptedFile);
		assertFalse(encryptedFile.exists());

		File result = encryptor.encrypt(testCase.payload());

		assertEquals(encryptedFile, result);
		long encryptedBytes = encryptedFile.length();
		assertTrue(0 < encryptedBytes);
		assertEquals(
			List.of("onBeforeEncrypt(" + testCase.payload() + ") targetBytes=0",
				"onAfterEncrypt(" + testCase.payload() + ") targetBytes=" + encryptedBytes),
			encryptor.events);
		assertSame(testCase.payload(), encryptor.arguments.get(0));
		assertSame(testCase.payload(), encryptor.arguments.get(1));
	}

	/**
	 * Test method for {@link GenericObjectEncryptor#encrypt(Object)}: the negative counterpart of
	 * {@link #encrypt_invokesBothHooksAroundTheWriteOfTheEncryptedFile(ObjectCryptCase)}. When the
	 * object can not be serialized the encryption step itself fails, so only
	 * {@code onBeforeEncrypt} may have run - which pins that {@code onBeforeEncrypt} runs before
	 * and {@code onAfterEncrypt} after the actual crypt operation, not merely in that relative
	 * order.
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void encrypt_doesNotInvokeTheAfterHookWhenTheObjectCanNotBeSerialized() throws Exception
	{
		File encryptedFile = new File(temporaryDirectory, "not-serializable.enc");
		RecordingObjectEncryptor<Object> encryptor = new RecordingObjectEncryptor<>(newCryptModel(),
			encryptedFile);
		Object notSerializable = new Object();

		assertThrows(NotSerializableException.class, () -> encryptor.encrypt(notSerializable));

		assertEquals(List.of("onBeforeEncrypt(" + notSerializable + ") targetBytes=0"),
			encryptor.events);
		assertSame(notSerializable, encryptor.arguments.get(0));
	}

	/**
	 * Test method for {@link GenericObjectDecryptor#decrypt(File)}: both extension hooks must be
	 * invoked, in this order, with the encrypted file that is being decrypted, and the decryption
	 * must still return the original object. Guards against a silent removal of either hook call.
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@ParameterizedTest
	@MethodSource("objectCryptCases")
	void decrypt_invokesBothHooksAroundTheReadOfTheEncryptedFile(final ObjectCryptCase testCase)
		throws Exception
	{
		File encryptedFile = new File(temporaryDirectory, "hooks.enc");
		new GenericObjectEncryptor<Serializable, String>(newCryptModel(), encryptedFile)
			.encrypt(testCase.payload());
		RecordingObjectDecryptor<Serializable> decryptor = new RecordingObjectDecryptor<>(
			newCryptModel());

		Serializable decrypted = decryptor.decrypt(encryptedFile);

		assertEquals(testCase.payload(), decrypted);
		assertEquals(List.of("onBeforeDecrypt(hooks.enc)", "onAfterDecrypt(hooks.enc)"),
			decryptor.events);
		assertSame(encryptedFile, decryptor.arguments.get(0));
		assertSame(encryptedFile, decryptor.arguments.get(1));
	}

	/**
	 * Test method for {@link GenericObjectDecryptor#decrypt(File)}: the negative counterpart of
	 * {@link #decrypt_invokesBothHooksAroundTheReadOfTheEncryptedFile(ObjectCryptCase)}. When the
	 * encrypted file does not exist the decryption step itself fails, so only
	 * {@code onBeforeDecrypt} may have run - which pins that {@code onBeforeDecrypt} runs before
	 * and {@code onAfterDecrypt} after the actual crypt operation, not merely in that relative
	 * order.
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void decrypt_doesNotInvokeTheAfterHookWhenTheEncryptedFileIsMissing() throws Exception
	{
		File missing = new File(temporaryDirectory, "missing.enc");
		RecordingObjectDecryptor<Serializable> decryptor = new RecordingObjectDecryptor<>(
			newCryptModel());
		assertFalse(missing.exists());

		assertThrows(FileNotFoundException.class, () -> decryptor.decrypt(missing));

		assertEquals(List.of("onBeforeDecrypt(missing.enc)"), decryptor.events);
		assertSame(missing, decryptor.arguments.get(0));
	}
}
