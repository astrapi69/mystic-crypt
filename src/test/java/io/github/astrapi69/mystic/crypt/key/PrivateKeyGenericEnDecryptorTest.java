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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.json.JsonStringToObjectExtensions;
import io.github.astrapi69.json.ObjectToJsonExtensions;
import io.github.astrapi69.test.object.Person;
import io.github.astrapi69.test.object.enumeration.Gender;

/**
 * The unit test class for the encryption and decryption with the class
 * {@link PublicKeyGenericEncryptor} and {@link PrivateKeyGenericDecryptor}
 */
public class PrivateKeyGenericEnDecryptorTest
{

	/**
	 * Test method for {@link PublicKeyGenericEncryptor#encrypt(Serializable)} and the corresponding
	 * method {@link PrivateKeyGenericDecryptor#decrypt(byte[])} with serializable test object
	 * {@link Person}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	/**
	 * Builds the generic encryptor/decryptor pair for one constructor variant; the generic method
	 * keeps the payload type flexible so the Person and the JSON round trip share the variants.
	 */
	interface GenericCryptorFactory
	{
		<T extends Serializable> PublicKeyGenericEncryptor<T> newEncryptor(PublicKey publicKey)
			throws Exception;

		<T extends Serializable> PrivateKeyGenericDecryptor<T> newDecryptor(PrivateKey privateKey)
			throws Exception;
	}

	/** One constructor-variant case of the 2x2 matrix (payload x construction). */
	record ConstructorVariant(String description, GenericCryptorFactory factory) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<ConstructorVariant> constructorVariants()
	{
		return Stream.of(new ConstructorVariant("bare key constructors", new GenericCryptorFactory()
		{
			@Override
			public <T extends Serializable> PublicKeyGenericEncryptor<T> newEncryptor(
				PublicKey publicKey)
			{
				return new PublicKeyGenericEncryptor<>(publicKey);
			}

			@Override
			public <T extends Serializable> PrivateKeyGenericDecryptor<T> newDecryptor(
				PrivateKey privateKey)
			{
				return new PrivateKeyGenericDecryptor<>(privateKey);
			}
		}), new ConstructorVariant("CryptModel constructors", new GenericCryptorFactory()
		{
			@Override
			public <T extends Serializable> PublicKeyGenericEncryptor<T> newEncryptor(
				PublicKey publicKey) throws Exception
			{
				CryptModel<Cipher, PublicKey, byte[]> encryptModel = CryptModel
					.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
				SecretKey symmetricKey = SecretKeyFactoryExtensions
					.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 128);
				CryptModel<Cipher, SecretKey, String> symmetricKeyModel = CryptModel
					.<Cipher, SecretKey, String> builder().key(symmetricKey)
					.algorithm(AesAlgorithm.AES).operationMode(Cipher.ENCRYPT_MODE).build();
				return new PublicKeyGenericEncryptor<>(
					new PublicKeyEncryptor(encryptModel, symmetricKeyModel));
			}

			@Override
			public <T extends Serializable> PrivateKeyGenericDecryptor<T> newDecryptor(
				PrivateKey privateKey) throws Exception
			{
				CryptModel<Cipher, PrivateKey, byte[]> decryptModel = CryptModel
					.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build();
				return new PrivateKeyGenericDecryptor<>(
					new PrivateKeyDecryptor(decryptModel, AesAlgorithm.AES));
			}
		}));
	}

	/** Reads the test key pair from the DER resources. */
	private static PrivateKey readTestPrivateKey() throws Exception
	{
		File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		return PrivateKeyReader.readPrivateKey(new File(derDir, "private.der"));
	}

	/**
	 * Test method for {@link PublicKeyGenericEncryptor#encrypt(Serializable)} and the corresponding
	 * method {@link PrivateKeyGenericDecryptor#decrypt(byte[])} with serializable test object
	 * {@link Person}, over every constructor variant
	 *
	 * @param variant
	 *            the constructor variant
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@ParameterizedTest
	@MethodSource("constructorVariants")
	public void testEncryptDecryptPerson(ConstructorVariant variant) throws Exception
	{
		PrivateKey privateKey = readTestPrivateKey();
		PublicKey publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		PublicKeyGenericEncryptor<Person> genericEncryptor = variant.factory()
			.newEncryptor(publicKey);
		PrivateKeyGenericDecryptor<Person> genericDecryptor = variant.factory()
			.newDecryptor(privateKey);
		assertNotNull(genericEncryptor);
		assertNotNull(genericDecryptor);

		Person person = Person.builder().about("about").name("Foo").gender(Gender.MALE).build();
		byte[] encrypted = genericEncryptor.encrypt(person);

		assertEquals(person, genericDecryptor.decrypt(encrypted), variant.description());
	}

	/**
	 * Test method for {@link PublicKeyGenericEncryptor#encrypt(Serializable)} and the corresponding
	 * method {@link PrivateKeyGenericDecryptor#decrypt(byte[])} with json object
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	/**
	 * Test method for {@link PublicKeyGenericEncryptor#encrypt(Serializable)} and the corresponding
	 * method {@link PrivateKeyGenericDecryptor#decrypt(byte[])} with a json payload, over every
	 * constructor variant
	 *
	 * @param variant
	 *            the constructor variant
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@ParameterizedTest
	@MethodSource("constructorVariants")
	public void testEncryptDecryptJson(ConstructorVariant variant) throws Exception
	{
		PrivateKey privateKey = readTestPrivateKey();
		PublicKey publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		PublicKeyGenericEncryptor<String> genericEncryptor = variant.factory()
			.newEncryptor(publicKey);
		PrivateKeyGenericDecryptor<String> genericDecryptor = variant.factory()
			.newDecryptor(privateKey);

		Person person = Person.builder().about("about").name("Foo").gender(Gender.MALE).build();
		String json = ObjectToJsonExtensions.toJson(person);
		byte[] encrypted = genericEncryptor.encrypt(json);
		String decryptedJson = genericDecryptor.decrypt(encrypted);

		assertEquals(json, decryptedJson, variant.description());
		assertEquals(person, JsonStringToObjectExtensions.toObject(decryptedJson, Person.class),
			variant.description());
	}

}
