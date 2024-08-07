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
package io.github.astrapi69.mystic.crypt.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

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
	@Test
	public void testDecrypt() throws Exception
	{
		Person actual;
		Person expected;
		PrivateKey privateKey;
		PublicKey publicKey;
		SecretKey symmetricKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel;
		CryptModel<Cipher, PrivateKey, byte[]> decryptModel;
		File derDir;
		File privatekeyDerFile;
		PublicKeyEncryptor encryptor;
		PrivateKeyDecryptor decryptor;

		PublicKeyGenericEncryptor<Person> genericEncryptor;
		PrivateKeyGenericDecryptor<Person> genericDecryptor;
		Person toEncrypt;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		decryptModel = CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build();
		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
		symmetricKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(),
			128);
		symmetricKeyModel = CryptModel.<Cipher, SecretKey, String> builder().key(symmetricKey)
			.algorithm(AesAlgorithm.AES).operationMode(Cipher.ENCRYPT_MODE).build();

		encryptor = new PublicKeyEncryptor(encryptModel, symmetricKeyModel);
		assertNotNull(encryptor);
		decryptor = new PrivateKeyDecryptor(decryptModel);
		assertNotNull(decryptor);

		genericEncryptor = new PublicKeyGenericEncryptor<>(encryptor);
		genericDecryptor = new PrivateKeyGenericDecryptor<Person>(decryptor);

		actual = Person.builder().about("about").name("Foo").gender(Gender.MALE).build();
		byte[] encrypt = genericEncryptor.encrypt(actual);
		Person decryptedPerson = genericDecryptor.decrypt(encrypt);
		expected = decryptedPerson;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link PublicKeyGenericEncryptor#encrypt(Serializable)} and the corresponding
	 * method {@link PrivateKeyGenericDecryptor#decrypt(byte[])} with json object
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testDecryptJson() throws Exception
	{
		String actual;
		String expected;
		PrivateKey privateKey;
		PublicKey publicKey;
		SecretKey symmetricKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel;
		CryptModel<Cipher, PrivateKey, byte[]> decryptModel;
		File derDir;
		File privatekeyDerFile;
		PublicKeyEncryptor encryptor;
		PrivateKeyDecryptor decryptor;

		PublicKeyGenericEncryptor<String> genericEncryptor;
		PrivateKeyGenericDecryptor<String> genericDecryptor;
		Person personToEncrypt;
		byte[] encryptedBytes;
		String decryptedJson;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
		decryptModel = CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build();
		symmetricKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(),
			128);
		symmetricKeyModel = CryptModel.<Cipher, SecretKey, String> builder().key(symmetricKey)
			.algorithm(AesAlgorithm.AES).operationMode(Cipher.ENCRYPT_MODE).build();

		encryptor = new PublicKeyEncryptor(encryptModel, symmetricKeyModel);
		assertNotNull(encryptor);
		decryptor = new PrivateKeyDecryptor(decryptModel);
		assertNotNull(decryptor);

		genericEncryptor = new PublicKeyGenericEncryptor<>(encryptor);
		genericDecryptor = new PrivateKeyGenericDecryptor<>(decryptor);

		personToEncrypt = Person.builder().about("about").name("Foo").gender(Gender.MALE).build();
		actual = ObjectToJsonExtensions.toJson(personToEncrypt);
		encryptedBytes = genericEncryptor.encrypt(actual);
		decryptedJson = genericDecryptor.decrypt(encryptedBytes);
		expected = decryptedJson;
		assertEquals(actual, expected);
		Person decryptedPerson = JsonStringToObjectExtensions.toObject(decryptedJson, Person.class);
		assertEquals(personToEncrypt, decryptedPerson);
	}

	/**
	 * Test method for {@link PublicKeyGenericEncryptor#encrypt(Serializable)} and the corresponding
	 * method {@link PrivateKeyGenericDecryptor#decrypt(byte[])} with json object with only
	 * {@link PrivateKey} and {@link PublicKey} object
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testDecryptJsonWithPrivateKeyAndPublicKey() throws Exception
	{
		String actual;
		String expected;
		PrivateKey privateKey;
		PublicKey publicKey;
		File derDir;
		File privatekeyDerFile;

		PublicKeyGenericEncryptor<String> genericEncryptor;
		PrivateKeyGenericDecryptor<String> genericDecryptor;
		Person personToEncrypt;
		byte[] encryptedBytes;
		String decryptedJson;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		genericEncryptor = new PublicKeyGenericEncryptor<>(publicKey);
		genericDecryptor = new PrivateKeyGenericDecryptor<>(privateKey);

		personToEncrypt = Person.builder().about("about").name("Foo").gender(Gender.MALE).build();
		actual = ObjectToJsonExtensions.toJson(personToEncrypt);
		encryptedBytes = genericEncryptor.encrypt(actual);
		decryptedJson = genericDecryptor.decrypt(encryptedBytes);
		expected = decryptedJson;
		assertEquals(actual, expected);
		Person decryptedPerson = JsonStringToObjectExtensions.toObject(decryptedJson, Person.class);
		assertEquals(personToEncrypt, decryptedPerson);
	}

	/**
	 * Test method for {@link PublicKeyGenericEncryptor#encrypt(Serializable)} and the corresponding
	 * method {@link PrivateKeyGenericDecryptor#decrypt(byte[])} with serializable test object
	 * {@link Person} with only {@link PrivateKey} and {@link PublicKey} object
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testDecryptWithPrivateKeyAndPublicKey() throws Exception
	{
		Person actual;
		Person expected;
		PrivateKey privateKey;
		PublicKey publicKey;
		File derDir;
		File privatekeyDerFile;

		PublicKeyGenericEncryptor<Person> genericEncryptor;
		PrivateKeyGenericDecryptor<Person> genericDecryptor;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		genericEncryptor = new PublicKeyGenericEncryptor<>(publicKey);
		genericDecryptor = new PrivateKeyGenericDecryptor<Person>(privateKey);

		actual = Person.builder().about("about").name("Foo").gender(Gender.MALE).build();
		byte[] encrypt = genericEncryptor.encrypt(actual);
		Person decryptedPerson = genericDecryptor.decrypt(encrypt);
		expected = decryptedPerson;
		assertEquals(actual, expected);
	}

}
