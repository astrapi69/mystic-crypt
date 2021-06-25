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
package io.github.astrapi69.crypto.file;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;

import javax.crypto.Cipher;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.AbstractTestCase;
import io.github.astrapi69.crypto.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.delete.DeleteFileExtensions;
import io.github.astrapi69.search.PathFinder;
import io.github.astrapi69.test.objects.Person;
import io.github.astrapi69.test.objects.enums.Gender;

/**
 * The unit test class for the class {@link GenericObjectEncryptor} and the class
 * {@link GenericObjectDecryptor}
 */
public class GenericObjectEncryptDecryptorTest extends AbstractTestCase<Person, Person>
{

	File cryptDir;
	CryptModel<Cipher, String, String> cryptModel;
	Person decrypted;
	GenericObjectDecryptor<Person, String> decryptor;
	File dirToEncrypt;
	File encrypted;
	GenericObjectEncryptor<Person, String> encryptor;
	String firstKey;
	Person toEncrypt;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@Override
	@BeforeMethod
	protected void setUp()
	{
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = Person.builder().about("about").name("Foo").gender(Gender.MALE).build();
		dirToEncrypt = new File(cryptDir, "food");
		firstKey = "D1D15ED36B887AF1";
		cryptModel = CryptModel.<Cipher, String, String> builder().key(firstKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).build();
	}

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with given constructor files.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptConstructorFiles() throws Exception
	{
		// new scenario...
		encryptor = new GenericObjectEncryptor<>(cryptModel,
			new File(cryptDir, "encryptedPerson.enc"));
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new GenericObjectDecryptor<>(cryptModel);

		decrypted = decryptor.decrypt(encrypted);

		expected = toEncrypt;
		actual = decrypted;
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with given constructor files.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptString() throws Exception
	{
		// new scenario...
		GenericObjectEncryptor<String, String> encryptor = new GenericObjectEncryptor<>(cryptModel,
			new File(cryptDir, "encryptedPerson.enc"));
		String text = "Foo bar i will be encrypted and decypted";
		encrypted = encryptor.encrypt(text);

		GenericObjectDecryptor<String, String> decryptor = new GenericObjectDecryptor<>(cryptModel);

		String decrypted = decryptor.decrypt(encrypted);

		assertEquals(text, decrypted);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
	}

}
