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
package io.github.astrapi69.crypto.pw;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.io.Files;

import io.github.astrapi69.delete.DeleteFileExtensions;
import io.github.astrapi69.search.PathFinder;
import io.github.astrapi69.write.WriteFileExtensions;
import io.github.astrapi69.collections.array.ArrayFactory;
import io.github.astrapi69.random.object.RandomStringFactory;

/**
 * The unit test class for the class {@link PasswordFileEncryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordFileEncryptorTest
{

	File cryptDir;
	File encrypted;
	PasswordFileEncryptor encryptor;
	String password;
	File toEncrypt;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		password = "foo";
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
	}

	/**
	 * Test method for test the method {@link PasswordFileEncryptor#encrypt(File)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncrypt() throws Exception
	{
		byte[] actual;
		byte[] expected;
		File encryptedCnstr;
		String encryptedFilename;
		// new scenario...
		encryptedFilename = "encryptedCnstr.enc";
		encryptedCnstr = new File(cryptDir, encryptedFilename);
		encryptor = new PasswordFileEncryptor(password, encryptedCnstr);
		encrypted = encryptor.encrypt(toEncrypt);
		actual = Files.toByteArray(encryptedCnstr);
		expected = ArrayFactory.newByteArray(6, -1, 90, -29, -121, 43, -47, -27, -64, -81,
			-100, 3, -10, -112, 22, -78, 37, 76, -72, 63, -80, 125, -40, 99, 104, -106, -11, -97,
			-22, 40, 21, 81, 113, -73, 119, 68, -46, 110, -97, -108, 10, -75, 122, 8, 51, 68, -58,
			-35);
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
	}

	/**
	 * Test method for test the method {@link PasswordFileEncryptor#encrypt(File)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptBigFile() throws Exception
	{
		byte[] actual;
		byte[] expected;
		File encryptedCnstr;
		String encryptedFilename;
		String longString;
		// new scenario...
		encryptedFilename = "bigEncryptedFile.txt";
		longString = RandomStringFactory.newRandomLongString(10000000);
		encryptedCnstr = new File(cryptDir, encryptedFilename);
		WriteFileExtensions.string2File(encryptedCnstr, longString);
		encryptor = new PasswordFileEncryptor(password);
		encrypted = encryptor.encrypt(encryptedCnstr);
//		actual = Files.toByteArray(encryptedCnstr);
//		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(encryptedCnstr);
	}
}
