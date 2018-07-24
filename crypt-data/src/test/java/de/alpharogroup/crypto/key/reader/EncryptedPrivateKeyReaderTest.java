/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.key.reader;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.PrivateKey;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.writer.EncryptedPrivateKeyWriter;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyReader}.
 */
public class EncryptedPrivateKeyReaderTest
{
	PrivateKey expected;
	PrivateKey actual;

	File derDir;
	File encryptedPrivateKeyFile;
	PrivateKey readedPrivateKey;
	String password;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		encryptedPrivateKeyFile = new File(derDir, "encryptedPrivate.der");
	}

	/**
	 * Tear down method will be invoked after every unit test method in this class.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@AfterMethod
	protected void tearDown() throws Exception
	{
		if (encryptedPrivateKeyFile.exists())
		{
			DeleteFileExtensions.delete(encryptedPrivateKeyFile);
		}
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#decryptPasswordProtectedPrivateKey(byte[], String, String)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptPasswordProtectedPrivateKeyByteArray() throws Exception
	{
		readedPrivateKey = PrivateKeyReader.readPrivateKey(PathFinder.getSrcTestResourcesDir(),
			"der", "private.der");
		password = "secret";
		final byte[] pwprotectedKey = EncryptedPrivateKeyWriter
			.encryptPrivateKeyWithPassword(readedPrivateKey, password);

		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader
			.decryptPasswordProtectedPrivateKey(pwprotectedKey, password,
				KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#decryptPasswordProtectedPrivateKey(File, String)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptPasswordProtectedPrivateKeyFilePassword() throws Exception
	{
		readedPrivateKey = PrivateKeyReader.readPrivateKey(PathFinder.getSrcTestResourcesDir(),
			"der", "private.der");
		password = "secret";
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			encryptedPrivateKeyFile, password);


		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader
			.decryptPasswordProtectedPrivateKey(encryptedPrivateKeyFile, password);
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#decryptPasswordProtectedPrivateKey(File, String, String)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptPasswordProtectedPrivateKeyFilePasswordAlgorithm() throws Exception
	{
		readedPrivateKey = PrivateKeyReader.readPrivateKey(PathFinder.getSrcTestResourcesDir(),
			"der", "private.der");
		password = "secret";
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			encryptedPrivateKeyFile, password);


		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader
			.decryptPasswordProtectedPrivateKey(encryptedPrivateKeyFile, password,
				KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(EncryptedPrivateKeyReader.class);
	}

}
