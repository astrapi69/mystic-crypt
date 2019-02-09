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
package de.alpharogroup.crypto.key.reader;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyReader}
 */
public class EncryptedPrivateKeyReaderTest
{
	PrivateKey actual;
	File derDir;
	File pemDir;

	File encryptedPrivateKeyFile;
	PrivateKey expected;
	String password;
	PrivateKey readedPrivateKey;

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
		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		encryptedPrivateKeyFile = new File(pemDir, "test.key");
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
	}


	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(byte[], String, String)}
	 */
	@Test(enabled = false)
	public void testReadPasswordProtectedPrivateKeyByteArrayStringString()
	{
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(File, String, String)}
	 */
	@Test(enabled = false)
	public void testReadPasswordProtectedPrivateKeyFileStringString()
	{
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#getKeyPair(File, String)}
	 * 
	 * @throws FileNotFoundException
	 *             is thrown if the file did not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws PEMException
	 *             is thrown if an error occurs on read the pem file
	 */
	@Test(enabled = true)
	public void testGetKeyPair() throws FileNotFoundException, PEMException, IOException
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPair keyPair = EncryptedPrivateKeyReader.getKeyPair(encryptedPrivateKeyFile, "bosco");
		assertNotNull(keyPair);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#readPasswordProtectedPrivateKey(File, String)}
	 */
	@Test(enabled = false)
	public void testReadPasswordProtectedPrivateKeyFileString()
	{
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
