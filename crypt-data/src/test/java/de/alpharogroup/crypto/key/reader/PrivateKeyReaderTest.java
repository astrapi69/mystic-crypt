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

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.PrivateKeyExtensions;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PrivateKeyReader}
 */
public class PrivateKeyReaderTest
{

	PrivateKey actual;

	File pemDir;
	File privateKeyPemFile;
	File privateKeyPemFile2;

	File derDir;
	File privateKeyDerFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privateKeyPemFile = new File(pemDir, "private.pem");
		privateKeyPemFile2 = new File(pemDir, "private2.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemFileAsBase64() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		String privateKeyAsBase64String;
		String base64;
		
		privateKeyAsBase64String = PrivateKeyReader
			.readPemFileAsBase64(privateKeyPemFile);

		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		base64 = PrivateKeyExtensions.toBase64(actual);
		assertNotNull(privateKeyAsBase64String);
		assertNotNull(base64);
		
		privateKeyAsBase64String = PrivateKeyReader
			.readPemFileAsBase64(privateKeyPemFile2);

		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		base64 = PrivateKeyExtensions.toBase64(actual);
		assertNotNull(privateKeyAsBase64String);
		assertNotNull(base64);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(File, SecurityProvider)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test(enabled = true)
	public void testReadPemPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPrivateKey(privateKeyDerFile);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(File, String)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemPrivateKeyFileString() throws NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException, IOException
	{
		actual = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile,
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(String, String)}.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred. *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadPemPrivateKeyStringString() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		final String privateKeyAsBase64String = PrivateKeyReader
			.readPemFileAsBase64(privateKeyPemFile);

		actual = PrivateKeyReader.readPemPrivateKey(privateKeyAsBase64String,
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link PrivateKeyReader} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PrivateKeyReader.class);
	}

}
