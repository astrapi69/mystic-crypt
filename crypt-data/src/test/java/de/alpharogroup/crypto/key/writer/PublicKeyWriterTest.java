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
package de.alpharogroup.crypto.key.writer;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.MdAlgorithm;
import de.alpharogroup.crypto.key.PrivateKeyExtensions;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.file.checksum.ChecksumExtensions;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyWriter}
 */
public class PublicKeyWriterTest
{

	PrivateKey privateKey;
	PublicKey publicKey;

	File pemDir;

	File derDir;
	File publicKeyDerFile;
	File publicKeyPemFile;

	File privateKeyPemFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publicKeyPemFile = new File(pemDir, "public.pem");
		privateKeyPemFile = new File(pemDir, "private.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publicKeyDerFile = new File(derDir, "public.der");
	}

	/**
	 * Test method for {@link PublicKeyWriter} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PublicKeyWriter.class);
	}

	/**
	 * Test method for {@link PublicKeyWriter#write(PublicKey, File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testWriteFile() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		String expected;
		String actual;
		File writtenPublickeyDerFile;
		// new scenario...
		publicKey = PublicKeyReader.readPublicKey(publicKeyDerFile);
		writtenPublickeyDerFile = new File(derDir, "written-public.der");
		PublicKeyWriter.write(publicKey, writtenPublickeyDerFile);

		expected = ChecksumExtensions.getChecksum(publicKeyDerFile, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(writtenPublickeyDerFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);
		DeleteFileExtensions.delete(writtenPublickeyDerFile);
	}

	/**
	 * Test method for {@link PublicKeyWriter#writeInPemFormat(PublicKey, File)}
	 *
	 * @throws Exception
	 *             is thrown if a security issue occurs
	 */
	@Test
	public void testWriteInPemFormat() throws Exception
	{
		String expected;
		String actual;
		File convertedPublickeyPemFile;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);
		convertedPublickeyPemFile = new File(pemDir, "converted-public.pem");
		PublicKeyWriter.writeInPemFormat(publicKey, convertedPublickeyPemFile);
		expected = ChecksumExtensions.getChecksum(publicKeyPemFile, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(convertedPublickeyPemFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);
		DeleteFileExtensions.delete(convertedPublickeyPemFile);
	}

}
