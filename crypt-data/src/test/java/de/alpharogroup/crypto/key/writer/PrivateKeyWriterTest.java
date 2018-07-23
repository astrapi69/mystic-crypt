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
package de.alpharogroup.crypto.key.writer;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
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

import de.alpharogroup.crypto.algorithm.MdAlgorithm;
import de.alpharogroup.crypto.key.KeyFileFormat;
import de.alpharogroup.crypto.key.KeyFormat;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.checksum.ChecksumExtensions;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import de.alpharogroup.io.StreamExtensions;

/**
 * The unit test class for the class {@link PrivateKeyWriter}
 */
public class PrivateKeyWriterTest
{

	PrivateKey actual;
	PrivateKey privateKey;

	File pemDir;

	File derDir;
	File privateKeyPemFile;

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

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
	}

	/**
	 * Test method for {@link PrivateKeyWriter#write(PrivateKey, File)}
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
		File writtenPrivatekeyDerFile;
		// new scenario...		
		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		writtenPrivatekeyDerFile = new File(derDir, "written-private.der");
		PrivateKeyWriter.write(privateKey, writtenPrivatekeyDerFile);
		expected = ChecksumExtensions.getChecksum(privateKeyDerFile, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(writtenPrivatekeyDerFile, MdAlgorithm.MD5);
		DeleteFileExtensions.delete(writtenPrivatekeyDerFile);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyWriter#writeInPemFormat(PrivateKey, File)}
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
	public void testWriteInPemFormat() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		String expected;
		String actual;
		File privatekeyPemFileInDerDir;
		File convertedPrivatekeyPemFile;
		// new scenario...		
		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		convertedPrivatekeyPemFile = new File(pemDir, "converted-private.pem");
		PrivateKeyWriter.writeInPemFormat(privateKey, convertedPrivatekeyPemFile);

		privatekeyPemFileInDerDir = new File(derDir, "private.pem");
		expected = ChecksumExtensions.getChecksum(privatekeyPemFileInDerDir, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(convertedPrivatekeyPemFile, MdAlgorithm.MD5);
		DeleteFileExtensions.delete(convertedPrivatekeyPemFile);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link PrivateKeyWriter#write(PrivateKey, OutputStream, KeyFileFormat, KeyFormat)}
	 * 
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	@Test(enabled = true) 
	public void testWritePrivateKeyOutputStreamKeyFileFormatKeyFormat() throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		String expected;
		String actual;
		OutputStream outputStream;
		File newWrittenPrivatekeyPemFile;
		File privatekeyPemFileInDerDir;
		// new scenario...
		privatekeyPemFileInDerDir = new File(derDir, "private.pem");
		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		newWrittenPrivatekeyPemFile = new File(pemDir, "new-written-private.pem");
		newWrittenPrivatekeyPemFile.createNewFile();
		
		outputStream = StreamExtensions.getOutputStream(newWrittenPrivatekeyPemFile);
		PrivateKeyWriter.write(privateKey, outputStream, KeyFileFormat.PEM, KeyFormat.PKCS_8);
		expected = ChecksumExtensions.getChecksum(privatekeyPemFileInDerDir, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(newWrittenPrivatekeyPemFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);

		DeleteFileExtensions.delete(newWrittenPrivatekeyPemFile);
		// new scenario...
		newWrittenPrivatekeyPemFile = new File(pemDir, "new-written-private.pem");
		newWrittenPrivatekeyPemFile.createNewFile();
		
		outputStream = StreamExtensions.getOutputStream(newWrittenPrivatekeyPemFile);
		PrivateKeyWriter.write(privateKey, outputStream, KeyFileFormat.PEM, KeyFormat.PKCS_1);
		expected = ChecksumExtensions.getChecksum(privatekeyPemFileInDerDir, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(newWrittenPrivatekeyPemFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);

		DeleteFileExtensions.delete(newWrittenPrivatekeyPemFile);
		// new scenario...
		privatekeyPemFileInDerDir = new File(derDir, "private.pem");
		privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);

		newWrittenPrivatekeyPemFile = new File(pemDir, "new-written-private.pem");
		newWrittenPrivatekeyPemFile.createNewFile();
		
		outputStream = StreamExtensions.getOutputStream(newWrittenPrivatekeyPemFile);
		PrivateKeyWriter.write(privateKey, outputStream, KeyFileFormat.PEM, null);
		expected = ChecksumExtensions.getChecksum(privatekeyPemFileInDerDir, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(newWrittenPrivatekeyPemFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);

		DeleteFileExtensions.delete(newWrittenPrivatekeyPemFile);
		// new scenario...
		newWrittenPrivatekeyPemFile = new File(pemDir, "new-written-private.pem");
		newWrittenPrivatekeyPemFile.createNewFile();
		
		outputStream = StreamExtensions.getOutputStream(newWrittenPrivatekeyPemFile);
		PrivateKeyWriter.write(privateKey, outputStream, KeyFileFormat.DER, null);
		expected = ChecksumExtensions.getChecksum(privateKeyDerFile, MdAlgorithm.MD5);
		actual = ChecksumExtensions.getChecksum(newWrittenPrivatekeyPemFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);

		DeleteFileExtensions.delete(newWrittenPrivatekeyPemFile);
		
	}

	/**
	 * Test method for {@link PrivateKeyWriter} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PrivateKeyWriter.class);
	}

}
