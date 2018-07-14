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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.MdAlgorithm;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
// import de.alpharogroup.file.checksum.Algorithm;
import de.alpharogroup.file.checksum.ChecksumExtensions;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PrivateKeyWriter}.
 */
public class PrivateKeyWriterTest
{

	/**
	 * Read test private key.
	 *
	 * @param root
	 *            the root
	 * @param fileName
	 *            the file name
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             the no such provider exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PrivateKey readTestPrivateKey(File root, String fileName)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
		IOException
	{

		final File privatekeyDerFile = new File(root, fileName);

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		return privateKey;
	}

	/**
	 * Read test private key.
	 *
	 * @param root
	 *            the root
	 * @param dir
	 *            the dir
	 * @param fileName
	 *            the file name
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             the no such provider exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PrivateKey readTestPrivateKey(File root, String dir, String fileName)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
		IOException
	{

		final File privatekeyDerDir = new File(root, dir);
		final File privatekeyDerFile = new File(privatekeyDerDir, fileName);

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		return privateKey;
	}

	/**
	 * Test method for {@link PrivateKeyWriter#write(PrivateKey, File)}.
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
		final File privatekeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(privatekeyDerDir, "private.der");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		final File writtenPrivatekeyDerFile = new File(privatekeyDerDir, "written-private.der");
		PrivateKeyWriter.write(privateKey, writtenPrivatekeyDerFile);
		String expected = ChecksumExtensions.getChecksum(privatekeyDerFile, MdAlgorithm.MD5);
		String actual = ChecksumExtensions.getChecksum(writtenPrivatekeyDerFile, MdAlgorithm.MD5);
		DeleteFileExtensions.delete(writtenPrivatekeyDerFile);
		assertEquals(expected, actual);
	}


	/**
	 * Test method for {@link PrivateKeyWriter#writeInPemFormat(PrivateKey, File)}.
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
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");
		final File privatekeyPemFile = new File(publickeyDerDir, "private.pem");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File convertedPrivatekeyPemFile = new File(keyPemDir, "converted-private.pem");
		PrivateKeyWriter.writeInPemFormat(privateKey, convertedPrivatekeyPemFile);
		String expected = ChecksumExtensions.getChecksum(privatekeyPemFile, MdAlgorithm.MD5);
		String actual = ChecksumExtensions.getChecksum(convertedPrivatekeyPemFile, MdAlgorithm.MD5);
		DeleteFileExtensions.delete(convertedPrivatekeyPemFile);
		assertEquals(expected, actual);
	}

}
