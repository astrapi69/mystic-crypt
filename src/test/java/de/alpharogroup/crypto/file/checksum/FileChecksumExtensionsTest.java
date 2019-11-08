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
package de.alpharogroup.crypto.file.checksum;

import static org.testng.AssertJUnit.assertEquals;

import java.io.*;
import java.security.NoSuchAlgorithmException;

import org.meanbean.factories.ObjectCreationException;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.AbstractTestCase;
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.algorithm.MdAlgorithm;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link FileChecksumExtensions}
 */
public class FileChecksumExtensionsTest extends AbstractTestCase<Long, Long>
{
	File checksumDir;
	File testFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@Override
	@BeforeMethod
	protected void setUp()
	{
		checksumDir = PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "checksum");
		testFile = new File(checksumDir, "testReadFileInput.txt");
	}


	/**
	 * Test method for {@link FileChecksumExtensions#getCheckSumAdler32(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetCheckSumAdler32File() throws IOException
	{
		long expected;
		long actual;
		actual = FileChecksumExtensions.getCheckSumAdler32(testFile);
		expected = 3296728756L;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link FileChecksumExtensions#getCheckSumCRC32(File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetCheckSumCRC32File() throws IOException
	{
		long expected;
		long actual;
		actual = FileChecksumExtensions.getCheckSumCRC32(testFile);
		expected = 197057321L;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link FileChecksumExtensions#getChecksum(File, Algorithm)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetChecksumFileAlgorithm() throws NoSuchAlgorithmException, IOException
	{
		String expected;
		String actual;

		expected = "f57f8379e8c62db6135f14d93a84ffd3";
		actual = FileChecksumExtensions.getChecksum(testFile, MdAlgorithm.MD2);
		assertEquals(expected, actual);

		expected = "3a37a2c10a590785dbfb9ce3b15b0464";
		actual = FileChecksumExtensions.getChecksum(testFile, MdAlgorithm.MD5);
		assertEquals(expected, actual);

		expected = "496dfa0ecf50cc6e3eda41fd3258272c2f2f0ff1";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_1);
		assertEquals(expected, actual);

		expected = "94151a5c66422a9adf706937eeb7fafec25032c380b55b0e92695baf297fb747";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_256);
		assertEquals(expected, actual);

		expected = "c1bc0091901a944828ca56f236f068d318086a55b96e045b1e7415df1449eb9c8e54546fec4b759ad2c6f7e3fbab7561";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_384);
		assertEquals(expected, actual);

		expected = "4d0c14f299254e58dcea1f524ca08af5f0776b1f5070919a859b92c2ab350635375862ab0727fd5e34ff35da837bd836a17047544db8df63adc4912211ea7f02";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_512);
		assertEquals(expected, actual);

	}

	/**
	 * Test method for {@link FileChecksumExtensions#getChecksum(File, boolean)}
	 *
	 * @throws FileNotFoundException
	 *             the file not found exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetChecksumFileBoolean() throws FileNotFoundException, IOException
	{
		long expected;
		long actual;

		expected = 197057321L;
		actual = FileChecksumExtensions.getChecksum(testFile, true);
		assertEquals(expected, actual);

		expected = 3296728756L;
		actual = FileChecksumExtensions.getChecksum(testFile, false);
		assertEquals(expected, actual);

	}

	/**
	 * Test method for {@link FileChecksumExtensions#getChecksum(File, String)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testGetChecksumFileString() throws NoSuchAlgorithmException, IOException
	{
		String expected;
		String actual;

		expected = "f57f8379e8c62db6135f14d93a84ffd3";
		actual = FileChecksumExtensions.getChecksum(testFile, MdAlgorithm.MD2.getAlgorithm());
		assertEquals(expected, actual);

		expected = "3a37a2c10a590785dbfb9ce3b15b0464";
		actual = FileChecksumExtensions.getChecksum(testFile, MdAlgorithm.MD5.getAlgorithm());
		assertEquals(expected, actual);

		expected = "496dfa0ecf50cc6e3eda41fd3258272c2f2f0ff1";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_1.getAlgorithm());
		assertEquals(expected, actual);

		expected = "94151a5c66422a9adf706937eeb7fafec25032c380b55b0e92695baf297fb747";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_256.getAlgorithm());
		assertEquals(expected, actual);

		expected = "c1bc0091901a944828ca56f236f068d318086a55b96e045b1e7415df1449eb9c8e54546fec4b759ad2c6f7e3fbab7561";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_384.getAlgorithm());
		assertEquals(expected, actual);

		expected = "4d0c14f299254e58dcea1f524ca08af5f0776b1f5070919a859b92c2ab350635375862ab0727fd5e34ff35da837bd836a17047544db8df63adc4912211ea7f02";
		actual = FileChecksumExtensions.getChecksum(testFile, HashAlgorithm.SHA_512.getAlgorithm());
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link FileChecksumExtensions}
	 */
	@Test(expectedExceptions = { BeanTestException.class, ObjectCreationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(FileChecksumExtensions.class);
	}

}
