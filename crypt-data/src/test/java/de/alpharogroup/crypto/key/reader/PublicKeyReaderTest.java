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
import java.lang.reflect.InvocationTargetException;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.PublicKeyExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyReader}
 */
public class PublicKeyReaderTest
{

	/**
	 * Test method for {@link PublicKeyReader#readPemPublicKey(File)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPemFileAsBase64() throws Exception
	{
		File publickeyPemDir;
		File publickeyPemFile;
		String publicKeyAsBase64String;
		PublicKey publicKey;
		String base64;

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());
		publicKeyAsBase64String = PublicKeyReader.readPemFileAsBase64(publickeyPemFile);

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		base64 = PublicKeyExtensions.toBase64(publicKey);
		assertNotNull(publicKeyAsBase64String);
		assertNotNull(base64);
	}

	/**
	 * Test method for {@link PublicKeyReader} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PublicKeyReader.class);
	}

}
