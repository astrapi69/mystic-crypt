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
package de.alpharogroup.crypto.key;

import java.io.File;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for the class {@link PublicKeyExtensions}.
 */
public class PublicKeyExtensionsTest
{

	/** The public key base64 encoded for use in tests. */
	public static String PUBLIC_KEY_BASE64_ENCODED = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3prZMWp2kO6rfENO4p7X"
		+ "KNK9OGisJsx4KG1gGfScszdQfIxW/6KaAEWghUShd1n2tyX6Lo3UqA5t9OyhyUnt"
		+ "XnAQ2CZPY5Nq2a5HCbH2e9QIzJdiPBNCXTs3wIprIGJv2T0O9qkOG7CIqhZjirnh"
		+ "aGUAAqMS0hvVDn+AApzv0FcJidaO5qX56Lso5lPpOWCRBEHqwQybXhFrDpbTbY0u"
		+ "0KhXogDnQ+jGt9lMEs8SGvKH0FuW3TuXsDNRk4uHS9w/jbbx1DC1sjFMv3jNHo4T"
		+ "rKopvRlcL2D3uHp/iAAIeU+DXeZSUIERi/FVkQxINRJf2bAdvRNDgTFtCUW4JQdm" + "YQIDAQAB";


	/** The public key in pem format for use in tests. */
	public static String PUBLIC_KEY_PEM_FORMATED =
		PublicKeyReader.BEGIN_PUBLIC_KEY_PREFIX
		+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3prZMWp2kO6rfENO4p7X" + "\n"
		+ "KNK9OGisJsx4KG1gGfScszdQfIxW/6KaAEWghUShd1n2tyX6Lo3UqA5t9OyhyUnt" + "\n"
		+ "XnAQ2CZPY5Nq2a5HCbH2e9QIzJdiPBNCXTs3wIprIGJv2T0O9qkOG7CIqhZjirnh" + "\n"
		+ "aGUAAqMS0hvVDn+AApzv0FcJidaO5qX56Lso5lPpOWCRBEHqwQybXhFrDpbTbY0u" + "\n"
		+ "0KhXogDnQ+jGt9lMEs8SGvKH0FuW3TuXsDNRk4uHS9w/jbbx1DC1sjFMv3jNHo4T" + "\n"
		+ "rKopvRlcL2D3uHp/iAAIeU+DXeZSUIERi/FVkQxINRJf2bAdvRNDgTFtCUW4JQdm" + "\n"
		+ "YQIDAQAB" + "\n"
		+ PublicKeyReader.END_PUBLIC_KEY_SUFFIX;

	/**
	 * Test method for {@link PublicKeyExtensions#toBase64(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test
	public void testToBase64() throws Exception
	{
		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile,
			SecurityProvider.BC);

		final String base64 = PublicKeyExtensions.toBase64(publicKey);
		AssertJUnit.assertEquals(PUBLIC_KEY_BASE64_ENCODED, base64);
	}

	/**
	 * Test method for {@link PublicKeyExtensions#toBase64(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test
	public void testToPemFormat() throws Exception
	{
		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile,
			SecurityProvider.BC);

		final String pemFormat = PublicKeyExtensions.toPemFormat(publicKey);
		final String expected = ReadFileExtensions.readFromFile(publickeyPemFile);
		AssertJUnit.assertEquals(pemFormat, expected);
	}

}
