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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PublicKeyReader;
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
	public static String PUBLIC_KEY_PEM_FORMATED = PublicKeyReader.BEGIN_PUBLIC_KEY_PREFIX
		+ "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3prZMWp2kO6rfENO4p7X" + "\n"
		+ "KNK9OGisJsx4KG1gGfScszdQfIxW/6KaAEWghUShd1n2tyX6Lo3UqA5t9OyhyUnt" + "\n"
		+ "XnAQ2CZPY5Nq2a5HCbH2e9QIzJdiPBNCXTs3wIprIGJv2T0O9qkOG7CIqhZjirnh" + "\n"
		+ "aGUAAqMS0hvVDn+AApzv0FcJidaO5qX56Lso5lPpOWCRBEHqwQybXhFrDpbTbY0u" + "\n"
		+ "0KhXogDnQ+jGt9lMEs8SGvKH0FuW3TuXsDNRk4uHS9w/jbbx1DC1sjFMv3jNHo4T" + "\n"
		+ "rKopvRlcL2D3uHp/iAAIeU+DXeZSUIERi/FVkQxINRJf2bAdvRNDgTFtCUW4JQdm" + "\n" + "YQIDAQAB"
		+ "\n" + PublicKeyReader.END_PUBLIC_KEY_SUFFIX;

	/** The hex string encoded for use in tests. */
	public static String HEX_STRING_ENCODED = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100de9ad9316a7690eeab7c434ee29ed728d2bd3868ac26cc78286d6019f49cb337507c8c56ffa29a0045a08544a17759f6b725fa2e8dd4a80e6df4eca1c949ed5e7010d8264f63936ad9ae4709b1f67bd408cc97623c13425d3b37c08a6b20626fd93d0ef6a90e1bb088aa16638ab9e168650002a312d21bd50e7f80029cefd0570989d68ee6a5f9e8bb28e653e93960910441eac10c9b5e116b0e96d36d8d2ed0a857a200e743e8c6b7d94c12cf121af287d05b96dd3b97b03351938b874bdc3f8db6f1d430b5b2314cbf78cd1e8e13acaa29bd195c2f60f7b87a7f880008794f835de6525081118bf155910c4835125fd9b01dbd134381316d0945b8250766610203010001";

	/**
	 * Test method for {@link PublicKeyExtensions#getKeyLength(PrivateKey)}.
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test(enabled = true)
	public void testGetKeyLength() throws Exception
	{

		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		final int actual = PublicKeyExtensions.getKeyLength(publicKey);
		final int expected = 2048;
		AssertJUnit.assertEquals(expected, actual);
	}

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

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		final String base64 = PublicKeyExtensions.toBase64(publicKey);
		AssertJUnit.assertEquals(PUBLIC_KEY_BASE64_ENCODED, base64);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toHexString(PrivateKey)}.
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test(enabled = true)
	public void testToHexString() throws Exception
	{

		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		final String actual = PublicKeyExtensions.toHexString(publicKey);
		final String expected = HEX_STRING_ENCODED;
		AssertJUnit.assertEquals(expected, actual);
	}


	/**
	 * Test method for {@link PrivateKeyExtensions#toHexString(PrivateKey)}.
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test(enabled = true)
	public void testToHexStringBoolean() throws Exception
	{

		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		final String actual = PublicKeyExtensions.toHexString(publicKey, false);
		final String expected = HEX_STRING_ENCODED.toUpperCase();
		AssertJUnit.assertEquals(expected, actual);
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

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		final String pemFormat = PublicKeyExtensions.toPemFormat(publicKey);
		final String expected = ReadFileExtensions.readFromFile(publickeyPemFile);
		AssertJUnit.assertEquals(pemFormat, expected);
	}

}
