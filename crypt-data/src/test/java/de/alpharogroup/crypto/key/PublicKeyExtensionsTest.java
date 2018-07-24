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
package de.alpharogroup.crypto.key;

import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.factories.KeyPairFactory;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyExtensions}.
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

	PublicKey publicKey;

	File pemDir;

	File derDir;
	File privateKeyPemFile;
	File privateKeyDerFile;
	File publicKeyPemFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privateKeyPemFile = new File(pemDir, "private.pem");
		publicKeyPemFile = new File(pemDir, "public.pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privateKeyDerFile = new File(derDir, "private.der");
	}

	/**
	 * Test method for {@link PublicKeyExtensions#getKeyLength(PrivateKey)}.
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test(enabled = true)
	public void testGetKeyLength() throws Exception
	{
		int actual;
		int expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.getKeyLength(publicKey);
		expected = 2048;
		assertEquals(expected, actual);
		// new scenario...
		actual = PublicKeyExtensions.getKeyLength(null);
		expected = -1;
		assertEquals(expected, actual);
		// new scenario...
		publicKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA, KeySize.KEYSIZE_1024)
			.getPublic();
		actual = PublicKeyExtensions.getKeyLength(publicKey);
		expected = 1024;
		assertEquals(expected, actual);
		// new scenario...
		publicKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.EC, KeySize.KEYSIZE_4096)
			.getPublic();
		actual = PublicKeyExtensions.getKeyLength(publicKey);
		expected = 239;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PublicKeyExtensions#splitByFixedLength(String, int)}
	 */
	@SuppressWarnings("deprecation")
	@Test
	public void testSplitByLength()
	{
		final String input = "HickoryDickoryDockxxxmousexranxupxthexclockxThexcom.foo.barxstruckxonexThexxyxranxdownBlogBarFooEEE";

		final List<String> output = PublicKeyExtensions.splitByFixedLength(input, 7);

		assertTrue(output.size() == 15);
		assertEquals(output.get(1), "Dickory");
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
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);
		actual = PublicKeyExtensions.toBase64(publicKey);
		expected = PUBLIC_KEY_BASE64_ENCODED;
		assertEquals(expected, actual);
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
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.toHexString(publicKey);
		expected = HEX_STRING_ENCODED;
		assertEquals(expected, actual);
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

		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.toHexString(publicKey, false);
		expected = HEX_STRING_ENCODED.toUpperCase();
		assertEquals(expected, actual);
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
		String actual;
		String expected;
		// new scenario...
		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);

		actual = PublicKeyExtensions.toPemFormat(publicKey);
		expected = ReadFileExtensions.readFromFile(publicKeyPemFile);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link PublicKeyExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PublicKeyExtensions.class);
	}

}
