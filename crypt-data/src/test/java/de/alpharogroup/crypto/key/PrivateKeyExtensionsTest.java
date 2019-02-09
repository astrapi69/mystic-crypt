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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.factories.KeyPairFactory;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PrivateKeyExtensions}
 */
public class PrivateKeyExtensionsTest
{

	public static String BASE64_ENCODED = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDemtkxanaQ7qt8Q07intco0r04aKwmzHgobWAZ9JyzN1B8jFb/opoARaCFRKF3Wfa3JfoujdSoDm307KHJSe1ecBDYJk9jk2rZrkcJsfZ71AjMl2I8E0JdOzfAimsgYm/ZPQ72qQ4bsIiqFmOKueFoZQACoxLSG9UOf4ACnO/QVwmJ1o7mpfnouyjmU+k5YJEEQerBDJteEWsOltNtjS7QqFeiAOdD6Ma32UwSzxIa8ofQW5bdO5ewM1GTi4dL3D+NtvHUMLWyMUy/eM0ejhOsqim9GVwvYPe4en+IAAh5T4Nd5lJQgRGL8VWRDEg1El/ZsB29E0OBMW0JRbglB2ZhAgMBAAECggEAF6rvHMntAUve/79IS+AHkFeXtr+qThW/UM0QQrI3VvayoAtr1JI9PXoprwG1CTOPf7mR+BEsYxHlrvzZ1sT9b+UKZXDtT/EEk1BsTSOWyWOp69bMowaJL9B0BQyyhybwLXDIfoFK9ra2UR9ARietR6Q1dBJSlfRPmtMDkUOOW+AySJOm0xPiwneNLd0yNcHvXe6jicQcR4P40PlAQrO6VXSeC5i7sQaomQhS7+RW3x14VndBwNve88d4/gOlcthM/MaRF6RoPtes6Rx9aXOGTzMGel99ntTHD/i2FBfCywOkL0VgfEcfnB7pLptJxQ2rLpEBHleWET7j0FokU8Nc4QKBgQD/81QfPQia+gCCc28/sOUJH90/NUROeRJyyl/zD7ddUE05aTxRG78LFtUw71v4tdSLC3q0K5zOXZYz4YptymTaabjsA7Q4oJg45QOP2Xs6myVRduSscj8ydMhb+d+KdpZRGok0SDpbMb8ezyLr7CS9MO1U/5c61p1YO6lq8ExrhwKBgQDepd50HjMNlB5M5lCGvh3gqM0/9U+StoxUqwI4ZVSayirJkPzAH0JctKyq2uERoFQWfS2W3AgD0xzLMpGUH6zkzqBXlq1IVqvADwRuIqayK+wYJj5iy3IWNePh1evsIHdjiKuaAPFViPulERq5cYJZBl2wXoYorCjpCaTydpQo1wKBgG6KGHqlUWIdNrsgP5uyOjiGmncB+k4p293XqTjAQOD8HV3+JR6ibQ/M/KX1ujLf1Lt4abYGX+KAaK5fafmgv43UuxizQNJ0CUoJHlCyDJZzCtr0Di6r6L9R0HZopDKYpLLCUx9RUmKwSWp06xAZHITY7KcY+6ddqPbCTZjxzw9hAoGAUX588hurrCiu/o6+otMrtHOUzPhJa/YNX2BIq8PLN+0PxD+hg+DtNWmcWd1LzFvW63ReH33iISRAwc98oa8GZamL3wNz4ap3qxDUGkvsoAKbpCs7YoX8+Ew5YQwgEom/qVr5FKGLtDczhLPCCGaXw2YlHM08Zd6+Cq5RBb6JdHkCgYBn2FhcBGdRjpi/7UB2VBUFNVY9RmvedLx2zwi1hLZuhHBMqG90kFWB0ZMPtrmlawcicrl1w71ywHlPTyUd2asDOCNFW2Q0i9DoQ9VFVWyogs1cpUMxSmA7wILobRLURes2vGlyqOdY0vkSGYAoNERNNG4YHiH9HCMhr6jCvHSQOg==";

	/** The hex string encoded for use in tests. */
	public static String HEX_STRING_ENCODED = "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100de9ad9316a7690eeab7c434ee29ed728d2bd3868ac26cc78286d6019f49cb337507c8c56ffa29a0045a08544a17759f6b725fa2e8dd4a80e6df4eca1c949ed5e7010d8264f63936ad9ae4709b1f67bd408cc97623c13425d3b37c08a6b20626fd93d0ef6a90e1bb088aa16638ab9e168650002a312d21bd50e7f80029cefd0570989d68ee6a5f9e8bb28e653e93960910441eac10c9b5e116b0e96d36d8d2ed0a857a200e743e8c6b7d94c12cf121af287d05b96dd3b97b03351938b874bdc3f8db6f1d430b5b2314cbf78cd1e8e13acaa29bd195c2f60f7b87a7f880008794f835de6525081118bf155910c4835125fd9b01dbd134381316d0945b82507666102030100010282010017aaef1cc9ed014bdeffbf484be007905797b6bfaa4e15bf50cd1042b23756f6b2a00b6bd4923d3d7a29af01b509338f7fb991f8112c6311e5aefcd9d6c4fd6fe50a6570ed4ff10493506c4d2396c963a9ebd6cca306892fd074050cb28726f02d70c87e814af6b6b6511f404627ad47a43574125295f44f9ad30391438e5be0324893a6d313e2c2778d2ddd3235c1ef5deea389c41c4783f8d0f94042b3ba55749e0b98bbb106a8990852efe456df1d78567741c0dbdef3c778fe03a572d84cfcc69117a4683ed7ace91c7d6973864f33067a5f7d9ed4c70ff8b61417c2cb03a42f45607c471f9c1ee92e9b49c50dab2e91011e5796113ee3d05a2453c35ce102818100fff3541f3d089afa0082736f3fb0e5091fdd3f35444e791272ca5ff30fb75d504d39693c511bbf0b16d530ef5bf8b5d48b0b7ab42b9cce5d9633e18a6dca64da69b8ec03b438a09838e5038fd97b3a9b255176e4ac723f3274c85bf9df8a7696511a8934483a5b31bf1ecf22ebec24bd30ed54ff973ad69d583ba96af04c6b8702818100dea5de741e330d941e4ce65086be1de0a8cd3ff54f92b68c54ab023865549aca2ac990fcc01f425cb4acaadae111a054167d2d96dc0803d31ccb3291941face4cea05796ad4856abc00f046e22a6b22bec18263e62cb721635e3e1d5ebec20776388ab9a00f15588fba5111ab9718259065db05e8628ac28e909a4f2769428d70281806e8a187aa551621d36bb203f9bb23a38869a7701fa4e29dbddd7a938c040e0fc1d5dfe251ea26d0fccfca5f5ba32dfd4bb7869b6065fe28068ae5f69f9a0bf8dd4bb18b340d274094a091e50b20c96730adaf40e2eabe8bf51d07668a43298a4b2c2531f515262b0496a74eb10191c84d8eca718fba75da8f6c24d98f1cf0f61028180517e7cf21babac28aefe8ebea2d32bb47394ccf8496bf60d5f6048abc3cb37ed0fc43fa183e0ed35699c59dd4bcc5bd6eb745e1f7de2212440c1cf7ca1af0665a98bdf0373e1aa77ab10d41a4beca0029ba42b3b6285fcf84c39610c201289bfa95af914a18bb4373384b3c2086697c366251ccd3c65debe0aae5105be89747902818067d8585c0467518e98bfed407654150535563d466bde74bc76cf08b584b66e84704ca86f74905581d1930fb6b9a56b072272b975c3bd72c0794f4f251dd9ab033823455b64348bd0e843d545556ca882cd5ca543314a603bc082e86d12d445eb36bc6972a8e758d2f91219802834444d346e181e21fd1c2321afa8c2bc74903a";

	/** The private key base64 encoded for use in tests. */
	public static String PRIVATE_KEY_BASE64_ENCODED = "-----BEGIN RSA PRIVATE KEY-----\n"
		+ "MIIEogIBAAKCAQEA3prZMWp2kO6rfENO4p7XKNK9OGisJsx4KG1gGfScszdQfIxW" + "\n"
		+ "/6KaAEWghUShd1n2tyX6Lo3UqA5t9OyhyUntXnAQ2CZPY5Nq2a5HCbH2e9QIzJdi" + "\n"
		+ "PBNCXTs3wIprIGJv2T0O9qkOG7CIqhZjirnhaGUAAqMS0hvVDn+AApzv0FcJidaO" + "\n"
		+ "5qX56Lso5lPpOWCRBEHqwQybXhFrDpbTbY0u0KhXogDnQ+jGt9lMEs8SGvKH0FuW" + "\n"
		+ "3TuXsDNRk4uHS9w/jbbx1DC1sjFMv3jNHo4TrKopvRlcL2D3uHp/iAAIeU+DXeZS" + "\n"
		+ "UIERi/FVkQxINRJf2bAdvRNDgTFtCUW4JQdmYQIDAQABAoIBABeq7xzJ7QFL3v+/" + "\n"
		+ "SEvgB5BXl7a/qk4Vv1DNEEKyN1b2sqALa9SSPT16Ka8BtQkzj3+5kfgRLGMR5a78" + "\n"
		+ "2dbE/W/lCmVw7U/xBJNQbE0jlsljqevWzKMGiS/QdAUMsocm8C1wyH6BSva2tlEf" + "\n"
		+ "QEYnrUekNXQSUpX0T5rTA5FDjlvgMkiTptMT4sJ3jS3dMjXB713uo4nEHEeD+ND5" + "\n"
		+ "QEKzulV0nguYu7EGqJkIUu/kVt8deFZ3QcDb3vPHeP4DpXLYTPzGkRekaD7XrOkc" + "\n"
		+ "fWlzhk8zBnpffZ7Uxw/4thQXwssDpC9FYHxHH5we6S6bScUNqy6RAR5XlhE+49Ba" + "\n"
		+ "JFPDXOECgYEA//NUHz0ImvoAgnNvP7DlCR/dPzVETnkScspf8w+3XVBNOWk8URu/" + "\n"
		+ "CxbVMO9b+LXUiwt6tCuczl2WM+GKbcpk2mm47AO0OKCYOOUDj9l7OpslUXbkrHI/" + "\n"
		+ "MnTIW/nfinaWURqJNEg6WzG/Hs8i6+wkvTDtVP+XOtadWDupavBMa4cCgYEA3qXe" + "\n"
		+ "dB4zDZQeTOZQhr4d4KjNP/VPkraMVKsCOGVUmsoqyZD8wB9CXLSsqtrhEaBUFn0t" + "\n"
		+ "ltwIA9McyzKRlB+s5M6gV5atSFarwA8EbiKmsivsGCY+YstyFjXj4dXr7CB3Y4ir" + "\n"
		+ "mgDxVYj7pREauXGCWQZdsF6GKKwo6Qmk8naUKNcCgYBuihh6pVFiHTa7ID+bsjo4" + "\n"
		+ "hpp3AfpOKdvd16k4wEDg/B1d/iUeom0PzPyl9boy39S7eGm2Bl/igGiuX2n5oL+N" + "\n"
		+ "1LsYs0DSdAlKCR5QsgyWcwra9A4uq+i/UdB2aKQymKSywlMfUVJisElqdOsQGRyE" + "\n"
		+ "2OynGPunXaj2wk2Y8c8PYQKBgFF+fPIbq6worv6OvqLTK7RzlMz4SWv2DV9gSKvD" + "\n"
		+ "yzftD8Q/oYPg7TVpnFndS8xb1ut0Xh994iEkQMHPfKGvBmWpi98Dc+Gqd6sQ1BpL" + "\n"
		+ "7KACm6QrO2KF/PhMOWEMIBKJv6la+RShi7Q3M4Szwghml8NmJRzNPGXevgquUQW+" + "\n"
		+ "iXR5AoGAZ9hYXARnUY6Yv+1AdlQVBTVWPUZr3nS8ds8ItYS2boRwTKhvdJBVgdGT" + "\n"
		+ "D7a5pWsHInK5dcO9csB5T08lHdmrAzgjRVtkNIvQ6EPVRVVsqILNXKVDMUpgO8CC" + "\n"
		+ "6G0S1EXrNrxpcqjnWNL5EhmAKDRETTRuGB4h/RwjIa+owrx0kDo=\n"
		+ "-----END RSA PRIVATE KEY-----\n";

	File derDir;
	File pemDir;

	PrivateKey privateKey;

	File privateKeyDerFile;
	File privateKeyPemFile;
	PublicKey publicKey;
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
	 * Test method for {@link PrivateKeyExtensions#generatePublicKey(PrivateKey)}
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
	public void testGeneratePublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		PublicKey expected;
		PublicKey actual;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		publicKey = PublicKeyReader.readPemPublicKey(publicKeyPemFile);
		expected = publicKey;

		actual = PrivateKeyExtensions.generatePublicKey(privateKey);
		assertEquals(expected, actual);
		// new scenario...
		privateKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA, KeySize.KEYSIZE_1024)
			.getPrivate();

		expected = null;
		actual = PrivateKeyExtensions.generatePublicKey(privateKey);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#getKeyLength(PrivateKey)}
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
	public void testGetKeyLength() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		int actual;
		int expected;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		actual = PrivateKeyExtensions.getKeyLength(privateKey);
		expected = 2048;
		assertEquals(expected, actual);
		// new scenario...
		actual = PrivateKeyExtensions.getKeyLength(null);
		expected = -1;
		assertEquals(expected, actual);
		// new scenario...
		privateKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.DSA, KeySize.KEYSIZE_1024)
			.getPrivate();
		actual = PrivateKeyExtensions.getKeyLength(privateKey);
		expected = 160;
		assertEquals(expected, actual);
		// new scenario...
		privateKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.EC, KeySize.KEYSIZE_4096)
			.getPrivate();
		actual = PrivateKeyExtensions.getKeyLength(privateKey);
		expected = 239;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#getKeySize(PrivateKey)}
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
	public void testGetKeySize() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		KeySize actual;
		KeySize expected;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		actual = PrivateKeyExtensions.getKeySize(privateKey);
		expected = KeySize.KEYSIZE_2048;
		assertEquals(expected, actual);
		// new scenario...
		actual = PrivateKeyExtensions.getKeySize(null);
		expected = null;
		assertEquals(expected, actual);
		// new scenario...
		privateKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_1024)
			.getPrivate();
		actual = PrivateKeyExtensions.getKeySize(privateKey);
		expected = KeySize.KEYSIZE_1024;
		assertEquals(expected, actual);
		// new scenario...
		privateKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_4096)
			.getPrivate();
		actual = PrivateKeyExtensions.getKeySize(privateKey);
		expected = KeySize.KEYSIZE_4096;
		assertEquals(expected, actual);
		// new scenario...
		privateKey = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_8192)
			.getPrivate();
		actual = PrivateKeyExtensions.getKeySize(privateKey);
		expected = KeySize.KEYSIZE_8192;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toBase64(PrivateKey)}
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
	public void testToBase64() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		String actual;
		String expected;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		actual = PrivateKeyExtensions.toBase64(privateKey);
		expected = BASE64_ENCODED;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toBase64(PrivateKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test(enabled = true)
	public void testToBase64Binary() throws Exception
	{
		String actual;
		String expected;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		actual = PrivateKeyExtensions.toBase64Binary(privateKey);
		expected = BASE64_ENCODED; // ???
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toHexString(PrivateKey)}
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
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		actual = PrivateKeyExtensions.toHexString(privateKey);
		expected = HEX_STRING_ENCODED;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toHexString(PrivateKey)}
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
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		actual = PrivateKeyExtensions.toHexString(privateKey, false);
		expected = HEX_STRING_ENCODED.toUpperCase();
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toBase64(PrivateKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test(enabled = true)
	public void testToPemFormat() throws Exception
	{
		String expected;
		String actual;
		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);

		actual = PrivateKeyExtensions.toPemFormat(privateKey);
		expected = PRIVATE_KEY_BASE64_ENCODED;
		assertEquals(expected, actual);

	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toPKCS8Format(PrivateKey)}
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
	public void testToPKCS1Format() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		Security.addProvider(new BouncyCastleProvider());
		byte[] pkcs1Format;
		PemObject pemObject;
		PKCS8EncodedKeySpec keySpec;
		KeyFactory kf;
		PrivateKey privateKey1;

		// new scenario...
		privateKey = PrivateKeyReader.readPemPrivateKey(privateKeyPemFile);
		pkcs1Format = PrivateKeyExtensions.toPKCS1Format(privateKey);
		assertNotNull(pkcs1Format);

		pemObject = new PemObject("RSA PUBLIC KEY", pkcs1Format);
		keySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
		kf = KeyFactory.getInstance("RSA");
		privateKey1 = kf.generatePrivate(keySpec);
		assertEquals(privateKey1, privateKey);

	}

	/**
	 * Test method for {@link PrivateKeyExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(PrivateKeyExtensions.class);
	}

}
