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

import static org.junit.Assert.assertNull;
import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The class {@link PrivateKeyHexDecryptor}
 */
public class PrivateKeyHexDecryptorTest
{

	/**
	 * Test method for {@link PrivateKeyHexDecryptor} constructors
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 *
	 */
	@Test
	public void testConstructors()
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
		IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException,
		BadPaddingException, InvalidAlgorithmParameterException, DecoderException
	{
		String actual;
		String expected;
		PrivateKey privateKey;
		File derDir;
		File privatekeyDerFile;
		PrivateKeyHexDecryptor decryptor;
		String encypted;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		decryptor = new PrivateKeyHexDecryptor(privateKey);
		assertNotNull(decryptor);
		assertEquals(privateKey, decryptor.getPrivateKey());
		assertNull(decryptor.getCipher());
		encypted = "02A3DD9BD09B568B3DE6B812542D65A85A7D61CB3C5FF0962504929A509A9B9344958D17148F4B863E712A05B1D8BBB91656C421E5D2F0D4E388DFF9453EAB85F1140D5549509BA4E1A58BB62BDF5AF23FA0F852DE7F13F66959F83D823FD5C2F7A7C940FEF9E2E97A8759571DABD9B551C7034581BD71E6E3D403FD3125CC20CADE8DD3B7FE79D5D3D8CDCE46C7629E1FAE18C3DB9EE4B36D624DE59AB0F87B73405C5514864184F3A8E22FBB9BC2E3E489E5B12F74C133267FFCF281BE63544187EE199FC96BB370BBE0424646F314C777FC4E98EB3BBD1671789FA880B601A0ACF8EF4CC51F226B1B7B8F8F2E607EE5C4A1A67092DF545CED067ECAF63BE7";
		actual = decryptor.decrypt(encypted);
		assertNotNull(actual);
		expected = "foo";
		assertEquals(actual, expected);
		assertNotNull(decryptor.getCipher());
	}
}
