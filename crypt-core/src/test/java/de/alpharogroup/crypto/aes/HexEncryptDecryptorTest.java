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
package de.alpharogroup.crypto.aes;


import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;
import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class HexEncryptDecryptorTest
{

	@BeforeMethod
	public void setUp() throws Exception
	{
	}

	@AfterMethod
	public void tearDown() throws Exception
	{
	}

	@Test
	public void testEncryptDecrypt() throws NoSuchAlgorithmException, InvalidKeyException,
		UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException,
		BadPaddingException, DecoderException, InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		final String test = "I'm an hellenic boy and will be encrypted with the HexEncryptor;-)";
		System.out.println("String before encryption:");
		System.out.println(test);
		final String key = "1234567890123456";
//		final HexEncryptor encryptor = new HexEncryptor(key);
		final HexNewEncryptor encryptor = new HexNewEncryptor(key);
		final String encrypted = encryptor.encrypt(test);
		System.out.println("String after encryption:");
		System.out.println(encrypted);
		final HexDecryptor decryptor = new HexDecryptor(key);
		final String decryted = decryptor.decrypt(encrypted);
		System.out.println("String after decryption:");
		System.out.println(decryted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryted));
	}

}
