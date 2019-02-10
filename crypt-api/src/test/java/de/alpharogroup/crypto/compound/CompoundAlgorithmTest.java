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
package de.alpharogroup.crypto.compound;

import static org.testng.AssertJUnit.assertEquals;

import org.testng.annotations.Test;

public class CompoundAlgorithmTest
{

	/**
	 * Test for concatenated constants.
	 */
	@Test
	public void testGetAlgorithms()
	{
		assertEquals(CompoundAlgorithm.PBE_WITH_MD5_AND_DES.getAlgorithm(), "PBEWithMD5AndDES");

		assertEquals(CompoundAlgorithm.PBE_WITH_MD5_AND_AES.getAlgorithm(), "PBEWithMD5AndAES");

		assertEquals(CompoundAlgorithm.PBE_WITH_SHA1_AND_DES_EDE.getAlgorithm(),
			"PBEWithSHA1AndDESede");

		assertEquals(CompoundAlgorithm.PBKDF2_WITH_HMAC_SHA1.getAlgorithm(), "PBKDF2WithHmacSHA1");

		assertEquals(CompoundAlgorithm.PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC.getAlgorithm(),
			"PBEWITHSHA1AND128BITAES-CBC-BC");

		assertEquals(CompoundAlgorithm.SHA256_WITH_RSA.getAlgorithm(), "SHA256withRSA");
	}
}
