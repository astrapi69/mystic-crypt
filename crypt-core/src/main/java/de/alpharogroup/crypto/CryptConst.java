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
package de.alpharogroup.crypto;

/**
 * Abstract constant class for Crypto object.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public abstract class CryptConst
{

	/**
	 * Constant array for the contents of salt.
	 */
	public static final byte[] SALT = { (byte)0xA9, (byte)0x9B, (byte)0xC8, (byte)0x32, (byte)0x56,
			(byte)0x35, (byte)0xE3, (byte)0x03 };

	/**
	 * Constant for the iteration count.
	 */
	public static final int ITERATIONCOUNT = 19;

	/**
	 * Constant for the private key.
	 */
	public static final String PRIVATE_KEY = "privattop secret";


	public static final String PBEWITH = "PBEWith";

	/**
	 * Constant for the algorithm to encrypt and decrypt.
	 */
	public static final String PBEWITH_MD5AND_DES = PBEWITH+ "MD5AndDES";

	/**
	 * Constant for the algorithm to encrypt and decrypt.
	 */
	public static final String PBEWITH_MD5AND_AES = "PBEWithMD5AndAES";

	/**
	 * Constant for the algorithm to encrypt and decrypt.
	 */
	public static final String PBEWITH_SHA1_AND_DES_EDE = "PBEWithSHA1AndDESede";

	/**
	 * Constant for the algorithm to encrypt and decrypt.
	 */
	public static final String PBKDF2_WITH_HMAC_SHA1 = "PBKDF2WithHmacSHA1";

	/**
	 * Constant for the algorithm to encrypt and decrypt.
	 */
	public static final String PBEWITH_SHA1_AND_128BIT_AES_CBC_BC = "PBEWITHSHA1AND128BITAES-CBC-BC";

	/**
	 * Constant for the encoding for the String.
	 */
	public static final String ENCODING = "UTF8";

	/**
	 * Constant for the initialization from SimpleEncryptor.
	 */
	public static final String SIMPLE_ENCRYPTOR = "SimpleEncryptor";

	/**
	 * Constant for the initialization from SimpleDecryptor.
	 */
	public static final String SIMPLE_DECRYPTOR = "SimpleDecryptor";
}
