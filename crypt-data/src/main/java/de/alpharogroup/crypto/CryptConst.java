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
package de.alpharogroup.crypto;

import de.alpharogroup.crypto.algorithm.AesAlgorithm;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.algorithm.MacAlgorithm;
import de.alpharogroup.crypto.algorithm.MdAlgorithm;
import de.alpharogroup.crypto.algorithm.SunJCEAlgorithm;
import de.alpharogroup.crypto.algorithm.UnionWord;
import de.alpharogroup.crypto.mechanisms.PBEMechanism;
import de.alpharogroup.crypto.pw.PasswordHashType;

/**
 * The abstract class {@link CryptConst} that holds constants for Crypto object.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public abstract class CryptConst
{

	/**
	 * Constant for the iteration count.
	 */
	public static final int ITERATIONCOUNT = 19;

	/** The Constant PBE_WITH. */
	public static final String PBE_WITH = PBEMechanism.PBE.name() + UnionWord.With.name();

	/**
	 * Constant for the algorithm 'PBEWithMD5AndAES' to encrypt and decrypt.
	 */
	public static final String PBE_WITH_MD5_AND_AES = PBE_WITH + MdAlgorithm.MD5.name()
		+ UnionWord.And.name() + AesAlgorithm.AES.name();

	/**
	 * Constant for the algorithm 'PBEWithMD5AndDES' to encrypt and decrypt.
	 */
	public static final String PBE_WITH_MD5_AND_DES = PBE_WITH + MdAlgorithm.MD5.name()
		+ UnionWord.And.name() + SunJCEAlgorithm.DES.name();

	/**
	 * Constant for the algorithm 'PBEWITHSHA1AND128BITAES-CBC-BC' to encrypt and decrypt.
	 */
	public static final String PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC = "PBEWITHSHA1AND128BITAES-CBC-BC";

	/**
	 * Constant for the algorithm 'PBEWithSHA1AndDESede' to encrypt and decrypt.
	 */
	public static final String PBE_WITH_SHA1_AND_DES_EDE = PBE_WITH + HashAlgorithm.SHA1.name()
		+ UnionWord.And.name() + SunJCEAlgorithm.DESede.name();

	/**
	 * Constant for the algorithm 'PBKDF2WithHmacSHA1' to encrypt and decrypt.
	 */
	public static final String PBKDF2_WITH_HMAC_SHA1 = PasswordHashType.PBKDF2.name() + UnionWord.With.name()
		+ MacAlgorithm.HMAC + HashAlgorithm.SHA1.name();

	/**
	 * Constant for the private key.
	 */
	public static final String PRIVATE_KEY = "privattop secret";

	/**
	 * Constant array for the contents of salt.
	 */
	public static final byte[] SALT = { (byte)0xA9, (byte)0x9B, (byte)0xC8, (byte)0x32, (byte)0x56,
			(byte)0x35, (byte)0xE3, (byte)0x03 };

	/** Constant for algorithm 'SHA256withRSA' to encrypt and decrypt. */
	public static final String SHA256_WITH_RSA = HashAlgorithm.SHA256.getAlgorithm()
		+ UnionWord.With.name().toLowerCase() + KeyPairGeneratorAlgorithm.RSA.getAlgorithm();

	/**
	 * Constant for the initialization from SimpleDecryptor.
	 */
	public static final String SIMPLE_DECRYPTOR = "SimpleDecryptor";

	/**
	 * Constant for the initialization from SimpleEncryptor.
	 */
	public static final String SIMPLE_ENCRYPTOR = "SimpleEncryptor";

}
