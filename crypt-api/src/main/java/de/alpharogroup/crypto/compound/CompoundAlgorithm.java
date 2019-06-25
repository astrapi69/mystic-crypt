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

import de.alpharogroup.crypto.algorithm.AesAlgorithm;
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.algorithm.MacAlgorithm;
import de.alpharogroup.crypto.algorithm.MdAlgorithm;
import de.alpharogroup.crypto.algorithm.SunJCEAlgorithm;
import de.alpharogroup.crypto.algorithm.UnionWord;
import de.alpharogroup.crypto.mechanisms.PBEMechanism;
import de.alpharogroup.crypto.modes.Mode;
import de.alpharogroup.crypto.pw.PasswordHashType;
import lombok.Getter;

/**
 * The enum {@link CompoundAlgorithm} provides some compound algorithms
 */
public enum CompoundAlgorithm implements Algorithm
{

	/**
	 * The enum constant for the 'PBEWithMD5AndAES' algorithm
	 */
	PBE_WITH_MD5_AND_AES(PBEMechanism.PBE.name() + UnionWord.With.name() + MdAlgorithm.MD5.name()
		+ UnionWord.And.name() + AesAlgorithm.AES.name()),

	/**
	 * The enum constant for the 'PBEWithMD5AndDES' algorithm
	 */
	PBE_WITH_MD5_AND_DES(PBEMechanism.PBE.name() + UnionWord.With.name() + MdAlgorithm.MD5.name()
		+ UnionWord.And.name() + SunJCEAlgorithm.DES.name()),

	/**
	 * The enum constant for the 'PBEWITHSHA1AND128BITAES-CBC-BC' algorithm
	 */
	PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC(
		PBEMechanism.PBE.name() + UnionWord.With.name().toUpperCase() + HashAlgorithm.SHA1.name()
			+ UnionWord.And.name().toUpperCase() + "128BIT" + AesAlgorithm.AES.name() + "-"
			+ Mode.CBC.name() + "-" + Mode.BC.name()),

	/**
	 * The enum constant for the 'PBEWithSHA1AndDESede' algorithm
	 */
	PBE_WITH_SHA1_AND_DES_EDE(PBEMechanism.PBE.name() + UnionWord.With.name()
		+ HashAlgorithm.SHA1.name() + UnionWord.And.name() + SunJCEAlgorithm.DESede.name()),

	/**
	 * The enum constant for the 'PBKDF2WithHmacSHA1' algorithm
	 */
	PBKDF2_WITH_HMAC_SHA1(PasswordHashType.PBKDF2.name() + UnionWord.With.name() + MacAlgorithm.HMAC
		+ HashAlgorithm.SHA1.name()),

	/**
	 * The enum constant for the 'SHA256withRSA' algorithm
	 */
	SHA256_WITH_RSA(HashAlgorithm.SHA256.getAlgorithm() + UnionWord.With.name().toLowerCase()
		+ KeyPairGeneratorAlgorithm.RSA.getAlgorithm());


	/**
	 * Constant for the default iteration count.
	 */
	public static final int ITERATIONCOUNT = 19;

	/**
	 * Constant for the default private key
	 */
	public static final String PRIVATE_KEY = "privatetopsecret";

	/**
	 * Constant array for the default contents of salt
	 */
	public static final byte[] SALT = { (byte)0xA9, (byte)0x9B, (byte)0xC8, (byte)0x32, (byte)0x56,
			(byte)0x35, (byte)0xE3, (byte)0x03 };

	/** The algorithm. */
	@Getter
	private final String algorithm;

	/**
	 * Instantiates a new {@link CompoundAlgorithm} object
	 *
	 * @param algorithm
	 *            the algorithm
	 */
	private CompoundAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}
}
