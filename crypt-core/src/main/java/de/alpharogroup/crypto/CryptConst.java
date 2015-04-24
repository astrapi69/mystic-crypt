/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

	/**
	 * Constant for the algorithm to encrypt and decrypt.
	 */
	public static final String PBEWITH_MD5AND_DES = "PBEWithMD5AndDES";

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
