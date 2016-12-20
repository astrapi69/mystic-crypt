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
package de.alpharogroup.crypto.algorithm;

/**
 * The enum {@link MacAlgorithm} contains the algorithm names that can be specified when requesting an instance of Mac.
 * For more info see:
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac</a>
 *
 * @version 1.0
 */
public enum MacAlgorithm  implements Algorithm
{

	/** The enum constant for HmacMD5 algorithm. */
	HmacMD5,

	/** The enum constant for PBEWithHmacMD5 algorithm. */
	PBEWithHmacMD5,

	/** The enum constant for HmacSHA1 algorithm. */
	HmacSHA1,

	/** The enum constant for PBEWithHmacSHA1 algorithm. */
	PBEWithHmacSHA1,

	/** The enum constant for HmacSHA224 algorithm. */
	HmacSHA224,

	/** The enum constant for PBEWithHmacSHA224 algorithm. */
	PBEWithHmacSHA224,

	/** The enum constant for HmacSHA256 algorithm. */
	HmacSHA256,

	/** The enum constant for PBEWithHmacSHA256 algorithm. */
	PBEWithHmacSHA256,

	/** The enum constant for HmacSHA384 algorithm. */
	HmacSHA384,

	/** The enum constant for PBEWithHmacSHA384 algorithm. */
	PBEWithHmacSHA384,

	/** The enum constant for HmacSHA512 algorithm. */
	HmacSHA512,

	/** The enum constant for PBEWithHmacSHA512 algorithm. */
	PBEWithHmacSHA512;

	public static final String HMAC = "Hmac";

	@Override
	public String getAlgorithm()
	{
		return this.name();
	}
}
