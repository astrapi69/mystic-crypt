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
package de.alpharogroup.crypto.algorithm;

import de.alpharogroup.crypto.modes.Mode;
import de.alpharogroup.crypto.padding.PaddingScheme;
import lombok.Getter;

/**
 * The enum {@link KeyPairWithModeAndPaddingAlgorithm}.
 *
 * @version 1.0
 */
public enum KeyPairWithModeAndPaddingAlgorithm implements Algorithm
{

	/**
	 * The enum constant with the 'RSA' algorithm with mode 'ECB' and padding
	 * 'OAEPWithSHA1AndMGF1Padding' that results in 'RSA/ECB/OAEPWithSHA1AndMGF1Padding'.
	 */
	RSA_ECB_OAEPWithSHA1AndMGF1Padding(KeyPairGeneratorAlgorithm.RSA.getAlgorithm() + "/"
		+ Mode.ECB.name() + "/" + PaddingScheme.OAEPWithSHA1AndMGF1Padding.getScheme()),

	/**
	 * The enum constant with the 'RSA' algorithm with mode 'ECB' and padding
	 * 'OAEPWithSHA256AndMGF1Padding' that results in 'RSA/ECB/OAEPWithSHA256AndMGF1Padding'.
	 */
	RSA_ECB_OAEPWithSHA256AndMGF1Padding(KeyPairGeneratorAlgorithm.RSA.getAlgorithm() + "/"
		+ Mode.ECB.name() + "/" + PaddingScheme.OAEPWithSHA256AndMGF1Padding.getScheme()),

	/**
	 * The enum constant with the 'RSA' algorithm with mode 'ECB' and padding
	 * 'OAEPWithSHA-1AndMGF1Padding' that results in 'RSA/ECB/OAEPWithSHA-1AndMGF1Padding'.
	 */
	RSA_ECB_OAEPWithSHA_1AndMGF1Padding(KeyPairGeneratorAlgorithm.RSA.getAlgorithm() + "/"
		+ Mode.ECB.name() + "/" + PaddingScheme.OAEPWithSHA_1AndMGF1Padding.getScheme()),

	/**
	 * The enum constant with the 'RSA' algorithm with mode 'ECB' and padding
	 * 'OAEPWithSHA-256AndMGF1Padding' that results in 'RSA/ECB/OAEPWithSHA-256AndMGF1Padding'.
	 */
	RSA_ECB_OAEPWithSHA_256AndMGF1Padding(KeyPairGeneratorAlgorithm.RSA.getAlgorithm() + "/"
		+ Mode.ECB.name() + "/" + PaddingScheme.OAEPWithSHA_256AndMGF1Padding.getScheme()),

	/**
	 * The enum constant with the 'RSA' algorithm with mode 'ECB' and padding 'PKCS1Padding' that
	 * results in 'RSA/ECB/PKCS1Padding'.
	 */
	RSA_ECB_PKCS1PADDING(KeyPairGeneratorAlgorithm.RSA.name() + "/" + Mode.ECB.name() + "/"
		+ PaddingScheme.PKCS1Padding.name()),

	/**
	 * The enum constant with the 'DESede' algorithm with mode 'CBC' and padding 'PKCS5Padding' that
	 * results in 'DESede/CBC/PKCS5Padding'.
	 */
	DESede_CBC_PKCS5Padding(SunJCEAlgorithm.DESede.name() + "/" + Mode.CBC.name() + "/"
		+ PaddingScheme.PKCS5Padding.name());


	/** The algorithm. */
	@Getter
	private final String algorithm;

	/**
	 * Instantiates a new {@link KeyPairWithModeAndPaddingAlgorithm} object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	private KeyPairWithModeAndPaddingAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}

}
