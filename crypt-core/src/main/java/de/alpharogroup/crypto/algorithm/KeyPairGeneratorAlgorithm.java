/**
 * Copyright (C) 2015 Asterios Raptis
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
package de.alpharogroup.crypto.algorithm;

/**
 * The enum {@link KeyPairGeneratorAlgorithm}.
 * For more info see:
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator</a>
 *
 * @version 1.0
 */
public enum KeyPairGeneratorAlgorithm
{
	/** The enum constant for DIFFIE_HELLMAN algorithm. */
	DIFFIE_HELLMAN("DiffieHellman"),

	/** The enum constant for EC algorithm. */
	EC("EC"),
	/** The enum constant for DSA algorithm. */
	DSA("DSA"),
	/** The enum constant for RSA algorithm. */
	RSA("RSA");
	/** The algorithm. */
	private final String algorithm;

	/**
	 * Instantiates a new KeyPairAlgorithm object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	KeyPairGeneratorAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}

	/**
	 * Gets the algorithm.
	 *
	 * @return the algorithm
	 */
	public String getAlgorithm()
	{
		return this.algorithm;
	}
}
