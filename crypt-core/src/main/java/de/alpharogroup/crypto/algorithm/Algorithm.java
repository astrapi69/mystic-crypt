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
package de.alpharogroup.crypto.algorithm;

/**
 * The Enum Algorithm.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public enum Algorithm
{

	/** The enum constant for MD2 algorithm. */
	MD2("MD2"),

	/** The enum constant for MD4 algorithm. */
	MD4("MD4"),

	/** The enum constant for MD5 algorithm. */
	MD5("MD5"),

	/** The enum constant for SHA-1 algorithm. */
	SHA_1("SHA-1"),

	/** The enum constant for SHA-256 algorithm. */
	SHA_256("SHA-256"),

	/** The enum constant for SHA-384 algorithm. */
	SHA_384("SHA-384"),

	/** The enum constant for SHA-512 algorithm. */
	SHA_512("SHA-512"),

	/** The enum constant for AES algorithm. */
	AES("AES");

	/** The algorithm. */
	private final String algorithm;

	/**
	 * Instantiates a new Algorithm object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	Algorithm(final String algorithm)
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
		return algorithm;
	}
}