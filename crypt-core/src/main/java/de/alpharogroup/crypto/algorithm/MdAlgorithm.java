package de.alpharogroup.crypto.algorithm;

import lombok.Getter;

/**
 * The enum {@link MdAlgorithm} defines the MessageDigest Algorithm.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public enum MdAlgorithm implements Algorithm
{

	/** The enum constant for MD2 algorithm. */
	MD2("MD2"),

	/** The enum constant for MD4 algorithm. */
	MD4("MD4"),

	/** The enum constant for MD5 algorithm. */
	MD5("MD5");

	/** The algorithm. */
	@Getter
	private final String algorithm;

	/**
	 * Instantiates a new {@link Algorithm} object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	private MdAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}
}
