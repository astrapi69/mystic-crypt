package de.alpharogroup.crypto.algorithm;

import lombok.Getter;

public enum AesAlgorithm implements Algorithm
{

	/** The enum constant for AES algorithm. */
	AES("AES");
	/** The algorithm. */
	@Getter
	private final String algorithm;

	/**
	 * Instantiates a new {@link Algorithm} object.
	 *
	 * @param algorithm
	 *            the algorithm.
	 */
	private AesAlgorithm(final String algorithm)
	{
		this.algorithm = algorithm;
	}
}
