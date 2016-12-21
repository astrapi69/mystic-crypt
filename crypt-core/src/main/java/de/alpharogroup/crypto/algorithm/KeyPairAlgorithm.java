package de.alpharogroup.crypto.algorithm;
/**
 * The Enum KeyPairAlgorithm.
 *
 * @version 1.0
 */
public enum KeyPairAlgorithm
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
	KeyPairAlgorithm(final String algorithm)
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
