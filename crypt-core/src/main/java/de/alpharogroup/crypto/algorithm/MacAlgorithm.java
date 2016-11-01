package de.alpharogroup.crypto.algorithm;

/**
 * The enum {@link MacAlgorithm} contains the algorithm names that can be specified when requesting an instance of Mac.
 * For more info see:
 * <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac">https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Mac</a>
 *
 * @version 1.0
 */
public enum MacAlgorithm
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
}
