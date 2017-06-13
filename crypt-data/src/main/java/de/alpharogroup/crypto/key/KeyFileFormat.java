package de.alpharogroup.crypto.key;

import lombok.Getter;

/**
 * The enum {@link KeyFileFormat}.
 */
public enum KeyFileFormat {

	/**
	 * The constant for the file format DER. The DER file format is encoded in
	 * binary form. DER formatted files usually have the file extension '*.der'.
	 */
	DER("der"),

	/**
	 * The constant for the file format PEM. The PEM file format is encoded
	 * in Base64 ASCII format. PEM formatted files usually have the file extension '*.cer', '*.crt' and '*.pem'.
	 */
	PEM("cer", "crt", "pem"),

	/**
	 * The constant for the file format P7B. The P7B file format is encoded
	 * in Base64 ASCII format. PEM formatted files usually have the file extension '*.p7b' and '*.p7c'.
	 */
	P7B("p7b", "p7c");

	/** The file extensions. */
	@Getter
	private final String[] fileExtensions;

	/**
	 * Instantiates a new key file format.
	 *
	 * @param fileExtensions
	 *            the file extensions
	 */
	private KeyFileFormat(String... fileExtensions) {
		this.fileExtensions = fileExtensions;
	}
}
