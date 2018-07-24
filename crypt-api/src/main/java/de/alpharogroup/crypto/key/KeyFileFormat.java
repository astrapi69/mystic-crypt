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
package de.alpharogroup.crypto.key;

import lombok.Getter;

/**
 * The enum {@link KeyFileFormat}.
 */
public enum KeyFileFormat
{

	/**
	 * The constant for the file format DER. The DER file format is encoded in binary form. DER
	 * formatted files usually have the file extension '*.der'.
	 */
	DER("der"),

	/**
	 * The constant for the file format PEM. The PEM file format is encoded in Base64 ASCII format.
	 * PEM formatted files usually have the file extension '*.cer', '*.crt' and '*.pem'.
	 */
	PEM("cer", "crt", "pem"),

	/**
	 * The constant for the file format P7B. The P7B file format is encoded in Base64 ASCII format.
	 * PEM formatted files usually have the file extension '*.p7b' and '*.p7c'.
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
	private KeyFileFormat(String... fileExtensions)
	{
		this.fileExtensions = fileExtensions;
	}
}
