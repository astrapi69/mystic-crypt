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
package de.alpharogroup.crypto.checksum;

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import de.alpharogroup.copy.object.CopyObjectExtensions;
import de.alpharogroup.crypto.algorithm.Algorithm;
import lombok.experimental.UtilityClass;

/**
 * The class {@link ObjectChecksumExtensions} is a utility class for computing checksum from objects
 *
 * @version 1.0
 * @author Asterios Raptis
 * @deprecated use instead the same name class from project checksum-up<br><br>
 *     Note: will be removed in next minor version
 */
@UtilityClass
public final class ObjectChecksumExtensions
{

	/**
	 * Gets the checksum from the given serializable object. If the flag crc is true than the
	 * checksum is constructed with an instance of <code>java.util.zip.CRC32</code> otherwise with
	 * an instance of <code>java.util.zip.Adler32</code>.
	 *
	 * @param <T>
	 *            the generic type of the serializable object
	 * @param serializableObject
	 *            the serializable object from what to get the checksum
	 * @param crc
	 *            the crc flag
	 * @return The checksum from the given serializable object as long
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static <T extends Serializable> long getChecksum(final T serializableObject,
		final boolean crc) throws IOException
	{
		return crc
			? ByteArrayChecksumExtensions
				.getCheckSumCRC32(CopyObjectExtensions.toByteArray(serializableObject))
			: ByteArrayChecksumExtensions
				.getCheckSumAdler32(CopyObjectExtensions.toByteArray(serializableObject));
	}

	/**
	 * Gets the checksum from the given file with an instance of the given algorithm
	 *
	 * @param <T>
	 *            the generic type of the serializable object
	 *
	 * @param serializableObject
	 *            the serializable object
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link MessageDigest} object.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static <T extends Serializable> String getChecksum(final T serializableObject,
		final String algorithm) throws NoSuchAlgorithmException, IOException
	{
		return ByteArrayChecksumExtensions
			.getChecksum(CopyObjectExtensions.toByteArray(serializableObject), algorithm);
	}

	/**
	 * Gets the checksum from the given file with an instance of the given algorithm
	 *
	 * @param <T>
	 *            the generic type of the serializable object
	 *
	 * @param serializableObject
	 *            the serializable object
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link MessageDigest} object.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static <T extends Serializable> String getChecksum(final T serializableObject,
		final Algorithm algorithm) throws NoSuchAlgorithmException, IOException
	{
		return getChecksum(serializableObject, algorithm.getAlgorithm());
	}

	/**
	 * Gets the checksum from the given file with an instance of the given algorithm.
	 *
	 * @param text
	 *            the string
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link MessageDigest} object.
	 */
	public static String getChecksum(final String text, final String algorithm)
		throws NoSuchAlgorithmException
	{
		return ByteArrayChecksumExtensions.getChecksum(text.getBytes(), algorithm);
	}

	/**
	 * Gets the checksum from the given file with an instance of the given algorithm.
	 *
	 * @param text
	 *            the string
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link MessageDigest} object.
	 */
	public static String getChecksum(final String text, final Algorithm algorithm)
		throws NoSuchAlgorithmException
	{
		return getChecksum(text, algorithm.getAlgorithm());
	}

	/**
	 * Gets the checksum from the given string. If the flag crc is true than the checksum is
	 * constructed with an instance of <code>java.util.zip.CRC32</code> otherwise with an instance
	 * of <code>java.util.zip.Adler32</code>.
	 *
	 * @param text
	 *            the string
	 * @param crc
	 *            the crc flag
	 * @return The checksum from the given string as long
	 */
	public static long getChecksum(final String text, final boolean crc)
	{
		return crc
			? ByteArrayChecksumExtensions.getCheckSumCRC32(text.getBytes())
			: ByteArrayChecksumExtensions.getCheckSumAdler32(text.getBytes());
	}

}
