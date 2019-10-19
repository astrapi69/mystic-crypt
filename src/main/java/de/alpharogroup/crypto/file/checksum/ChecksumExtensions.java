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
package de.alpharogroup.crypto.file.checksum;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;
import java.util.zip.CRC32;
import java.util.zip.CheckedInputStream;
import java.util.zip.Checksum;

import org.apache.commons.lang3.ArrayUtils;

import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.file.read.ReadFileExtensions;
import lombok.experimental.UtilityClass;

/**
 * The class {@link ChecksumExtensions} is a utility class for computing checksum from files and
 * byte arrays.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
@UtilityClass
public final class ChecksumExtensions
{

	/** The constant HEXADECIMAL_CHARACTER_CLASS. */
	private static final String HEXADECIMAL_CHARACTER_CLASS = "[a-fA-F0-9]";

	/** The constant REGEX_VALIDATION_SHA1. */
	public static final String REGEX_VALIDATION_SHA1 = HEXADECIMAL_CHARACTER_CLASS + "{40}";

	/** The constant REGEX_VALIDATION_MD5. */
	public static final String REGEX_VALIDATION_MD5 = HEXADECIMAL_CHARACTER_CLASS + "{32}";

	/** The constant REGEX_VALIDATION_SHA512. */
	public static final String REGEX_VALIDATION_SHA512 = HEXADECIMAL_CHARACTER_CLASS + "{128}";

	/**
	 * Gets the checksum from the given byte arrays with the given algorithm
	 *
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @param byteArrays
	 *            the array of byte arrays
	 * @return The checksum from the given byte arrays as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link java.security.MessageDigest} object.
	 */
	public static String getChecksum(final Algorithm algorithm, final byte[]... byteArrays)
		throws NoSuchAlgorithmException
	{
		StringBuilder sb = new StringBuilder();
		for (byte[] byteArray : byteArrays)
		{
			sb.append(getChecksum(byteArray, algorithm.getAlgorithm()));
		}
		return sb.toString();
	}

	/**
	 * Gets the checksum from the given byte array with an instance of.
	 *
	 * @param bytes
	 *            the byte array.
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link java.security.MessageDigest} object.
	 */
	public static String getChecksum(final byte[] bytes, final Algorithm algorithm)
		throws NoSuchAlgorithmException
	{
		return getChecksum(bytes, algorithm.getAlgorithm());
	}

	/**
	 * Gets the checksum from the given byte array with an instance of.
	 *
	 * @param bytes
	 *            the byte array.
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link java.security.MessageDigest} object.
	 */
	public static String getChecksum(final byte[] bytes, final String algorithm)
		throws NoSuchAlgorithmException
	{
		final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
		messageDigest.reset();
		messageDigest.update(bytes);
		final byte digest[] = messageDigest.digest();
		final StringBuilder hexView = new StringBuilder();
		for (final byte element : digest)
		{
			final String intAsHex = Integer.toHexString(0xFF & element);
			if (intAsHex.length() == 1)
			{
				hexView.append('0');
			}
			hexView.append(intAsHex);
		}
		return hexView.toString();
	}

	/**
	 * Gets the checksum from the given byte array with an instance of.
	 *
	 * @param bytes
	 *            the Byte object array.
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link java.security.MessageDigest} object.
	 */
	public static String getChecksum(final Byte[] bytes, final Algorithm algorithm)
		throws NoSuchAlgorithmException
	{
		return getChecksum(bytes, algorithm.getAlgorithm());
	}

	/**
	 * Gets the checksum from the given byte array with an instance of.
	 *
	 * @param bytes
	 *            the Byte object array.
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link java.security.MessageDigest} object.
	 */
	public static String getChecksum(final Byte[] bytes, final String algorithm)
		throws NoSuchAlgorithmException
	{
		return getChecksum(ArrayUtils.toPrimitive(bytes), algorithm);
	}

	/**
	 * Gets the checksum from the given file with an instance of the given algorithm.
	 *
	 * @param file
	 *            the file.
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link java.security.MessageDigest} object.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String getChecksum(final File file, final Algorithm algorithm)
		throws NoSuchAlgorithmException, IOException
	{
		return getChecksum(file, algorithm.getAlgorithm());
	}

	/**
	 * Gets the checksum from the given file. If the flag crc is true than the CheckedInputStream is
	 * constructed with an instance of <code>java.util.zip.CRC32</code> otherwise with an instance
	 * of <code>java.util.zip.Adler32</code>.
	 *
	 * @param file
	 *            The file The file from what to get the checksum.
	 * @param crc
	 *            The crc If the flag crc is true than the CheckedInputStream is constructed with an
	 *            instance of {@link java.util.zip.CRC32} object otherwise it is constructed with an
	 *            instance of
	 * @return The checksum from the given file as long.
	 * @throws FileNotFoundException
	 *             Is thrown if the file is not found.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred. {@link java.util.zip.CRC32} object
	 *             otherwise it is constructed with an instance of {@link java.util.zip.Adler32}
	 *             object. {@link java.util.zip.Adler32} object.
	 */
	public static long getChecksum(final File file, final boolean crc)
		throws FileNotFoundException, IOException
	{
		try (CheckedInputStream cis = crc
			? new CheckedInputStream(new FileInputStream(file), new CRC32())
			: new CheckedInputStream(new FileInputStream(file), new Adler32());)
		{
			final int length = (int)file.length();
			final byte[] buffer = new byte[length];
			long checksum = 0;
			while (cis.read(buffer) >= 0)
			{
				checksum = cis.getChecksum().getValue();
			}
			checksum = cis.getChecksum().getValue();
			return checksum;
		}
	}

	/**
	 * Gets the checksum from the given file with an instance of the given algorithm.
	 *
	 * @param file
	 *            the file.
	 * @param algorithm
	 *            the algorithm to get the checksum. This could be for instance "MD4", "MD5",
	 *            "SHA-1", "SHA-256", "SHA-384" or "SHA-512".
	 * @return The checksum from the file as a String object.
	 * @throws NoSuchAlgorithmException
	 *             Is thrown if the algorithm is not supported or does not exists.
	 *             {@link java.security.MessageDigest} object.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String getChecksum(final File file, final String algorithm)
		throws NoSuchAlgorithmException, IOException
	{
		return getChecksum(ReadFileExtensions.toByteArray(file), algorithm);
	}

	/**
	 * Gets the checksum from the given byte array with an instance of.
	 *
	 * @param bytes
	 *            The byte array.
	 * @return The checksum from the byte array as long. {@link java.util.zip.Adler32} object.
	 */
	public static long getCheckSumAdler32(final byte[] bytes)
	{
		final Checksum checksum = new Adler32();
		checksum.update(bytes, 0, bytes.length);
		final long cs = checksum.getValue();
		return cs;
	}

	/**
	 * Gets the checksum from the given file with an instance of.
	 *
	 * @param file
	 *            The file.
	 * @return The checksum from the file as long. {@link java.util.zip.Adler32} object.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static long getCheckSumAdler32(final File file) throws IOException
	{
		return getCheckSumAdler32(ReadFileExtensions.toByteArray(file));
	}

	/**
	 * Gets the checksum from the given byte array with an instance of.
	 *
	 * @param bytes
	 *            The byte array.
	 * @return The checksum from the byte array as long. {@link java.util.zip.CRC32} object.
	 */
	public static long getCheckSumCRC32(final byte[] bytes)
	{
		final Checksum checksum = new CRC32();
		checksum.update(bytes, 0, bytes.length);
		final long cs = checksum.getValue();
		return cs;
	}

	/**
	 * Gets the checksum from the given file with an instance of.
	 *
	 * @param file
	 *            The file.
	 * @return The checksum from the file as long. {@link java.util.zip.CRC32} object.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static long getCheckSumCRC32(final File file) throws IOException
	{
		return getCheckSumCRC32(ReadFileExtensions.toByteArray(file));
	}

	/**
	 * Checks if the given value matches a MD5 value pattern.
	 *
	 * @param value
	 *            the value
	 * @return true, the given value matches a MD5 value otherwise false
	 */
	public static boolean matchesMD5(final String value)
	{
		return value.matches(REGEX_VALIDATION_MD5);
	}

	/**
	 * Checks if the given value matches a SHA1 value pattern.
	 *
	 * @param value
	 *            the value
	 * @return true, the given value matches a SHA1 value otherwise false
	 */
	public static boolean matchesSHA1(final String value)
	{
		return value.matches(REGEX_VALIDATION_SHA1);
	}

	/**
	 * Checks if the given value matches a SHA512 value pattern.
	 *
	 * @param value
	 *            the value
	 * @return true, the given value matches a SHA1 value otherwise false
	 */
	public static boolean matchesSHA512(final String value)
	{
		return value.matches(REGEX_VALIDATION_SHA512);
	}

}
