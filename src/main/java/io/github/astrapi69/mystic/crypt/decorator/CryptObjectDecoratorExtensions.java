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
package io.github.astrapi69.mystic.crypt.decorator;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Objects;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;
import io.github.astrapi69.file.read.ReadFileExtensions;

/**
 * Utility class for decorating and undecorating cryptographic objects.
 */
public final class CryptObjectDecoratorExtensions
{
	private CryptObjectDecoratorExtensions()
	{
	}

	/**
	 * Decorates the content of the given file using the specified decorator.
	 *
	 * @param toEncrypt
	 *            the file to be encrypted
	 * @param decorator
	 *            the decorator to be used
	 * @return the decorated string
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static String decorateFile(final File toEncrypt,
		final CryptObjectDecorator<String> decorator) throws IOException
	{
		Objects.requireNonNull(toEncrypt);
		Objects.requireNonNull(decorator);
		return decorateWithStringDecorator(ReadFileExtensions.fromFile(toEncrypt), decorator);
	}

	/**
	 * Decorates the given string using a byte array decorator.
	 *
	 * @param toEncrypt
	 *            the string to be encrypted
	 * @param decorator
	 *            the decorator to be used
	 * @param charset
	 *            the charset to be used for encoding
	 * @return the decorated string
	 */
	public static String decorateWithBytearrayDecorator(final String toEncrypt,
		final CryptObjectDecorator<byte[]> decorator, final Charset charset)
	{
		Objects.requireNonNull(toEncrypt);
		Objects.requireNonNull(decorator);
		Objects.requireNonNull(charset);
		StringBuilder sb = new StringBuilder();
		sb.append(new String(decorator.getPrefix(), charset));
		sb.append(toEncrypt);
		sb.append(new String(decorator.getSuffix(), charset));
		return sb.toString();
	}

	/**
	 * Decorates the given string using a character decorator.
	 *
	 * @param toEncrypt
	 *            the string to be encrypted
	 * @param decorator
	 *            the decorator to be used
	 * @return the decorated string
	 */
	public static String decorateWithCharacterDecorator(final String toEncrypt,
		final CryptObjectDecorator<Character> decorator)
	{
		Objects.requireNonNull(toEncrypt);
		Objects.requireNonNull(decorator);
		StringBuilder sb = new StringBuilder();
		sb.append(decorator.getPrefix());
		sb.append(toEncrypt);
		sb.append(decorator.getSuffix());
		return sb.toString();
	}

	/**
	 * Decorates the given string using a string decorator.
	 *
	 * @param toEncrypt
	 *            the string to be encrypted
	 * @param decorator
	 *            the decorator to be used
	 * @return the decorated string
	 */
	public static String decorateWithStringDecorator(final String toEncrypt,
		final CryptObjectDecorator<String> decorator)
	{
		Objects.requireNonNull(toEncrypt);
		Objects.requireNonNull(decorator);
		StringBuilder sb = new StringBuilder();
		sb.append(decorator.getPrefix());
		sb.append(toEncrypt);
		sb.append(decorator.getSuffix());
		return sb.toString();
	}

	private static boolean endsWith(final byte[] array, final byte[] suffix)
	{
		Objects.requireNonNull(array);
		Objects.requireNonNull(suffix);
		int lastIndex = suffix.length - 1;
		int currentIndex = lastIndex;
		if (ArrayUtils.isEmpty(suffix))
		{
			return false;
		}
		for (int i = array.length - 1; 0 <= i; i--)
		{
			if (suffix[currentIndex--] != array[i])
			{
				return false;
			}
			if (currentIndex == -1)
			{
				break;
			}
		}
		return true;
	}

	private static byte[] removeFromEnd(final byte[] array, final byte[] suffix)
	{
		Objects.requireNonNull(array);
		Objects.requireNonNull(suffix);
		return Arrays.copyOf(array, array.length - suffix.length);
	}

	private static byte[] removeFromStart(final byte[] array, final byte[] prefix)
	{
		Objects.requireNonNull(array);
		Objects.requireNonNull(prefix);
		byte[] result = new byte[array.length - prefix.length];
		System.arraycopy(array, prefix.length, result, 0, result.length);
		return result;
	}

	private static boolean startsWith(final byte[] array, byte[] prefix)
	{
		for (int i = 0; i < prefix.length; i++)
		{
			if (prefix[i] != array[i])
			{
				return false;
			}
		}
		return true;
	}

	/**
	 * Undecorates the content of the given file using the specified decorator.
	 *
	 * @param decrypted
	 *            the file to be decrypted
	 * @param decorator
	 *            the decorator to be used
	 * @return the undecorated string
	 * @throws IOException
	 *             if an I/O error occurs
	 */
	public static String undecorateFile(final File decrypted,
		final CryptObjectDecorator<String> decorator) throws IOException
	{
		Objects.requireNonNull(decrypted);
		Objects.requireNonNull(decorator);
		return undecorateWithStringDecorator(ReadFileExtensions.fromFile(decrypted), decorator);
	}

	/**
	 * Undecorates the given string using a byte array decorator.
	 *
	 * @param toEncrypt
	 *            the string to be decrypted
	 * @param decorator
	 *            the decorator to be used
	 * @return the undecorated string
	 */
	public static String undecorateWithBytearrayDecorator(final String toEncrypt,
		final CryptObjectDecorator<byte[]> decorator)
	{
		Objects.requireNonNull(toEncrypt);
		Objects.requireNonNull(decorator);
		byte[] result = toEncrypt.getBytes();
		byte[] prefix = decorator.getPrefix();
		byte[] suffix = decorator.getSuffix();

		result = ArrayUtils.removeElements(result, prefix);
		if (startsWith(result, prefix))
		{
			result = removeFromStart(result, prefix);
		}

		if (endsWith(result, suffix))
		{
			result = removeFromEnd(result, suffix);
		}
		return new String(result);
	}

	/**
	 * Undecorates the given string using a character decorator.
	 *
	 * @param toEncrypt
	 *            the string to be decrypted
	 * @param decorator
	 *            the decorator to be used
	 * @return the undecorated string
	 */
	public static String undecorateWithCharacterDecorator(final String toEncrypt,
		final CryptObjectDecorator<Character> decorator)
	{
		Objects.requireNonNull(toEncrypt);
		Objects.requireNonNull(decorator);
		StringBuilder sb = new StringBuilder(toEncrypt);
		boolean prefixRemoved = false;
		if (toEncrypt.startsWith(decorator.getPrefix().toString()))
		{
			sb.deleteCharAt(0);
			prefixRemoved = true;
		}
		if (toEncrypt.endsWith(decorator.getSuffix().toString()))
		{
			if (prefixRemoved)
			{
				sb.deleteCharAt(toEncrypt.length() - 2);
			}
			else
			{
				sb.deleteCharAt(toEncrypt.length() - 1);
			}
		}
		return sb.toString();
	}

	/**
	 * Undecorates the given string using a string decorator.
	 *
	 * @param decrypted
	 *            the string to be decrypted
	 * @param decorator
	 *            the decorator to be used
	 * @return the undecorated string
	 */
	public static String undecorateWithStringDecorator(final String decrypted,
		final CryptObjectDecorator<String> decorator)
	{
		Objects.requireNonNull(decrypted);
		Objects.requireNonNull(decorator);
		String result = decrypted;
		if (decrypted.startsWith(decorator.getPrefix()))
		{
			result = StringUtils.removeStart(result, decorator.getPrefix());
		}
		if (decrypted.endsWith(decorator.getSuffix()))
		{
			result = StringUtils.removeEnd(result, decorator.getSuffix());
		}
		return result;
	}
}
