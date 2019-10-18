package de.alpharogroup.crypto.decorator;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import de.alpharogroup.crypto.model.CharacterDecorator;
import de.alpharogroup.crypto.model.CryptObjectDecorator;
import de.alpharogroup.file.read.ReadFileExtensions;
import lombok.NonNull;

public class CryptObjectDecoratorExtensions
{
	public static String decorateWithCharacterDecorator(final @NonNull String toEncrypt,
		final @NonNull CharacterDecorator decorator)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(decorator.getPrefix());
		sb.append(toEncrypt);
		sb.append(decorator.getSuffix());
		return sb.toString();
	}

	public static String undecorateWithCharacterDecorator(final @NonNull String toEncrypt,
		final @NonNull CharacterDecorator decorator)
	{
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

	public static String decorateWithStringDecorator(final @NonNull String toEncrypt,
		final @NonNull CryptObjectDecorator<String> decorator)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(decorator.getPrefix());
		sb.append(toEncrypt);
		sb.append(decorator.getSuffix());
		return sb.toString();
	}

	public static String undecorateWithStringDecorator(final @NonNull String decrypted,
		final @NonNull CryptObjectDecorator<String> decorator)
	{
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

	public static String decorateFile(final @NonNull File toEncrypt,
		final @NonNull CryptObjectDecorator<String> decorator) throws IOException
	{
		return decorateWithStringDecorator(ReadFileExtensions.readFromFile(toEncrypt), decorator);
	}

	public static String undecorateFile(final @NonNull File decrypted,
		final @NonNull CryptObjectDecorator<String> decorator) throws IOException
	{
		return undecorateWithStringDecorator(ReadFileExtensions.readFromFile(decrypted), decorator);
	}


	public static String decorateWithBytearrayDecorator(final @NonNull String toEncrypt,
		final @NonNull CryptObjectDecorator<byte[]> decorator, final @NonNull Charset charset)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(new String(decorator.getPrefix(), charset));

		sb.append(toEncrypt);

		sb.append(new String(decorator.getSuffix(), charset));
		return sb.toString();
	}

	private static boolean startsWith(final byte[] array, byte[] prefix) {
		for (int i = 0; i < prefix.length; i++)
		{
			if(prefix[i]!=array[i]) {
				return false;
			}
		}
		return true;
	}

	private static byte[] removeFromStart(final @NonNull byte[] array, final @NonNull byte[] prefix) {
		byte[] result = new byte[array.length-prefix.length];
		System.arraycopy(array, prefix.length, result, 0, result.length);
		return result;
	}

	private static byte[] removeFromEnd(final @NonNull byte[] array, final @NonNull byte[] suffix) {
		return Arrays.copyOf(array, array.length-suffix.length);
	}


	private static boolean endsWith(final @NonNull byte[] array,final @NonNull byte[] suffix) {
		int lastIndex = suffix.length-1;
		int currentIndex = lastIndex;
		if(ArrayUtils.isEmpty(suffix)) {
			return false;
		}
		for (int i = array.length-1; 0 <= i; i--)
		{
			if(suffix[currentIndex--]!=array[i]) {
				return false;
			}
			if(currentIndex==-1) {
				break;
			}
		}
		return true;
	}

	public static String undecorateWithBytearrayDecorator(final @NonNull String toEncrypt,
		final @NonNull CryptObjectDecorator<byte[]> decorator)
	{
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
}