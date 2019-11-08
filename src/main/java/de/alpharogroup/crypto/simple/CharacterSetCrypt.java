package de.alpharogroup.crypto.simple;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.TreeSet;
import java.util.stream.Collectors;

import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link CharacterSetCrypt} provides algorithms for encrypt a text with a character set.
 * The text is encrypted with the character set over the index. The decryption builds the text over
 * the indexes and the character set. So the character set is the key element in this encryption
 * method.
 */
@UtilityClass
public class CharacterSetCrypt
{

	/**
	 * To text.
	 *
	 * @param integerList
	 *            the integer list
	 * @param characters
	 *            the characters
	 * @return the string
	 */
	public static String toText(final @NonNull List<Integer> integerList,
		final @NonNull List<Character> characters)
	{
		StringBuilder sb = new StringBuilder();
		for (int index : integerList)
		{
			sb.append(characters.get(index));
		}
		return sb.toString();
	}

	/**
	 * To index list.
	 *
	 * @param text
	 *            the text
	 * @param characters
	 *            the characters
	 * @return the list
	 */
	public static List<Integer> toIndexList(final @NonNull String text,
		final @NonNull List<Character> characters)
	{
		char[] chars = text.toCharArray();
		List<Integer> integerList = new ArrayList<>();
		for (char c : chars)
		{
			integerList.add(characters.indexOf(Character.valueOf(c)));
		}
		return integerList;
	}

	/**
	 * Factory method for create new {@link ArrayList} of unique characters from the given text
	 * sorted with the given {@link Comparator} <br>
	 * <br>
	 * Note: This method can be used for a custom Comparator that have a defined order. For example:
	 * <code>
	 * // defined custom order
	 * List<Character> definedOrder = Arrays.asList('c', 'b', 'a', 'd', '.', ...);
	 * Comparator<Character> customComparator = Comparator.comparing(character -> definedOrder.indexOf(character));
	 * </code>
	 *
	 * @param text
	 *            the text
	 * @param comparator
	 *            the comparator
	 * @return the new {@link List} with the unique characters
	 */
	public static List<Character> newCharacterList(final @NonNull String text,
		final @NonNull Comparator<Character> comparator)
	{
		return new ArrayList<>(text.chars().mapToObj(i -> (char)i)
			.collect(Collectors.toCollection(() -> new TreeSet<>(comparator))));
	}

	/**
	 * Factory method for create new {@link ArrayList} of unique characters from the given text
	 *
	 * @param text
	 *            the text
	 * @return the new {@link List} with the unique characters
	 */
	public static List<Character> newCharacterList(final @NonNull String text)
	{
		return newCharacterList(text, Comparator.<Character> naturalOrder());
	}

}
