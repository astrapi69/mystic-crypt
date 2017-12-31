package de.alpharogroup.crypto.obfuscation;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import de.alpharogroup.collections.pairs.KeyValuePair;
import lombok.experimental.UtilityClass;

/**
 * The class {@link ObfuscatorExtensions} provides algorithms for obfuscate strings.
 */
@UtilityClass
public class ObfuscatorExtensions
{

	/**
	 * Obfuscate.
	 *
	 * @param rules the rules
	 * @param toObfuscate the to obfuscate
	 * @return the string
	 */
	public static String obfuscate(final List<KeyValuePair<String, String>> rules, String toObfuscate)
	{
		StringBuilder sb = new StringBuilder();
		Map<String, String> map = toMap(rules);
		for (int i = 0; i < toObfuscate.length(); i++){
		    char currentCharacter = toObfuscate.charAt(i);
		    String charAsString = Character.toString(currentCharacter);
		    if(map.containsKey(charAsString)) {
		    	sb.append(map.get(charAsString));
		    } else {
		    	sb.append(charAsString);
		    }
		}
		return sb.toString();
	}

	/**
	 * Transforms the given {@link List} of {@link KeyValuePair}'s to a {@link Map}.
	 *
	 * @param <K>
	 *            The generic type of the key
	 * @param <V>
	 *            The generic type of the value
	 * @param list
	 *            the list
	 * @return the new map.
	 */
	public static <K, V> Map<K, V> toMap(final Collection<KeyValuePair<K, V>> list)
	{
		final Map<K, V> map = new HashMap<>();
		for (KeyValuePair<K, V> keyValuePair : list)
		{
			map.put(keyValuePair.getKey(), keyValuePair.getValue());
		}
		return map;
	}


	public static String disentangle(final List<KeyValuePair<String, String>> rules, final String obfuscated)
	{
		String clonedObfuscated = obfuscated;
		Map<String, String> map = toMap(rules);
		for (final Map.Entry<String, String> rule : map.entrySet())
		{
			clonedObfuscated = StringUtils.replace(clonedObfuscated, rule.getValue(), rule.getKey());
		}
		return clonedObfuscated;
	}

}
