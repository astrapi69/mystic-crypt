package de.alpharogroup.crypto.obfuscation;

import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.BiMap;

import lombok.experimental.UtilityClass;

/**
 * The class {@link ObfuscatorExtensions} provides algorithms for obfuscate strings.
 */
@UtilityClass
public class ObfuscatorExtensions
{

	/**
	 * Obfuscate the given {@link BiMap}.
	 *
	 * @param rules the rules
	 * @param toObfuscate the to obfuscate
	 * @return the string
	 */
	public static String obfuscate(final BiMap<String, String> rules, String toObfuscate)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++){
		    char currentCharacter = toObfuscate.charAt(i);
		    String charAsString = Character.toString(currentCharacter);
		    if(rules.containsKey(charAsString)) {
		    	sb.append(rules.get(charAsString));
		    } else {
		    	sb.append(charAsString);
		    }
		}
		return sb.toString();
	}

	/**
	 * Disentangle the given {@link BiMap}.
	 *
	 * @param rules the rules
	 * @param obfuscated the obfuscated
	 * @return the string
	 */
	public static String disentangle(final BiMap<String, String> rules, final String obfuscated)
	{
		String clonedObfuscated = obfuscated;
		for (final Map.Entry<String, String> rule : rules.entrySet())
		{
			clonedObfuscated = StringUtils.replace(clonedObfuscated, rule.getValue(), rule.getKey());
		}
		return clonedObfuscated;
	}

}
