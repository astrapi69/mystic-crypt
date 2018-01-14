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
package de.alpharogroup.crypto.obfuscation.experimental;

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
	 * @param rules
	 *            the rules
	 * @param toObfuscate
	 *            the to obfuscate
	 * @return the string
	 */
	public static String obfuscate(final BiMap<String, String> rules, String toObfuscate)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			char currentCharacter = toObfuscate.charAt(i);
			String charAsString = Character.toString(currentCharacter);
			if (rules.containsKey(charAsString))
			{
				sb.append(rules.get(charAsString));
			}
			else
			{
				sb.append(charAsString);
			}
		}
		return sb.toString();
	}

	/**
	 * Disentangle the given {@link BiMap}.
	 *
	 * @param rules
	 *            the rules
	 * @param obfuscated
	 *            the obfuscated
	 * @return the string
	 */
	public static String disentangle(final BiMap<String, String> rules, final String obfuscated)
	{
		String clonedObfuscated = obfuscated;
		for (final Map.Entry<String, String> rule : rules.entrySet())
		{
			clonedObfuscated = StringUtils.replace(clonedObfuscated, rule.getValue(),
				rule.getKey());
		}
		return clonedObfuscated;
	}

}
