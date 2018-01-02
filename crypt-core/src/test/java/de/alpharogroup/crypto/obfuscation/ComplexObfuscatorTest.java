package de.alpharogroup.crypto.obfuscation;

import static org.testng.AssertJUnit.assertEquals;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.collections.list.ListExtensions;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ComplexObfuscationRule;
import de.alpharogroup.crypto.obfuscation.rules.ComplexObfuscationRules;
import de.alpharogroup.crypto.obfuscation.rules.ObfuscationRules;

/**
 * The unit test class for the class {@link ComplexObfuscator}.
 */
public class ComplexObfuscatorTest
{


	/**
	 * Test method for {@link ComplexObfuscator#disentangle()}.
	 */
	@Test
	public void testDisentangle()
	{
//		String actual;
//		String expected;

//		final Map<String, String> charmap = new HashMap<>();
//
//		charmap.put("1", "O");
//		charmap.put("2", "Tw");
//		charmap.put("3", "Th");
//		charmap.put("4", "Fo");
//		charmap.put("5", "Fi");
//		charmap.put("6", "Si");
//		charmap.put("7", "Se");
//		charmap.put("8", "E");
//		charmap.put("9", "N");
//
//		final KeyMapObfuscationRules charreplaceRule = new KeyMapObfuscationRules(charmap);
//		String toObfuscatedString = "854917632";
//		Obfuscatable obfuscator = new Obfuscator(charreplaceRule, toObfuscatedString);
//		actual = obfuscator.obfuscate();
//		expected = "EFiFoNOSeSiThTw";
//		assertEquals(expected, actual);
//
//		actual = obfuscator.disentangle();
//		expected = toObfuscatedString;
//		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link ComplexObfuscator#obfuscate()}.
	 */
	@Test
	public void testObfuscate()
	{
		String actual;
		String expected;
		// a key for obfuscation
		String toObfuscatedString = "abc";
		// create a rule for obfuscate the key

		BiMap<Character, ComplexObfuscationRule> obfuscationRules = HashBiMap.create();
		obfuscationRules.put('a', ComplexObfuscationRule.builder()
			.character('a')
			.replaceWith(ObfuscationRules.builder()
				.rules(ListExtensions.newArrayList("b"))
				.build())
			.build());
		obfuscationRules.put('b', ComplexObfuscationRule.builder()
			.character('b')
			.replaceWith(ObfuscationRules.builder()
				.rules(ListExtensions.newArrayList("c"))
				.build())
			.build());
		obfuscationRules.put('c', ComplexObfuscationRule.builder()
			.character('c')
			.replaceWith(ObfuscationRules.builder()
				.rules(ListExtensions.newArrayList("d"))
				.build())
			.build());
		ComplexObfuscationRules replaceKeyRules = new ComplexObfuscationRules(obfuscationRules);
		// obfuscate the key
		Obfuscatable obfuscator = new ComplexObfuscator(replaceKeyRules, toObfuscatedString);
		actual = obfuscator.obfuscate();

		expected = "bcd";
		assertEquals(expected, actual);
	}

}
