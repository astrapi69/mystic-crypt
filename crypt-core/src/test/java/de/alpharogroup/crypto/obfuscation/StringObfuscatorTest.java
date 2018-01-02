package de.alpharogroup.crypto.obfuscation;

import static org.testng.AssertJUnit.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rules.SimpleObfuscationRules;

public class StringObfuscatorTest
{

	/**
	 * Test method for {@link Obfuscator#disentangle()}.
	 */
	@Test
	public void testDisentangle()
	{
		String actual;
		String expected;

		final Map<String, String> charmap = new HashMap<>();

		charmap.put("1", "O");
		charmap.put("2", "Tw");
		charmap.put("3", "Th");
		charmap.put("4", "Fo");
		charmap.put("5", "Fi");
		charmap.put("6", "Si");
		charmap.put("7", "Se");
		charmap.put("8", "E");
		charmap.put("9", "N");
		BiMap<String, String> obfuscationRules = HashBiMap.create(charmap);

		final SimpleObfuscationRules charreplaceRule = new SimpleObfuscationRules(obfuscationRules);
		String toObfuscatedString = "854917632";
		Obfuscatable obfuscator = new StringObfuscator(charreplaceRule, toObfuscatedString);
		actual = obfuscator.obfuscate();
		expected = "EFiFoNOSeSiThTw";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = toObfuscatedString;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link Obfuscator#obfuscate()}.
	 */
	@Test
	public void testObfuscate()
	{
		String actual;
		String expected;
		// a key for obfuscation
		String toObfuscatedString = "XnQ6eyTmK_ca-rLE_6U4";
		// create a rule for obfuscate the key
		final Map<String, String> keymap = new HashMap<>();
		keymap.put("6", "666");
		keymap.put("T", "t");
		keymap.put("L", "777");
		BiMap<String, String> obfuscationRules = HashBiMap.create(keymap);

		// create the rule
		final SimpleObfuscationRules replaceKeyRule = new SimpleObfuscationRules(obfuscationRules);
		// obfuscate the key
		Obfuscatable obfuscator = new StringObfuscator(replaceKeyRule, toObfuscatedString);
		actual = obfuscator.obfuscate();
		expected = "XnQ666eytmK_ca-r777E_666U4";
		assertEquals(expected, actual);
	}

}
