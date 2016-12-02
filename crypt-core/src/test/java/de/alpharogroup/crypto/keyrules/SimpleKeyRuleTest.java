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
package de.alpharogroup.crypto.keyrules;

import java.util.HashMap;
import java.util.Map;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;


public class SimpleKeyRuleTest
{

	@Test
	public void test()
	{
		// a key for encryption
		String toObfuscatedString = "XnQ6eyTmK_ca-rLE_6U4";
		// create a rule for obfuscate the key
		final Map<String, String> keymap = new HashMap<>();
		keymap.put("6", "666");
		keymap.put("T", "t");
		keymap.put("L", "777");
		// create the rule
		final SimpleKeyRule replaceKeyRule = new SimpleKeyRule(keymap);
		// obfuscate the key
		Obfuscatable obfuscator = new Obfuscator(replaceKeyRule, toObfuscatedString);
		String actual = obfuscator.obfuscate();
		String expected = "XnQ666eytmK_ca-r777E_666U4";
		AssertJUnit.assertEquals(expected, actual);
		// disentangledKey the key
		final String disentangledKey = obfuscator.disentangle();
		AssertJUnit.assertEquals(toObfuscatedString, disentangledKey);

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

		 final SimpleKeyRule charreplaceRule = new SimpleKeyRule(charmap);
		 toObfuscatedString = "854917632";
		 obfuscator = new Obfuscator(charreplaceRule, toObfuscatedString);
		 actual = obfuscator.obfuscate();
		 expected = "EFiFoNOSeSiThTw";
		 AssertJUnit.assertEquals(expected, actual);

		 actual = obfuscator.disentangle();
		 expected = toObfuscatedString;
		 AssertJUnit.assertEquals(expected, actual);

	}

}
