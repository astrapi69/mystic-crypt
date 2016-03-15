/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
