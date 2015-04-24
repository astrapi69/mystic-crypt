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
		String key = "XnQ6eyTmK_ca-rLE_6U4";
		// create a rule for obfuscate the key
		Map<String, String> keymap = new HashMap<>();
		keymap.put("6", "666");
		keymap.put("T", "t");
		keymap.put("L", "777");
		// create the rule
		SimpleKeyRule replaceKeyRule = new SimpleKeyRule(keymap);
		// obfuscate the key
		Obfuscator obfuscator = new Obfuscator(replaceKeyRule, key);
		String obfuscatedKey = obfuscator.obfuscate();
		AssertJUnit.assertEquals("XnQ666eytmK_ca-r777E_666U4", obfuscatedKey);
		// disentangledKey the key
		String disentangledKey = obfuscator.disentangle();
		AssertJUnit.assertEquals(key, disentangledKey);

	}

}
