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

import java.util.Map;

import de.alpharogroup.check.Check;

import org.apache.commons.lang.StringUtils;

public class Obfuscator
{
	private SimpleKeyRule rule;
	private final String key;

	public Obfuscator(SimpleKeyRule rule, String key)
	{
		Check.get().notNull(rule, "rule");
		Check.get().notEmpty(key, "key");
		this.rule = rule;
		this.key = key;
	}

	public String obfuscate()
	{
		Map<String, String> rules = rule.getRules();
		String clonedKey = key;
		for (Map.Entry<String, String> rule : rules.entrySet())
		{
			clonedKey = StringUtils.replace(clonedKey, rule.getKey(), rule.getValue());
		}
		return clonedKey;

	}

	public String disentangle()
	{
		String clonedKey = obfuscate();
		Map<String, String> rules = rule.getRules();
		for (Map.Entry<String, String> rule : rules.entrySet())
		{
			clonedKey = StringUtils.replace(clonedKey, rule.getValue(), rule.getKey());
		}
		return clonedKey;
	}

}
