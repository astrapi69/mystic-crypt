/**
 * Copyright (C) 2015 Asterios Raptis
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

import lombok.Getter;
import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.interfaces.KeyRule;

/**
 * The Class {@link SimpleKeyRule} can define a simple rule for encrypt and decrypt a key.
 */
public class SimpleKeyRule implements KeyRule
{

	/**
	 * The rules for encrypt the key.
	 */
	@Getter
	private final Map<String, String> rules;

	/**
	 * Instantiates a new {@link SimpleKeyRule}.
	 *
	 * @param rules
	 *            the rules for encrypt the key.
	 */
	public SimpleKeyRule(final Map<String, String> rules)
	{
		Check.get().notEmpty(rules, "rules");
		this.rules = rules;
	}

}
