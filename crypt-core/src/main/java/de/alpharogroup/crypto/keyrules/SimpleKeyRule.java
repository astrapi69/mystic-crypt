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

import net.sourceforge.jaulp.check.Check;
import lombok.Getter;
import de.alpharogroup.crypto.interfaces.KeyRule;

public class SimpleKeyRule implements KeyRule
{
	@Getter
	private Map<String, String> rules;

	public SimpleKeyRule(Map<String, String> rules)
	{
		Check.get().notEmpty(rules, "rules");
		this.rules = rules;
	}

}
