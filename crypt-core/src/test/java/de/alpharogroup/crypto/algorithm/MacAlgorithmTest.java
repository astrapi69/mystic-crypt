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
package de.alpharogroup.crypto.algorithm;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

public class MacAlgorithmTest
{

	@Test
	public void test()
	{
		String expected = "HmacMD5";
		String actual = MacAlgorithm.HmacMD5.name();
		AssertJUnit.assertEquals(expected, actual);

		expected = "PBEWithHmacMD5";
		actual = MacAlgorithm.PBEWithHmacMD5.name();
		AssertJUnit.assertEquals(expected, actual);

	}

}
